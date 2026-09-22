"""SMTP sending.

Unlike IMAP, SMTP connections are not kept open: a submission is a short
exchange and providers drop idle sessions anyway, so each send opens, sends and
closes. The blocking work runs in a worker thread.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from typing import Any

from mail_mcp import netguard
from mail_mcp.accounts import AUTH_XOAUTH2, SECURITY_NONE, SECURITY_SSL, MailAccount
from mail_mcp.imap_client import ssl_context
from mail_mcp.xoauth2 import TokenError, access_token_for, sasl_xoauth2_b64

logger = logging.getLogger("mail-mcp.smtp")


class SmtpError(RuntimeError):
    """Raised for any SMTP failure, with a message fit for an agent."""

    def __init__(self, message: str, *, detail: str = ""):
        self.message = message
        self.detail = detail
        super().__init__(f"{message} {detail}".strip())


def _connect(account: MailAccount, context: ssl.SSLContext) -> smtplib.SMTP:
    try:
        netguard.check_host(account.smtp_host)
    except netguard.TargetError as e:
        raise SmtpError(str(e)) from e
    if account.smtp_security == SECURITY_SSL:
        return smtplib.SMTP_SSL(
            account.smtp_host,
            account.smtp_port,
            timeout=account.timeout,
            context=context,
        )
    server = smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=account.timeout)
    server.ehlo()
    if account.smtp_security != SECURITY_NONE:
        server.starttls(context=context)
        server.ehlo()
    return server


def _authenticate(
    server: smtplib.SMTP, account: MailAccount, access_token: str | None
) -> None:
    if account.auth == AUTH_XOAUTH2:
        argument = sasl_xoauth2_b64(account.smtp_username, access_token or "")
        code, response = server.docmd("AUTH", "XOAUTH2 " + argument)
        if code not in (235, 503):
            raise smtplib.SMTPAuthenticationError(code, response)
    else:
        server.login(account.smtp_username, account.secret)


async def send(
    account: MailAccount, message: bytes, recipients: list[str], sender: str | None = None
) -> dict[str, Any]:
    """Send one message; returns a small report about what was accepted."""
    if account.read_only:
        raise SmtpError("This mailbox is connected read-only, so sending is not allowed.")
    if not recipients:
        raise SmtpError("No recipient to send to.")

    access_token = None
    if account.auth == AUTH_XOAUTH2:
        try:
            access_token = await access_token_for(
                provider=account.oauth_provider,
                refresh_token=account.secret,
                client_id=account.oauth_client_id,
                client_secret=account.oauth_client_secret,
                tenant=account.oauth_tenant,
            )
        except TokenError as e:
            raise SmtpError("OAuth token refresh failed.", detail=str(e)) from e

    envelope_from = sender or account.address
    context = ssl_context(account.verify_ssl)

    def _send() -> dict[str, Any]:
        try:
            server = _connect(account, context)
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            raise SmtpError(
                f"Cannot reach the SMTP server {account.smtp_host}:{account.smtp_port}.",
                detail=str(e),
            ) from e
        try:
            _authenticate(server, account, access_token)
        except smtplib.SMTPAuthenticationError as e:
            server.close()
            raise SmtpError(
                f"SMTP login rejected for {account.address}.",
                detail=f"{e.smtp_code} {_text(e.smtp_error)} Many providers "
                "require an app password for SMTP.",
            ) from e
        except smtplib.SMTPException as e:
            server.close()
            raise SmtpError("SMTP authentication failed.", detail=str(e)) from e
        try:
            refused = server.sendmail(envelope_from, recipients, message)
        except smtplib.SMTPRecipientsRefused as e:
            raise SmtpError(
                "Every recipient was refused by the server.",
                detail="; ".join(
                    f"{addr}: {_text(err[1])}" for addr, err in e.recipients.items()
                ),
            ) from e
        except smtplib.SMTPException as e:
            raise SmtpError("The server refused the message.", detail=str(e)) from e
        finally:
            try:
                server.quit()
            except smtplib.SMTPException:
                server.close()
        return {
            "accepted": [r for r in recipients if r not in refused],
            "refused": {addr: _text(err[1]) for addr, err in refused.items()},
        }

    result = await asyncio.to_thread(_send)
    logger.info(
        "Sent message from %s to %d recipient(s)", account.address, len(result["accepted"])
    )
    return result


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


async def check(account: MailAccount) -> dict[str, Any]:
    """Open an SMTP session and authenticate, without sending anything."""
    access_token = None
    if account.auth == AUTH_XOAUTH2:
        try:
            access_token = await access_token_for(
                provider=account.oauth_provider,
                refresh_token=account.secret,
                client_id=account.oauth_client_id,
                client_secret=account.oauth_client_secret,
                tenant=account.oauth_tenant,
            )
        except TokenError as e:
            raise SmtpError("OAuth token refresh failed.", detail=str(e)) from e
    context = ssl_context(account.verify_ssl)

    def _probe() -> dict[str, Any]:
        try:
            server = _connect(account, context)
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            raise SmtpError(
                f"Cannot reach the SMTP server {account.smtp_host}:{account.smtp_port}.",
                detail=str(e),
            ) from e
        try:
            _authenticate(server, account, access_token)
        except smtplib.SMTPAuthenticationError as e:
            raise SmtpError(
                f"SMTP login rejected for {account.address}.",
                detail=f"{e.smtp_code} {_text(e.smtp_error)}",
            ) from e
        except smtplib.SMTPException as e:
            raise SmtpError("SMTP authentication failed.", detail=str(e)) from e
        finally:
            try:
                server.quit()
            except smtplib.SMTPException:
                server.close()
        return {"ok": True, "host": f"{account.smtp_host}:{account.smtp_port}"}

    return await asyncio.to_thread(_probe)
