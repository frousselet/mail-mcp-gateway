"""Mail MCP Gateway: exposes any IMAP/SMTP mailbox as MCP tools.

Two deployment modes share the same tool set:

- **single mailbox set** (default): credentials come from environment variables
  (or ``MAIL_ACCOUNTS_FILE``), which suits ``stdio`` use from a local agent;
- **multi-user** (``MAIL_MULTITENANT=1``, what ``mail-mcp-web`` runs): each
  caller authenticates with OAuth and the mailboxes are resolved per request
  from the access token, so one process serves many people and many addresses.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from mail_mcp import formatting, mutf7, smtp_client
from mail_mcp.accounts import AccountConfigError, AccountSet, MailAccount
from mail_mcp.composer import ComposeError, build_forward, build_message, build_reply
from mail_mcp.imap_client import ImapClient, ImapError
from mail_mcp.message import parse_headers, parse_message, truncate
from mail_mcp.search import SearchError, build_criteria, describe
from mail_mcp.smtp_client import SmtpError

logging.basicConfig(
    level=os.environ.get("MAIL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mail-mcp")

_MULTITENANT = os.environ.get("MAIL_MULTITENANT", "").lower() in ("1", "true", "yes")

# Multi-user singletons, created in _build_mcp so single-mailbox imports stay light.
STORE = None  # type: ignore[assignment]
REGISTRY = None  # type: ignore[assignment]
OAUTH_PROVIDER = None  # type: ignore[assignment]

INSTRUCTIONS = (
    "Read and send email over IMAP/SMTP for the mailbox(es) attached to this "
    "connection.\n\n"
    "Start with `list_accounts` to see which addresses are available: every "
    "tool takes an optional `account` (an address, a label or an id) and falls "
    "back to the connection's default mailbox when it is omitted.\n\n"
    "Reading: `list_folders`, `list_messages`, `search_messages`, `get_message`, "
    "`get_thread`, `get_attachment`, `folder_status`.\n"
    "Writing: `send_message`, `reply_message`, `forward_message`, `save_draft`, "
    "`mark_messages`, `move_messages`, `delete_messages`, `create_folder`.\n\n"
    "Messages are identified by their IMAP UID **within a folder**, so pass the "
    "same `folder` you listed them from. UIDs are stable, but they are not "
    "shared between folders: after a move, list again to get the new UID.\n\n"
    "Sending is real and irreversible: confirm recipients and content with the "
    "user before calling `send_message`, `reply_message` or `forward_message`."
)


# ---------------------------------------------------------------------------
# Single-mailbox configuration (environment)
# ---------------------------------------------------------------------------


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _account_from_env() -> MailAccount | None:
    address = os.environ.get("MAIL_ADDRESS", "").strip()
    if not address:
        return None
    imap_host = os.environ.get("MAIL_IMAP_HOST", "").strip()
    smtp_host = os.environ.get("MAIL_SMTP_HOST", "").strip()
    account = MailAccount(
        address=address,
        account_id="box_env",
        label=os.environ.get("MAIL_LABEL", "").strip(),
        from_name=os.environ.get("MAIL_FROM_NAME", "").strip(),
        imap_host=imap_host,
        imap_port=int(os.environ.get("MAIL_IMAP_PORT", "993")),
        imap_security=os.environ.get("MAIL_IMAP_SECURITY", "ssl").strip().lower(),
        imap_username=os.environ.get("MAIL_IMAP_USERNAME", "").strip(),
        smtp_host=smtp_host,
        smtp_port=int(os.environ.get("MAIL_SMTP_PORT", "587")),
        smtp_security=os.environ.get("MAIL_SMTP_SECURITY", "starttls").strip().lower(),
        smtp_username=os.environ.get("MAIL_SMTP_USERNAME", "").strip(),
        auth=os.environ.get("MAIL_AUTH", "password").strip().lower(),
        secret=os.environ.get("MAIL_PASSWORD", "")
        or os.environ.get("MAIL_REFRESH_TOKEN", ""),
        oauth_provider=os.environ.get("MAIL_OAUTH_PROVIDER", "").strip().lower(),
        oauth_client_id=os.environ.get("MAIL_OAUTH_CLIENT_ID", "").strip(),
        oauth_client_secret=os.environ.get("MAIL_OAUTH_CLIENT_SECRET", "").strip(),
        oauth_tenant=os.environ.get("MAIL_OAUTH_TENANT", "common").strip(),
        verify_ssl=_bool_env("MAIL_VERIFY_SSL", True),
        read_only=_bool_env("MAIL_READ_ONLY", False),
        timeout=float(os.environ.get("MAIL_TIMEOUT", "30")),
    )
    return account


def _accounts_from_file(path: str) -> list[MailAccount]:
    """Load several mailboxes from a JSON file (a list of account objects)."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Could not read MAIL_ACCOUNTS_FILE %s: %s", path, e)
        return []
    if isinstance(payload, dict):
        payload = payload.get("accounts", [])
    accounts: list[MailAccount] = []
    for index, record in enumerate(payload or []):
        secret = record.pop("password", "") or record.pop("secret", "")
        record.setdefault("account_id", f"box_file{index + 1}")
        try:
            account = MailAccount.from_record(record, secret=secret)
            account.validate()
        except (AccountConfigError, TypeError) as e:
            logger.error("Skipping mailbox #%d from %s: %s", index + 1, path, e)
            continue
        accounts.append(account)
    return accounts


def _env_account_set() -> AccountSet:
    accounts: list[MailAccount] = []
    path = os.environ.get("MAIL_ACCOUNTS_FILE", "").strip()
    if path:
        accounts += _accounts_from_file(path)
    single = _account_from_env()
    if single is not None:
        accounts.append(single)
    default_id = os.environ.get("MAIL_DEFAULT_ACCOUNT", "").strip()
    if default_id:
        for account in accounts:
            if account.matches(default_id):
                default_id = account.account_id
                break
    return AccountSet(accounts=accounts, default_account_id=default_id)


_ENV_ACCOUNTS: AccountSet | None = None
_ENV_CLIENTS: dict[str, ImapClient] = {}


def _build_mcp() -> MCPServer:
    """Construct the MCP server, turning on OAuth in multi-user mode."""
    kwargs: dict[str, Any] = {"instructions": INSTRUCTIONS}
    if _MULTITENANT:
        from mail_mcp.oauth import SCOPE, MailOAuthProvider
        from mail_mcp.store import ConnectionStore, MailboxRegistry

        global STORE, REGISTRY, OAUTH_PROVIDER
        STORE = ConnectionStore()
        REGISTRY = MailboxRegistry(STORE)
        OAUTH_PROVIDER = MailOAuthProvider(STORE)

        # Startup fallback only: the web app serves request-derived metadata.
        public_url = (
            os.environ.get("MAIL_PUBLIC_URL") or "http://localhost:8000"
        ).rstrip("/")
        kwargs["auth_server_provider"] = OAUTH_PROVIDER
        kwargs["auth"] = AuthSettings(
            issuer_url=public_url,  # type: ignore[arg-type]
            resource_server_url=public_url,  # type: ignore[arg-type]
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(enabled=False),
            # Tokens are minted here and bound to a client_id, not to a
            # resource audience, so the SDK's audience check would reject them.
            validate_token_resource=False,
        )
    return MCPServer("mail", **kwargs)


mcp = _build_mcp()


def transport_security() -> TransportSecuritySettings:
    """DNS-rebinding protection settings shared by every transport.

    Behind a reverse proxy the Host header is the public domain, so the SDK's
    default allow-list would answer 421 to every request. Pin the hosts with
    MAIL_ALLOWED_HOSTS, or leave the check off and rely on OAuth.
    """
    allowed = [
        host.strip()
        for host in os.environ.get("MAIL_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    ]
    if allowed:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"https://{h}" for h in allowed]
            + [f"http://{h}" for h in allowed],
        )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# ---------------------------------------------------------------------------
# Per-request resolution
# ---------------------------------------------------------------------------


class ToolError(RuntimeError):
    """An error meant to be shown to the agent verbatim."""


def _current_account_set() -> AccountSet:
    if _MULTITENANT:
        token = get_access_token()
        if token is None:
            raise ToolError("Unauthenticated: missing or invalid access token.")
        account_set = (
            REGISTRY.account_set_for_client_id(token.client_id) if REGISTRY else None
        )
        if account_set is None:
            raise ToolError("Unknown connection for the presented credentials.")
        return account_set

    global _ENV_ACCOUNTS
    if _ENV_ACCOUNTS is None:
        _ENV_ACCOUNTS = _env_account_set()
    return _ENV_ACCOUNTS


def _resolve(selector: str | None) -> tuple[MailAccount, ImapClient]:
    """Find the mailbox a call is about and its live IMAP client."""
    account_set = _current_account_set()
    account = account_set.resolve(selector)
    if _MULTITENANT and REGISTRY is not None:
        token = get_access_token()
        client = REGISTRY.imap_for(token.client_id if token else "", account)
    else:
        client = _ENV_CLIENTS.get(account.account_id)
        if client is None:
            client = ImapClient(account)
            _ENV_CLIENTS[account.account_id] = client
    return account, client


def _handle(error: Exception) -> str:
    """Turn an internal error into the text the agent sees."""
    if isinstance(error, (ImapError, SmtpError)):
        return f"Error: {error.message} {error.detail}".strip()
    if isinstance(error, (AccountConfigError, ComposeError, SearchError, ToolError)):
        return f"Error: {error}"
    logger.exception("Unexpected failure in a tool call")
    return f"Error: {type(error).__name__}: {error}"


def _ensure_writable(account: MailAccount, action: str) -> None:
    """Stop a read-only mailbox before anything is composed or sent."""
    if account.read_only:
        raise ToolError(
            f"{account.address} is connected read-only, so {action} is not allowed. "
            "Change that in the web UI if you meant to."
        )


def _uid_list(uids: list[int] | int | str) -> list[int]:
    """Accept a list, a single UID, or a comma-separated string."""
    if isinstance(uids, int):
        return [uids]
    if isinstance(uids, str):
        return [int(part) for part in uids.replace(" ", "").split(",") if part]
    return [int(uid) for uid in uids]


async def _summaries(
    client: ImapClient, folder: str | None, uids: list[int]
) -> list[dict[str, Any]]:
    items = await client.fetch_summaries(folder, uids)
    for item in items:
        item["headers"] = parse_headers(item.pop("headers_raw", b""))
    return items


# ---------------------------------------------------------------------------
# Tools: discovery
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_accounts() -> str:
    """List the mailboxes (email addresses) this connection can use.

    Every other tool takes an optional `account` argument naming one of these,
    by address, label or id. Omit it and the default mailbox is used.
    """
    try:
        account_set = _current_account_set()
        return formatting.format_accounts(
            list(account_set.accounts), account_set.default_account_id
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def check_account(account: str | None = None) -> str:
    """Test that a mailbox really connects: IMAP login, folders, SMTP login.

    Use this first when something fails, to tell a credential problem from a
    server or network problem.

    Args:
        account: Which mailbox to test (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        imap_report = await client.check()
        try:
            smtp_report = await smtp_client.check(mail_account)
            smtp_line = f"SMTP OK ({smtp_report['host']})"
        except SmtpError as e:
            smtp_line = f"SMTP FAILED: {e.message} {e.detail}".strip()
        capabilities = ", ".join(imap_report["capabilities"][:12])
        return formatting.format_action(
            f"IMAP OK ({imap_report['host']}), {imap_report['folders']} folders.",
            smtp=smtp_line,
            mailbox=mail_account.address,
            capabilities=capabilities,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def list_folders(account: str | None = None) -> str:
    """List the folders of a mailbox, with their role (sent, trash, drafts...).

    Args:
        account: Which mailbox to read (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        folders = await client.list_folders(refresh=True)
        status = None
        try:
            status = await client.status("INBOX")
        except ImapError:
            pass
        return formatting.format_folders(folders, mail_account, status)
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def folder_status(folder: str = "INBOX", account: str | None = None) -> str:
    """Message counts for one folder, plus mailbox quota when the server reports it.

    Args:
        folder: Folder name or role (INBOX, sent, trash, drafts, junk, archive).
        account: Which mailbox to read (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        status = await client.status(folder)
        quota = await client.quota()
        return formatting.format_action(
            f"{status.get('folder', folder)} ({mail_account.address})",
            messages=status.get("messages"),
            unread=status.get("unseen"),
            recent=status.get("recent"),
            uidnext=status.get("uidnext"),
            quota=(
                f"{quota['used_kb'] / 1024:.0f} MB of {quota['limit_kb'] / 1024:.0f} MB "
                f"({quota['used_percent']}%)"
                if quota and quota.get("limit_kb")
                else None
            ),
        )
    except Exception as e:
        return _handle(e)


# ---------------------------------------------------------------------------
# Tools: reading
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_messages(
    folder: str = "INBOX",
    limit: int = 25,
    unread_only: bool = False,
    account: str | None = None,
) -> str:
    """List the most recent messages in a folder, newest first.

    Args:
        folder: Folder name or role (INBOX, sent, trash, drafts, junk, archive).
        limit: How many messages to return (default 25).
        unread_only: Only messages that are still unread.
        account: Which mailbox to read (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        criteria = build_criteria(unread=True) if unread_only else build_criteria()
        uids, total = await client.search(folder, criteria, limit=limit)
        summaries = await _summaries(client, folder, uids)
        return formatting.format_message_list(
            summaries,
            account=mail_account,
            folder=folder,
            total=total,
            criteria="UNSEEN" if unread_only else "",
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def search_messages(
    query: str | None = None,
    sender: str | None = None,
    recipient: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    since: str | None = None,
    before: str | None = None,
    unread: bool | None = None,
    flagged: bool | None = None,
    has_attachment: bool = False,
    folder: str = "INBOX",
    limit: int = 25,
    raw_query: str | None = None,
    account: str | None = None,
) -> str:
    """Search a folder. All filters are optional and combine with AND.

    Args:
        query: Free text searched in headers and body (IMAP TEXT).
        sender: Match the From header (substring, e.g. "@acme.com").
        recipient: Match the To header.
        subject: Match the Subject header.
        body: Search the body only.
        since: Only messages on or after this date (YYYY-MM-DD, 'today',
            'yesterday', or an age such as '7d', '2w', '6m').
        before: Only messages before this date, same formats.
        unread: True for unread only, False for read only.
        flagged: True for flagged (starred) only, False for unflagged only.
        has_attachment: Only messages that look like they carry attachments.
        folder: Folder name or role to search (default INBOX).
        limit: How many messages to return (default 25, newest first).
        raw_query: Raw IMAP SEARCH tokens, appended as-is for advanced use.
        account: Which mailbox to search (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        criteria = build_criteria(
            query=query,
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            since=since,
            before=before,
            unread=unread,
            flagged=flagged,
            has_attachment=has_attachment,
            raw=raw_query,
        )
        uids, total = await client.search(folder, criteria, limit=limit)
        summaries = await _summaries(client, folder, uids)
        return formatting.format_message_list(
            summaries,
            account=mail_account,
            folder=folder,
            total=total,
            criteria=describe(criteria),
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def get_message(
    uid: int,
    folder: str = "INBOX",
    max_chars: int = 8000,
    include_html: bool = False,
    mark_as_read: bool = False,
    account: str | None = None,
) -> str:
    """Read one message in full, by its UID in a folder.

    Args:
        uid: The message UID, as shown by list_messages or search_messages.
        folder: The folder that UID belongs to (UIDs are per-folder).
        max_chars: Truncate the body beyond this many characters (0 = no limit).
        include_html: Also return the raw HTML part when there is one.
        mark_as_read: Set the \\Seen flag after reading (default: leave it alone).
        account: Which mailbox to read (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        raw = await client.fetch_raw(folder, uid)
        parsed = parse_message(raw)
        body, was_truncated = truncate(parsed.body, max_chars)
        if include_html and parsed.html:
            html_body, _ = truncate(parsed.html, max_chars)
            body = f"{body}\n\n--- HTML source ---\n{html_body}"
        flags: list[str] = []
        summaries = await client.fetch_summaries(folder, [uid])
        if summaries:
            flags = summaries[0].get("flags", [])
        if mark_as_read:
            await client.store_flags(folder, [uid], ["\\Seen"], add=True)
        return formatting.format_message(
            parsed,
            uid=uid,
            folder=folder,
            account=mail_account,
            body=body,
            truncated=was_truncated,
            flags=flags,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def get_thread(
    uid: int, folder: str = "INBOX", limit: int = 20, account: str | None = None
) -> str:
    """Find the other messages of a conversation, in this folder and in Sent.

    IMAP has no portable threading command, so this matches on the normalised
    subject and then keeps only messages that share the conversation's
    Message-ID chain (References / In-Reply-To), plus exact subject matches.

    Args:
        uid: A UID belonging to the conversation.
        folder: The folder that UID belongs to.
        limit: How many messages to return per folder searched.
        account: Which mailbox to read (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        raw = await client.fetch_raw(folder, uid)
        parsed = parse_message(raw)
        base_subject = parsed.subject
        for prefix in ("re:", "fwd:", "fw:", "tr:", "rép:", "rep:"):
            while base_subject.lower().startswith(prefix):
                base_subject = base_subject[len(prefix):].strip()
        chain = set(parsed.references) | {parsed.message_id}
        chain.discard("")

        folders = [folder]
        sent = await client.folder_for_role("sent")
        if sent and sent != folder:
            folders.append(sent)

        sections: list[str] = []
        for target in folders:
            criteria = build_criteria(subject=base_subject or parsed.subject)
            uids, total = await client.search(target, criteria, limit=limit)
            summaries = await _summaries(client, target, uids)
            kept = []
            for item in summaries:
                headers = item["headers"]
                ids = set(headers.get("references", []))
                ids.add(headers.get("message_id", ""))
                ids.add(headers.get("in_reply_to", ""))
                ids.discard("")
                same_subject = bool(base_subject) and base_subject.lower() in headers.get(
                    "subject", ""
                ).lower()
                if chain & ids or same_subject:
                    kept.append(item)
            if kept:
                sections.append(
                    formatting.format_message_list(
                        kept,
                        account=mail_account,
                        folder=target,
                        total=total,
                        criteria=f'SUBJECT "{base_subject}"',
                    )
                )
        if not sections:
            return f"No other message found in the conversation {base_subject!r}."
        return f"Conversation: **{base_subject}**\n\n" + "\n\n".join(sections)
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def get_attachment(
    uid: int,
    part_id: str,
    folder: str = "INBOX",
    max_bytes: int = 1_000_000,
    account: str | None = None,
) -> str:
    """Download one attachment, as text when it is text, base64 otherwise.

    Args:
        uid: The UID of the message carrying the attachment.
        part_id: The part id shown in get_message's attachment list.
        folder: The folder that UID belongs to.
        max_bytes: Refuse attachments larger than this (default 1 MB).
        account: Which mailbox to read (address, label or id).
    """
    try:
        _, client = _resolve(account)
        raw = await client.fetch_raw(folder, uid)
        parsed = parse_message(raw)
        part = parsed.attachment_part(str(part_id))
        if part is None:
            available = ", ".join(
                f"{a.part_id} ({a.filename})" for a in parsed.attachments
            )
            return (
                f"Error: message {uid} has no part {part_id!r}. "
                f"Available: {available or 'none'}."
            )
        payload = part.get_payload(decode=True) or b""
        if len(payload) > max_bytes:
            return (
                f"Error: that attachment is {len(payload)} bytes, over the "
                f"{max_bytes} byte limit. Raise max_bytes to fetch it anyway."
            )
        filename = next(
            (a.filename for a in parsed.attachments if a.part_id == str(part_id)),
            f"part-{part_id}",
        )
        content_type = part.get_content_type()
        if content_type.startswith("text/"):
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            return f"{filename} ({content_type}, {len(payload)} bytes):\n\n{text}"
        encoded = base64.b64encode(payload).decode()
        return (
            f"{filename} ({content_type}, {len(payload)} bytes), base64:\n\n{encoded}"
        )
    except Exception as e:
        return _handle(e)


# ---------------------------------------------------------------------------
# Tools: writing
# ---------------------------------------------------------------------------


async def _save_copy(client: ImapClient, role: str, message: bytes, flags: str) -> str:
    """APPEND a copy of an outgoing message; returns the folder name or ''."""
    try:
        target = await client.folder_for_role(role)
        if not target:
            return ""
        await client.append(target, message, flags=flags)
        return mutf7.decode(target)
    except ImapError as e:
        logger.warning("Could not save a copy to %s: %s", role, e)
        return ""


@mcp.tool()
async def send_message(
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    save_to_sent: bool = True,
    account: str | None = None,
) -> str:
    """Send a new email. This is irreversible: confirm with the user first.

    Args:
        to: Recipient(s), comma-separated. Names are allowed ("Ada <a@b.c>").
        subject: The subject line.
        body: The plain text body.
        cc: Carbon-copy recipient(s), comma-separated.
        bcc: Blind carbon-copy recipient(s), comma-separated.
        html: Optional HTML alternative of the body.
        attachments: [{"filename": ..., "content_base64": ..., "content_type": ...}].
        save_to_sent: Also store a copy in the Sent folder (default true).
        account: Which mailbox to send from (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        _ensure_writable(mail_account, "sending")
        outgoing = build_message(
            mail_account,
            to=to,
            subject=subject,
            body=body,
            cc=cc,
            bcc=bcc,
            html=html or "",
            attachments=attachments,
        )
        result = await smtp_client.send(
            mail_account, outgoing.as_bytes(), outgoing.recipients
        )
        saved = ""
        if save_to_sent:
            saved = await _save_copy(client, "sent", outgoing.as_bytes(), "\\Seen")
        return formatting.format_send_result(
            result,
            account=mail_account,
            subject=subject,
            saved_to=saved,
            message_id=outgoing.message_id,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def reply_message(
    uid: int,
    body: str,
    folder: str = "INBOX",
    reply_all: bool = False,
    quote_original: bool = True,
    attachments: list[dict[str, Any]] | None = None,
    save_to_sent: bool = True,
    account: str | None = None,
) -> str:
    """Reply to a message, keeping it in the same conversation.

    Args:
        uid: The UID of the message to reply to.
        body: Your reply text (the original is quoted below it).
        folder: The folder that UID belongs to.
        reply_all: Also copy the other recipients of the original.
        quote_original: Append the quoted original (default true).
        attachments: [{"filename": ..., "content_base64": ..., "content_type": ...}].
        save_to_sent: Also store a copy in the Sent folder (default true).
        account: Which mailbox to reply from (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        _ensure_writable(mail_account, "replying")
        original = parse_message(await client.fetch_raw(folder, uid))
        outgoing = build_reply(
            mail_account,
            original,
            body=body,
            reply_all=reply_all,
            attachments=attachments,
            quote_original=quote_original,
        )
        result = await smtp_client.send(
            mail_account, outgoing.as_bytes(), outgoing.recipients
        )
        saved = ""
        if save_to_sent:
            saved = await _save_copy(client, "sent", outgoing.as_bytes(), "\\Seen")
        try:
            await client.store_flags(folder, [uid], ["\\Answered"], add=True)
        except ImapError:
            pass
        return formatting.format_send_result(
            result,
            account=mail_account,
            subject=outgoing.message.get("Subject", ""),
            saved_to=saved,
            message_id=outgoing.message_id,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def forward_message(
    uid: int,
    to: str,
    body: str = "",
    folder: str = "INBOX",
    cc: str | None = None,
    attach_original: bool = True,
    save_to_sent: bool = True,
    account: str | None = None,
) -> str:
    """Forward a message to someone else.

    Args:
        uid: The UID of the message to forward.
        to: Recipient(s), comma-separated.
        body: Optional note to put above the forwarded content.
        folder: The folder that UID belongs to.
        cc: Carbon-copy recipient(s), comma-separated.
        attach_original: Attach the original as a .eml file (default true).
        save_to_sent: Also store a copy in the Sent folder (default true).
        account: Which mailbox to forward from (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        _ensure_writable(mail_account, "forwarding")
        original = parse_message(await client.fetch_raw(folder, uid))
        outgoing = build_forward(
            mail_account,
            original,
            to=to,
            body=body,
            cc=cc,
            attach_original=attach_original,
        )
        result = await smtp_client.send(
            mail_account, outgoing.as_bytes(), outgoing.recipients
        )
        saved = ""
        if save_to_sent:
            saved = await _save_copy(client, "sent", outgoing.as_bytes(), "\\Seen")
        return formatting.format_send_result(
            result,
            account=mail_account,
            subject=outgoing.message.get("Subject", ""),
            saved_to=saved,
            message_id=outgoing.message_id,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def save_draft(
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    account: str | None = None,
) -> str:
    """Write a message to the Drafts folder without sending it.

    Use this when the user should review or finish the message themselves.

    Args:
        to: Recipient(s), comma-separated.
        subject: The subject line.
        body: The plain text body.
        cc: Carbon-copy recipient(s), comma-separated.
        bcc: Blind carbon-copy recipient(s), comma-separated.
        html: Optional HTML alternative of the body.
        attachments: [{"filename": ..., "content_base64": ..., "content_type": ...}].
        account: Which mailbox to draft in (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        _ensure_writable(mail_account, "saving drafts")
        outgoing = build_message(
            mail_account,
            to=to,
            subject=subject,
            body=body,
            cc=cc,
            bcc=bcc,
            html=html or "",
            attachments=attachments,
        )
        saved = await _save_copy(client, "drafts", outgoing.as_bytes(), "\\Draft")
        if not saved:
            return (
                "Error: this mailbox has no Drafts folder I can write to. "
                "Create one with create_folder, or send the message instead."
            )
        return formatting.format_action(
            f"Draft saved to {saved} ({mail_account.address}).",
            subject=subject,
            to=to,
            message_id=outgoing.message_id,
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def mark_messages(
    uids: list[int],
    action: str,
    folder: str = "INBOX",
    account: str | None = None,
) -> str:
    """Flag messages: read, unread, flagged (starred), unflagged, answered.

    Args:
        uids: The UIDs to act on.
        action: One of read, unread, flagged, unflagged, answered, unanswered.
        folder: The folder those UIDs belong to.
        account: Which mailbox to act on (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        targets = _uid_list(uids)
        mapping = {
            "read": ("\\Seen", True),
            "seen": ("\\Seen", True),
            "unread": ("\\Seen", False),
            "unseen": ("\\Seen", False),
            "flagged": ("\\Flagged", True),
            "starred": ("\\Flagged", True),
            "unflagged": ("\\Flagged", False),
            "answered": ("\\Answered", True),
            "unanswered": ("\\Answered", False),
        }
        entry = mapping.get(action.strip().lower())
        if entry is None:
            return (
                f"Error: unknown action {action!r}. Use one of: "
                f"{', '.join(sorted(mapping))}."
            )
        flag, add = entry
        count = await client.store_flags(folder, targets, [flag], add=add)
        return formatting.format_action(
            f"Marked {count} message(s) as {action} in {folder} "
            f"({mail_account.address}).",
            uids=", ".join(str(u) for u in targets),
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def move_messages(
    uids: list[int],
    destination: str,
    folder: str = "INBOX",
    account: str | None = None,
) -> str:
    """Move messages to another folder.

    Args:
        uids: The UIDs to move.
        destination: Target folder name or role (archive, junk, trash...).
        folder: The folder those UIDs currently belong to.
        account: Which mailbox to act on (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        targets = _uid_list(uids)
        count = await client.move(folder, targets, destination)
        return formatting.format_action(
            f"Moved {count} message(s) from {folder} to {destination} "
            f"({mail_account.address}).",
            note="UIDs change on move; list the destination folder to get the new ones.",
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def delete_messages(
    uids: list[int],
    folder: str = "INBOX",
    permanent: bool = False,
    account: str | None = None,
) -> str:
    """Delete messages, by moving them to Trash (or permanently if asked).

    Args:
        uids: The UIDs to delete.
        folder: The folder those UIDs belong to.
        permanent: Expunge instead of moving to Trash. This cannot be undone.
        account: Which mailbox to act on (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        targets = _uid_list(uids)
        if not permanent:
            trash = await client.folder_for_role("trash")
            if trash:
                count = await client.move(folder, targets, trash)
                return formatting.format_action(
                    f"Moved {count} message(s) to Trash ({mail_account.address}).",
                    folder=folder,
                )
        count = await client.store_flags(folder, targets, ["\\Deleted"], add=True)
        scope = await client.expunge(folder, targets)
        return formatting.format_action(
            f"Permanently deleted {count} message(s) from {folder} "
            f"({mail_account.address}). This cannot be undone.",
            note=(
                ""
                if scope == "uids"
                else "This server cannot expunge single messages, so anything "
                "else already flagged as deleted in that folder was removed too."
            ),
        )
    except Exception as e:
        return _handle(e)


@mcp.tool()
async def create_folder(name: str, account: str | None = None) -> str:
    """Create a folder. Use the server's delimiter for nesting (e.g. "Clients/Acme").

    Args:
        name: The folder name to create.
        account: Which mailbox to act on (address, label or id).
    """
    try:
        mail_account, client = _resolve(account)
        created = await client.create_folder(name)
        return formatting.format_action(
            f"Created folder {created!r} in {mail_account.address}."
        )
    except Exception as e:
        return _handle(e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server standalone (stdio by default)."""
    import argparse

    parser = argparse.ArgumentParser(description="Mail MCP Gateway server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address for HTTP transports"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port for HTTP transports"
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return
    mcp.run(
        transport=args.transport,
        host=args.host,
        port=args.port,
        transport_security=transport_security(),
    )


if __name__ == "__main__":
    main()
