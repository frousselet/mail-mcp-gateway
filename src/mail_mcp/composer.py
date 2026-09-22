"""Build outgoing messages (new mail, replies, forwards, drafts)."""

from __future__ import annotations

import base64
import binascii
import mimetypes
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid, parseaddr
from typing import Any

from mail_mcp.accounts import MailAccount
from mail_mcp.message import ParsedMessage, html_to_text

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


class ComposeError(ValueError):
    """Raised when an outgoing message cannot be built from the arguments."""


@dataclass
class OutgoingMessage:
    message: EmailMessage
    recipients: list[str] = field(default_factory=list)

    @property
    def message_id(self) -> str:
        return self.message.get("Message-ID", "")

    def as_bytes(self) -> bytes:
        return self.message.as_bytes()


def _split_addresses(value: str | list[str] | None) -> list[str]:
    """Accept a list, or a comma/semicolon separated string, of addresses."""
    if not value:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
    else:
        parts = [str(p).strip() for p in value]
    return [p for p in parts if p]


def _bare(address: str) -> str:
    return parseaddr(address)[1] or address


def attach_files(message: EmailMessage, attachments: list[dict[str, Any]] | None) -> None:
    """Attach ``[{filename, content_base64, content_type?}, ...]`` to a message."""
    total = 0
    for item in attachments or []:
        if not isinstance(item, dict):
            raise ComposeError(
                "Each attachment must be an object with 'filename' and "
                "'content_base64' fields."
            )
        filename = str(item.get("filename") or "").strip()
        encoded = item.get("content_base64") or item.get("content") or ""
        if not filename or not encoded:
            raise ComposeError(
                "An attachment needs both 'filename' and 'content_base64'."
            )
        try:
            payload = base64.b64decode(str(encoded), validate=False)
        except (binascii.Error, ValueError) as e:
            raise ComposeError(f"Attachment {filename!r} is not valid base64.") from e
        total += len(payload)
        if total > MAX_ATTACHMENT_BYTES:
            raise ComposeError(
                f"Attachments exceed the {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB limit."
            )
        content_type = str(
            item.get("content_type")
            or mimetypes.guess_type(filename)[0]
            or "application/octet-stream"
        )
        maintype, _, subtype = content_type.partition("/")
        message.add_attachment(
            payload,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename,
        )


def build_message(
    account: MailAccount,
    *,
    to: str | list[str] | None = None,
    subject: str = "",
    body: str = "",
    cc: str | list[str] | None = None,
    bcc: str | list[str] | None = None,
    html: str = "",
    reply_to: str | list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
    bcc_header: bool = False,
) -> OutgoingMessage:
    """Build a message ready to hand to SMTP or to APPEND as a draft.

    ``bcc_header`` writes the blind recipients into the message itself. That is
    wrong for something about to be sent, since a Bcc carried in the headers is
    not blind, and right for a draft, which is how mail clients remember them
    until the message goes out.
    """
    to_list = _split_addresses(to)
    cc_list = _split_addresses(cc)
    bcc_list = _split_addresses(bcc)
    if not (to_list or cc_list or bcc_list):
        raise ComposeError("At least one recipient is required (to, cc or bcc).")

    message = EmailMessage()
    message["From"] = account.sender()
    if to_list:
        message["To"] = ", ".join(to_list)
    if cc_list:
        message["Cc"] = ", ".join(cc_list)
    if bcc_list and bcc_header:
        message["Bcc"] = ", ".join(bcc_list)
    message["Subject"] = subject or "(no subject)"
    message["Date"] = format_datetime(datetime.now(UTC))
    domain = account.address.rpartition("@")[2] or "localhost"
    message["Message-ID"] = make_msgid(domain=domain)
    reply_list = _split_addresses(reply_to)
    if reply_list:
        message["Reply-To"] = ", ".join(reply_list)
    for name, value in (headers or {}).items():
        if value:
            message[name] = value

    if html and not body:
        body = html_to_text(html)
    message.set_content(body or "")
    if html:
        message.add_alternative(html, subtype="html")

    attach_files(message, attachments)

    recipients = [_bare(a) for a in to_list + cc_list + bcc_list]
    return OutgoingMessage(message=message, recipients=recipients)


def _quote_body(original: ParsedMessage, limit: int = 8000) -> str:
    """Quote the original body the way a mail client does."""
    when = original.date.strftime("%d %b %Y at %H:%M") if original.date else "an earlier date"
    lines = [f"On {when}, {original.from_ or 'the sender'} wrote:"]
    body = original.body[:limit]
    lines += [f"> {line}" for line in body.splitlines()]
    return "\n".join(lines)


def build_reply(
    account: MailAccount,
    original: ParsedMessage,
    *,
    body: str,
    reply_all: bool = False,
    html: str = "",
    attachments: list[dict[str, Any]] | None = None,
    quote_original: bool = True,
    extra_to: str | list[str] | None = None,
) -> OutgoingMessage:
    """Build a reply threaded onto ``original``."""
    reply_targets = original.reply_to or ([original.from_] if original.from_ else [])
    to_list = _split_addresses(reply_targets) + _split_addresses(extra_to)
    cc_list: list[str] = []
    if reply_all:
        mine = account.address.lower()
        for address in original.to + original.cc:
            if _bare(address).lower() != mine and address not in to_list:
                cc_list.append(address)
    if not to_list and not cc_list:
        raise ComposeError("The original message has no address to reply to.")

    subject = original.subject or ""
    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}".strip()

    text = body
    if quote_original and original.body:
        text = f"{body}\n\n{_quote_body(original)}"

    references = list(original.references)
    if original.message_id and original.message_id not in references:
        references.append(original.message_id)

    headers = {}
    if original.message_id:
        headers["In-Reply-To"] = original.message_id
    if references:
        headers["References"] = " ".join(references)

    return build_message(
        account,
        to=to_list,
        cc=cc_list,
        subject=subject,
        body=text,
        html=html,
        attachments=attachments,
        headers=headers,
    )


def build_forward(
    account: MailAccount,
    original: ParsedMessage,
    *,
    to: str | list[str],
    body: str = "",
    cc: str | list[str] | None = None,
    attach_original: bool = True,
) -> OutgoingMessage:
    """Build a forward, carrying the original message as an attachment."""
    subject = original.subject or ""
    if not subject.lower().startswith(("fw:", "fwd:")):
        subject = f"Fwd: {subject}".strip()

    intro = body.rstrip()
    header_block = "\n".join(
        filter(
            None,
            [
                "---------- Forwarded message ----------",
                f"From: {original.from_}" if original.from_ else "",
                f"Date: {original.date.isoformat()}" if original.date else "",
                f"Subject: {original.subject}" if original.subject else "",
                f"To: {', '.join(original.to)}" if original.to else "",
            ],
        )
    )
    text = f"{intro}\n\n{header_block}\n\n{original.body}".strip()

    outgoing = build_message(
        account, to=to, cc=cc, subject=subject, body=text
    )
    if attach_original and original.raw:
        outgoing.message.add_attachment(
            original.raw,
            maintype="message",
            subtype="rfc822",
            filename=f"{(original.subject or 'message')[:60]}.eml",
        )
    return outgoing


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


def carried_attachments(original: ParsedMessage) -> list[dict[str, Any]]:
    """Re-encode an existing message's attachments so they can be re-attached.

    IMAP cannot edit a message in place: revising a draft means writing a new
    one, and its attachments have to travel across by hand or they are lost.
    """
    carried: list[dict[str, Any]] = []
    for attachment in original.attachments:
        part = original.attachment_part(attachment.part_id)
        if part is None:
            continue
        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue
        carried.append(
            {
                "filename": attachment.filename,
                "content_base64": base64.b64encode(payload).decode(),
                "content_type": attachment.content_type,
            }
        )
    return carried


def revise_draft(
    account: MailAccount,
    original: ParsedMessage,
    *,
    to: str | list[str] | None = None,
    subject: str | None = None,
    body: str | None = None,
    cc: str | list[str] | None = None,
    bcc: str | list[str] | None = None,
    html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    keep_attachments: bool = True,
) -> OutgoingMessage:
    """Build the revised version of a draft: only the given fields change.

    Everything not passed is carried over from the draft as it stands, so
    "change the subject" does not quietly drop the recipients or the files.
    """
    files = attachments
    if files is None and keep_attachments:
        files = carried_attachments(original)

    return build_message(
        account,
        to=to if to is not None else list(original.to),
        cc=cc if cc is not None else list(original.cc),
        bcc=bcc if bcc is not None else list(original.bcc),
        subject=subject if subject is not None else original.subject,
        body=body if body is not None else original.body,
        html=html if html is not None else original.html,
        attachments=files,
        headers={
            "In-Reply-To": original.in_reply_to,
            "References": " ".join(original.references),
        },
        bcc_header=True,
    )


def prepare_for_sending(original: ParsedMessage) -> tuple[bytes, list[str]]:
    """Turn a stored draft into what SMTP needs: the wire bytes and envelope.

    ``Bcc`` is read to build the envelope and then stripped from the message,
    because a blind copy that travels in the headers is not blind. ``Date`` is
    refreshed: the draft may have been written days ago.
    """
    message = message_from_bytes(original.raw, policy=policy.default)
    recipients = [
        _bare(address)
        for header in ("To", "Cc", "Bcc")
        for address in _split_addresses(message.get(header, ""))
    ]
    recipients = [address for address in recipients if address]
    if not recipients:
        raise ComposeError("That draft has no recipient, so there is nobody to send it to.")

    del message["Bcc"]
    del message["Date"]
    message["Date"] = format_datetime(datetime.now(UTC))
    return message.as_bytes(), recipients
