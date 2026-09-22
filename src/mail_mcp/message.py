"""Parsing of RFC 5322 messages into something an agent can read.

Mail is messy: headers are RFC 2047 word-encoded, bodies come in mixed
charsets, HTML-only mail is common and attachments can nest arbitrarily. This
module turns a raw message into plain text plus a flat list of attachment
parts addressed by a stable ``part_id``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, ClassVar

_WS_RE = re.compile(r"[ \t]+")
_BLANKS_RE = re.compile(r"\n{3,}")


def decode_value(value: str | bytes | None) -> str:
    """Decode an RFC 2047 encoded header into text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    try:
        return str(make_header(decode_header(value))).strip()
    except (UnicodeDecodeError, LookupError, ValueError):
        return value.strip()


def addresses(value: str | None) -> list[str]:
    """Split an address header into ``Name <addr>`` strings, decoded."""
    if not value:
        return []
    out: list[str] = []
    for name, addr in getaddresses([decode_value(value)]):
        if name and addr:
            out.append(f"{name} <{addr}>")
        elif addr:
            out.append(addr)
        elif name:
            out.append(name)
    return out


def address_only(value: str | None) -> list[str]:
    """Just the bare addresses from a header."""
    if not value:
        return []
    return [addr for _, addr in getaddresses([decode_value(value)]) if addr]


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


class _TextExtractor(HTMLParser):
    """Minimal HTML to text: keeps block structure, drops markup and scripts."""

    _BLOCKS: ClassVar[set[str]] = {
        "p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
        "table", "blockquote", "section", "article", "header", "footer",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag in self._BLOCKS:
            self.parts.append("\n")
        elif tag == "a":
            href = dict(attrs).get("href", "")
            if href and not href.startswith(("javascript:", "#")):
                self._pending_href = href

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head"):
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCKS:
            self.parts.append("\n")
        elif tag == "a":
            href = getattr(self, "_pending_href", "")
            if href:
                self.parts.append(f" <{href}>")
                self._pending_href = ""

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    text = "".join(parser.parts)
    text = _WS_RE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    return _BLANKS_RE.sub("\n\n", text).strip()


def _part_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


@dataclass
class Attachment:
    part_id: str
    filename: str
    content_type: str
    size: int
    inline: bool = False
    content_id: str = ""


@dataclass
class ParsedMessage:
    """A message, split into the pieces the MCP tools return."""

    subject: str = ""
    from_: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    date: datetime | None = None
    message_id: str = ""
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    list_unsubscribe: str = ""
    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    raw: bytes = b""
    _parts: dict[str, Message] = field(default_factory=dict, repr=False)

    @property
    def body(self) -> str:
        """Best-effort plain text body (HTML converted when that is all there is)."""
        if self.text.strip():
            return self.text.strip()
        if self.html.strip():
            return html_to_text(self.html)
        return ""

    def attachment_part(self, part_id: str) -> Message | None:
        return self._parts.get(part_id)

    def summary_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "from": self.from_,
            "to": self.to,
            "cc": self.cc,
            "date": self.date.isoformat() if self.date else "",
            "message_id": self.message_id,
            "attachments": [a.filename for a in self.attachments],
        }


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse a full RFC 5322 message."""
    message = message_from_bytes(raw, policy=policy.default)
    parsed = ParsedMessage(raw=raw)
    parsed.subject = decode_value(message.get("Subject"))
    parsed.from_ = ", ".join(addresses(message.get("From")))
    parsed.to = addresses(message.get("To"))
    parsed.cc = addresses(message.get("Cc"))
    parsed.bcc = addresses(message.get("Bcc"))
    parsed.reply_to = addresses(message.get("Reply-To"))
    parsed.date = parse_date(message.get("Date"))
    parsed.message_id = (message.get("Message-ID") or "").strip()
    parsed.in_reply_to = (message.get("In-Reply-To") or "").strip()
    parsed.references = (message.get("References") or "").split()
    parsed.list_unsubscribe = (message.get("List-Unsubscribe") or "").strip()

    index = 0
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        index += 1
        part_id = str(index)
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        filename = decode_value(part.get_filename() or "")

        is_attachment = disposition in ("attachment", "inline") and bool(filename)
        if not is_attachment and content_type.startswith("text/") and not filename:
            if content_type == "text/plain" and not parsed.text:
                parsed.text = _part_text(part)
                continue
            if content_type == "text/html" and not parsed.html:
                parsed.html = _part_text(part)
                continue
        if not is_attachment and content_type.startswith(("image/", "application/")):
            is_attachment = True
            filename = filename or f"part-{part_id}.{content_type.partition('/')[2]}"
        if not is_attachment:
            continue

        payload = part.get_payload(decode=True) or b""
        parsed.attachments.append(
            Attachment(
                part_id=part_id,
                filename=filename or f"part-{part_id}",
                content_type=content_type,
                size=len(payload),
                inline=disposition == "inline",
                content_id=(part.get("Content-ID") or "").strip("<>"),
            )
        )
        parsed._parts[part_id] = part
    return parsed


def parse_headers(raw_headers: bytes) -> dict[str, Any]:
    """Parse the header block fetched for a listing."""
    message = message_from_bytes(raw_headers, policy=policy.default)
    return {
        "subject": decode_value(message.get("Subject")),
        "from": ", ".join(addresses(message.get("From"))),
        "from_address": (address_only(message.get("From")) or [""])[0],
        "to": addresses(message.get("To")),
        "cc": addresses(message.get("Cc")),
        "date": parse_date(message.get("Date")),
        "message_id": (message.get("Message-ID") or "").strip(),
        "in_reply_to": (message.get("In-Reply-To") or "").strip(),
        "references": (message.get("References") or "").split(),
        "list_unsubscribe": (message.get("List-Unsubscribe") or "").strip(),
    }


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Cut ``text`` to ``limit`` characters on a line boundary when possible."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    cut = text[:limit]
    newline = cut.rfind("\n")
    if newline > limit * 0.6:
        cut = cut[:newline]
    return cut.rstrip(), True
