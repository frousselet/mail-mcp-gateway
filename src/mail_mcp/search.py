"""Build IMAP SEARCH criteria from the arguments an agent passes.

The IMAP search grammar (RFC 3501, 6.4.4) is positional and quoting-sensitive,
so the tools expose named filters and this module turns them into the byte
tokens ``imaplib`` sends. Values go out as UTF-8 with ``CHARSET UTF-8``, which
every modern server accepts; :mod:`mail_mcp.imap_client` falls back to ASCII
when one does not.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta

_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)
_RELATIVE_RE = re.compile(r"^(\d+)\s*([dwmy])$", re.IGNORECASE)


class SearchError(ValueError):
    """Raised when a search argument cannot be turned into IMAP criteria."""


def imap_date(value: str | date | datetime) -> str:
    """Format a date the way IMAP wants it: ``01-Jan-2024``."""
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return f"{value.day:02d}-{_MONTHS[value.month - 1]}-{value.year}"

    text = str(value).strip()
    relative = _RELATIVE_RE.match(text)
    if relative:
        amount, unit = int(relative.group(1)), relative.group(2).lower()
        days = {"d": 1, "w": 7, "m": 30, "y": 365}[unit] * amount
        return imap_date(date.today() - timedelta(days=days))
    lowered = text.lower()
    if lowered == "today":
        return imap_date(date.today())
    if lowered == "yesterday":
        return imap_date(date.today() - timedelta(days=1))
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%b-%Y", "%Y/%m/%d"):
        try:
            return imap_date(datetime.strptime(text, fmt).date())
        except ValueError:
            continue
    raise SearchError(
        f"{value!r} is not a date I understand. Use YYYY-MM-DD, 'today', "
        "'yesterday', or a relative age such as '7d', '2w', '6m'."
    )


def _quoted(value: str) -> bytes:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return b'"' + escaped.encode("utf-8") + b'"'


def build_criteria(
    *,
    query: str | None = None,
    sender: str | None = None,
    recipient: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    since: str | None = None,
    before: str | None = None,
    unread: bool | None = None,
    flagged: bool | None = None,
    answered: bool | None = None,
    has_attachment: bool = False,
    larger_than: int | None = None,
    raw: str | None = None,
) -> list[bytes]:
    """Turn named filters into IMAP SEARCH tokens (ANDed together)."""
    criteria: list[bytes] = []

    if sender:
        criteria += [b"FROM", _quoted(sender)]
    if recipient:
        criteria += [b"TO", _quoted(recipient)]
    if subject:
        criteria += [b"SUBJECT", _quoted(subject)]
    if body:
        criteria += [b"BODY", _quoted(body)]
    if query:
        criteria += [b"TEXT", _quoted(query)]
    if since:
        criteria += [b"SINCE", imap_date(since).encode()]
    if before:
        criteria += [b"BEFORE", imap_date(before).encode()]
    if unread is True:
        criteria.append(b"UNSEEN")
    elif unread is False:
        criteria.append(b"SEEN")
    if flagged is True:
        criteria.append(b"FLAGGED")
    elif flagged is False:
        criteria.append(b"UNFLAGGED")
    if answered is True:
        criteria.append(b"ANSWERED")
    elif answered is False:
        criteria.append(b"UNANSWERED")
    if has_attachment:
        # IMAP has no attachment predicate; multipart/mixed is the usual proxy
        # and matches what mail clients do.
        criteria += [b"HEADER", b"Content-Type", _quoted("multipart/mixed")]
    if larger_than:
        criteria += [b"LARGER", str(int(larger_than)).encode()]
    if raw:
        criteria += [token.encode("utf-8") for token in raw.split()]

    return criteria or [b"ALL"]


def describe(criteria: list[bytes]) -> str:
    """Render criteria back as the IMAP command text, for tool output."""
    return " ".join(token.decode("utf-8", errors="replace") for token in criteria)
