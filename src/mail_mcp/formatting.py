"""Render tool results as compact Markdown.

Tools return text, not JSON: an agent reads these strings directly, so they
lead with what matters (who, when, subject, UID) and keep identifiers visible
so follow-up calls can reference them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mail_mcp.accounts import MailAccount
from mail_mcp.events import EventRecord
from mail_mcp.imap_client import FolderInfo
from mail_mcp.message import ParsedMessage

_FLAG_ICONS = {
    "\\Seen": "",
    "\\Answered": "answered",
    "\\Flagged": "flagged",
    "\\Draft": "draft",
    "\\Deleted": "deleted",
}


def _when(value: datetime | None) -> str:
    if value is None:
        return "unknown date"
    return value.strftime("%Y-%m-%d %H:%M")


def _size(num: int | None) -> str:
    if not num:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0
    return ""


def format_accounts(accounts: list[MailAccount], default_account_id: str = "") -> str:
    if not accounts:
        return (
            "No mailbox is attached to this connection yet. Add one in the web UI, "
            "then call this tool again."
        )
    lines = [f"{len(accounts)} mailbox(es) on this connection:\n"]
    for account in accounts:
        mark = " (default)" if account.account_id == default_account_id else ""
        lines.append(f"- **{account.address}**{mark}")
        if account.label and account.label != account.address:
            lines.append(f"  Label: {account.label}")
        lines.append(f"  IMAP: {account.imap_host}:{account.imap_port} "
                     f"({account.imap_security})")
        lines.append(f"  SMTP: {account.smtp_host}:{account.smtp_port} "
                     f"({account.smtp_security})")
        identities = account.sending_identities()
        if identities[0].lower() != account.address.lower() or len(identities) > 1:
            lines.append(f"  Sends as: {', '.join(identities)} (first is the default)")
        lines.append(f"  Auth: {account.auth}"
                     + (" | read-only" if account.read_only else ""))
        lines.append("")
    lines.append(
        "Pass `account` to any tool to pick one (address, label or id); "
        "omit it to use the default."
    )
    return "\n".join(lines)


def format_folders(
    folders: list[FolderInfo], account: MailAccount, status: dict[str, Any] | None = None
) -> str:
    lines = [f"Folders in {account.address} ({len(folders)}):\n"]
    for folder in folders:
        role = f" [{folder.role}]" if folder.role else ""
        note = "" if folder.selectable else " (not selectable)"
        lines.append(f"- {folder.name}{role}{note}")
    if status:
        lines.append(
            f"\nINBOX: {status.get('messages', '?')} messages, "
            f"{status.get('unseen', '?')} unread."
        )
    return "\n".join(lines)


def format_message_list(
    summaries: list[dict[str, Any]],
    *,
    account: MailAccount,
    folder: str,
    total: int,
    criteria: str = "",
) -> str:
    if not summaries:
        detail = f" matching `{criteria}`" if criteria and criteria != "ALL" else ""
        return f"No message{detail} in {folder} ({account.address})."

    header = (
        f"{len(summaries)} of {total} message(s) in {folder} ({account.address})"
        + (f", search: `{criteria}`" if criteria and criteria != "ALL" else "")
    )
    lines = [header, ""]
    for item in summaries:
        headers = item.get("headers", {})
        flags = item.get("flags", [])
        marks = []
        if "\\Seen" not in flags:
            marks.append("UNREAD")
        for flag, label in _FLAG_ICONS.items():
            if label and flag in flags:
                marks.append(label)
        mark_text = f" [{', '.join(marks)}]" if marks else ""
        date = headers.get("date") or item.get("internal_date")
        lines.append(
            f"- **{headers.get('subject') or '(no subject)'}**{mark_text}\n"
            f"  From: {headers.get('from') or 'unknown'}\n"
            f"  Date: {_when(date)} | UID: `{item['uid']}`"
            + (f" | {_size(item.get('size'))}" if item.get("size") else "")
        )
    lines.append("")
    lines.append(
        "Use `get_message` with a UID (and the same folder) to read one in full."
    )
    return "\n".join(lines)


def format_message(
    parsed: ParsedMessage,
    *,
    uid: int,
    folder: str,
    account: MailAccount,
    body: str,
    truncated: bool = False,
    flags: list[str] | None = None,
) -> str:
    lines = [
        f"**{parsed.subject or '(no subject)'}**",
        "",
        f"From: {parsed.from_}",
        f"To: {', '.join(parsed.to) or '(none)'}",
    ]
    if parsed.cc:
        lines.append(f"Cc: {', '.join(parsed.cc)}")
    if parsed.reply_to:
        lines.append(f"Reply-To: {', '.join(parsed.reply_to)}")
    lines.append(f"Date: {_when(parsed.date)}")
    lines.append(f"Folder: {folder} | UID: `{uid}` | Mailbox: {account.address}")
    if flags:
        lines.append(f"Flags: {', '.join(flags)}")
    if parsed.message_id:
        lines.append(f"Message-ID: {parsed.message_id}")
    if parsed.attachments:
        lines.append("")
        lines.append("Attachments:")
        for attachment in parsed.attachments:
            lines.append(
                f"- `{attachment.part_id}` {attachment.filename} "
                f"({attachment.content_type}, {_size(attachment.size)})"
                + (" [inline]" if attachment.inline else "")
            )
        lines.append(
            "Fetch one with `get_attachment` using the part id shown above."
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(body or "(this message has no text body)")
    if truncated:
        lines.append("")
        lines.append(
            "[body truncated; call get_message again with a larger max_chars "
            "to read the rest]"
        )
    return "\n".join(lines)


def format_send_result(
    result: dict[str, Any],
    *,
    account: MailAccount,
    subject: str,
    saved_to: str = "",
    message_id: str = "",
) -> str:
    accepted = result.get("accepted", [])
    refused = result.get("refused", {})
    lines = [
        f"Sent **{subject or '(no subject)'}** from {account.address} "
        f"to {len(accepted)} recipient(s)."
    ]
    if accepted:
        lines.append(f"Accepted: {', '.join(accepted)}")
    if refused:
        lines.append("Refused:")
        for address, reason in refused.items():
            lines.append(f"- {address}: {reason}")
    if saved_to:
        lines.append(f"A copy was saved to {saved_to}.")
    if message_id:
        lines.append(f"Message-ID: {message_id}")
    return "\n".join(lines)


def format_action(message: str, **details: Any) -> str:
    lines = [message]
    for key, value in details.items():
        if value not in (None, "", [], {}):
            lines.append(f"{key.replace('_', ' ').capitalize()}: {value}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Calendars
# ---------------------------------------------------------------------------


def _event_when(event: EventRecord, tz: str = "UTC") -> str:
    """Render an event's span the way a person reads it."""
    from datetime import date, datetime

    from mail_mcp.events import zone

    start, end = event.start, event.end
    if start is None:
        return "(no start)"
    if event.all_day or (isinstance(start, date) and not isinstance(start, datetime)):
        if end is not None and getattr(end, "toordinal", None) and end != start:
            last = end
            try:  # DTEND of an all-day event is exclusive
                from datetime import timedelta

                last = end - timedelta(days=1)
            except TypeError:
                pass
            if last != start:
                return f"{start} to {last} (all day)"
        return f"{start} (all day)"

    local_start = start.astimezone(zone(tz))
    if end is None:
        return local_start.strftime("%Y-%m-%d %H:%M")
    local_end = end.astimezone(zone(tz))
    if local_start.date() == local_end.date():
        return (
            f"{local_start.strftime('%Y-%m-%d %H:%M')}"
            f" to {local_end.strftime('%H:%M')}"
        )
    return (
        f"{local_start.strftime('%Y-%m-%d %H:%M')}"
        f" to {local_end.strftime('%Y-%m-%d %H:%M')}"
    )


def format_calendar_accounts(accounts: list[Any], default_account_id: str = "") -> str:
    if not accounts:
        return (
            "No calendar is attached to this connection. Add one in the web UI, "
            "then call this tool again."
        )
    lines = [f"{len(accounts)} calendar account(s) on this connection:\n"]
    for account in accounts:
        mark = " (default)" if account.account_id == default_account_id else ""
        lines.append(f"- **{account.address}**{mark}")
        lines.append(f"  Server: {account.entry_point()}")
        lines.append(f"  Timezone: {account.timezone}"
                     + (" | read-only" if account.read_only else ""))
        lines.append("")
    return "\n".join(lines)


def format_calendars(calendars: list[Any], account: Any) -> str:
    if not calendars:
        return f"{account.address} has no calendar the agent can use."
    lines = [f"{len(calendars)} calendar(s) for {account.address}:\n"]
    for calendar in calendars:
        flags = " (read-only)" if calendar.read_only else ""
        lines.append(f"- **{calendar.name}**{flags}")
        if calendar.description:
            lines.append(f"  {calendar.description}")
        lines.append(f"  Path: `{calendar.href}`")
    lines.append("")
    lines.append("Pass `calendar` to any calendar tool to pick one by name.")
    return "\n".join(lines)


def format_events(
    events: list[Any],
    *,
    account: Any,
    calendar: str,
    window: str = "",
    query: str = "",
) -> str:
    if not events:
        detail = f" matching {query!r}" if query else ""
        return f"No event{detail} in {calendar} ({account.address}) {window}.".replace(
            "  ", " "
        )
    header = f"{len(events)} event(s) in {calendar} ({account.address})"
    if window:
        header += f" {window}"
    if query:
        header += f", matching {query!r}"
    lines = [header, ""]
    for event in events:
        line = f"- **{event.summary or '(no title)'}**"
        if event.status and event.status.upper() == "CANCELLED":
            line += " [cancelled]"
        lines.append(line)
        lines.append(f"  {_event_when(event, account.timezone)}")
        if event.location:
            lines.append(f"  Location: {event.location}")
        if event.attendees:
            lines.append(f"  Attendees: {len(event.attendees)}")
        if event.recurrence:
            lines.append(f"  Repeats: {event.recurrence}")
        lines.append(f"  UID: `{event.uid}`")
    lines.append("")
    lines.append("Use `get_event` with a UID to see one in full.")
    return "\n".join(lines)


def format_event(event: Any, *, account: Any, calendar: str) -> str:
    lines = [
        f"**{event.summary or '(no title)'}**",
        "",
        f"When: {_event_when(event, account.timezone)}",
    ]
    if event.location:
        lines.append(f"Location: {event.location}")
    if event.organizer:
        lines.append(f"Organizer: {event.organizer}")
    if event.status:
        lines.append(f"Status: {event.status}")
    if event.recurrence:
        lines.append(f"Repeats: {event.recurrence}")
    lines.append(f"Calendar: {calendar} | Account: {account.address}")
    lines.append(f"UID: `{event.uid}`")
    if event.attendees:
        lines.append("")
        lines.append("Attendees:")
        for attendee in event.attendees:
            lines.append(f"- {attendee.describe()}")
    if event.description:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(event.description)
    return "\n".join(lines)


def format_free_slots(
    slots: list[tuple[Any, Any]], *, account: Any, calendar: str, minutes: int
) -> str:
    from mail_mcp.events import zone

    if not slots:
        return (
            f"No free slot of {minutes} minutes in {calendar} ({account.address}) "
            "within that window."
        )
    info = zone(account.timezone)
    lines = [
        f"{len(slots)} free slot(s) of at least {minutes} minutes "
        f"({account.address}, times in {account.timezone}):\n"
    ]
    for start, end in slots:
        local_start, local_end = start.astimezone(info), end.astimezone(info)
        same_day = local_start.date() == local_end.date()
        ending = (
            local_end.strftime("%H:%M")
            if same_day
            else local_end.strftime("%Y-%m-%d %H:%M")
        )
        lines.append(f"- {local_start.strftime('%Y-%m-%d %H:%M')} to {ending}")
    return "\n".join(lines)
