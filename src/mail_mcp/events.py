"""Reading and writing iCalendar events.

CalDAV moves ``VEVENT`` components around; this module is the boundary between
those and the plain values the MCP tools exchange. Parsing and serialisation go
through the ``icalendar`` library rather than hand-rolled text handling, so
line folding, escaping, parameters and timezones behave.

Updates re-use the component that came off the server and change only the
properties asked for: an event carries fields no agent knows about (alarms,
custom X- properties, scheduling state), and rewriting it from scratch would
silently drop them.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from icalendar import Calendar, Event, vCalAddress, vText

PRODID = "-//mail-mcp-gateway//CalDAV//EN"

_RELATIVE_RE = re.compile(r"^([+-]?\d+)\s*([hdwm])$", re.IGNORECASE)
_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d/%m/%Y %H:%M",
    "%Y-%m-%d",
    "%d/%m/%Y",
)

PARTSTAT_BY_ANSWER = {
    "accept": "ACCEPTED",
    "accepted": "ACCEPTED",
    "yes": "ACCEPTED",
    "decline": "DECLINED",
    "declined": "DECLINED",
    "no": "DECLINED",
    "tentative": "TENTATIVE",
    "maybe": "TENTATIVE",
}


class EventError(ValueError):
    """Raised when event arguments cannot be turned into a VEVENT."""


# ---------------------------------------------------------------------------
# Time parsing
# ---------------------------------------------------------------------------


def zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except Exception:
        return ZoneInfo("UTC")


def parse_when(
    value: str | datetime | date | None,
    tz: str = "UTC",
    *,
    end_of_day: bool = False,
) -> datetime:
    """Read a time from what an agent is likely to pass.

    Accepts ISO-ish stamps (``2026-09-24T10:00``), plain dates
    (``2026-09-24``), ``now``/``today``/``tomorrow``/``yesterday`` and relative
    offsets (``+7d``, ``-2w``, ``+3h``). A value without an offset is read in
    ``tz``; a bare date becomes midnight, or the end of that day when
    ``end_of_day`` is set.
    """
    info = zone(tz)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=info)
    if isinstance(value, date):
        moment = time(23, 59, 59) if end_of_day else time(0, 0)
        return datetime.combine(value, moment, tzinfo=info)
    if value is None or not str(value).strip():
        return datetime.now(info)

    text = str(value).strip()
    lowered = text.lower()
    now = datetime.now(info)
    if lowered in ("now",):
        return now
    if lowered in ("today", "tomorrow", "yesterday"):
        offset = {"today": 0, "tomorrow": 1, "yesterday": -1}[lowered]
        day = (now + timedelta(days=offset)).date()
        return parse_when(day, tz, end_of_day=end_of_day)

    relative = _RELATIVE_RE.match(text)
    if relative:
        amount, unit = int(relative.group(1)), relative.group(2).lower()
        delta = {
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
            "w": timedelta(weeks=amount),
            "m": timedelta(days=30 * amount),
        }[unit]
        return now + delta

    normalised = text.replace("Z", "+0000")
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(normalised, fmt)
        except ValueError:
            continue
        if fmt in ("%Y-%m-%d", "%d/%m/%Y"):
            return parse_when(parsed.date(), tz, end_of_day=end_of_day)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=info)

    # Last chance: ISO 8601 with a colon in the offset.
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as e:
        raise EventError(
            f"{value!r} is not a date or time I understand. Use 2026-09-24, "
            "2026-09-24T10:00, 'today', 'tomorrow', or an offset such as '+7d'."
        ) from e
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=info)


def to_utc(moment: datetime) -> datetime:
    return moment.astimezone(UTC)


def caldav_stamp(moment: datetime) -> str:
    """UTC in the basic format CalDAV time-range filters want."""
    return to_utc(moment).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class Attendee:
    email: str
    name: str = ""
    status: str = ""  # PARTSTAT
    role: str = ""

    def describe(self) -> str:
        who = f"{self.name} <{self.email}>" if self.name else self.email
        return f"{who} ({self.status.lower()})" if self.status else who


@dataclass
class EventRecord:
    """One VEVENT, flattened into what the tools return."""

    uid: str = ""
    summary: str = ""
    start: datetime | date | None = None
    end: datetime | date | None = None
    all_day: bool = False
    location: str = ""
    description: str = ""
    status: str = ""
    organizer: str = ""
    attendees: list[Attendee] = field(default_factory=list)
    recurrence: str = ""
    recurrence_id: str = ""
    url: str = ""
    href: str = ""  # CalDAV path of the containing resource
    etag: str = ""
    calendar: str = ""
    raw: bytes = b""

    @property
    def my_status(self) -> str:
        return self.status

    def attendee_for(self, address: str) -> Attendee | None:
        wanted = address.strip().lower()
        for attendee in self.attendees:
            if attendee.email.lower() == wanted:
                return attendee
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "summary": self.summary,
            "start": _isoformat(self.start),
            "end": _isoformat(self.end),
            "all_day": self.all_day,
            "location": self.location,
            "status": self.status,
            "organizer": self.organizer,
            "attendees": [a.describe() for a in self.attendees],
            "recurrence": self.recurrence,
            "calendar": self.calendar,
            "href": self.href,
        }


def _isoformat(value: datetime | date | None) -> str:
    if value is None:
        return ""
    return value.isoformat()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _text(component, name: str) -> str:
    value = component.get(name)
    if value is None:
        return ""
    return str(value).strip()


def _rrule_text(component) -> str:
    """Render RRULE the way it appears on the wire, not as a repr."""
    rule = component.get("rrule")
    if rule is None:
        return ""
    try:
        return rule.to_ical().decode()
    except AttributeError:
        return str(rule)


def _attendees(component) -> list[Attendee]:
    raw = component.get("attendee")
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    out: list[Attendee] = []
    for item in values:
        address = str(item).replace("mailto:", "").replace("MAILTO:", "").strip()
        params = getattr(item, "params", {}) or {}
        out.append(
            Attendee(
                email=address,
                name=str(params.get("CN", "")).strip(),
                status=str(params.get("PARTSTAT", "")).strip(),
                role=str(params.get("ROLE", "")).strip(),
            )
        )
    return out


def parse_events(
    raw: bytes | str, *, href: str = "", etag: str = "", calendar: str = ""
) -> list[EventRecord]:
    """Parse one calendar resource into its events (usually a single one)."""
    if not raw:
        return []
    try:
        parsed = Calendar.from_ical(raw)
    except Exception as e:
        raise EventError(f"This calendar entry could not be read: {e}") from e

    records: list[EventRecord] = []
    for component in parsed.walk("VEVENT"):
        start = component.decoded("dtstart", None) if component.get("dtstart") else None
        if component.get("dtend"):
            end = component.decoded("dtend", None)
        elif component.get("duration") and start is not None:
            end = start + component.decoded("duration")
        else:
            end = None
        organizer = _text(component, "organizer").replace("mailto:", "")
        records.append(
            EventRecord(
                uid=_text(component, "uid"),
                summary=_text(component, "summary"),
                start=start,
                end=end,
                all_day=isinstance(start, date) and not isinstance(start, datetime),
                location=_text(component, "location"),
                description=_text(component, "description"),
                status=_text(component, "status"),
                organizer=organizer,
                attendees=_attendees(component),
                recurrence=_rrule_text(component),
                recurrence_id=_text(component, "recurrence-id"),
                url=_text(component, "url"),
                href=href,
                etag=etag,
                calendar=calendar,
                raw=raw if isinstance(raw, bytes) else str(raw).encode(),
            )
        )
    return records


# ---------------------------------------------------------------------------
# Building and editing
# ---------------------------------------------------------------------------


def _wrap(component: Event) -> bytes:
    calendar = Calendar()
    calendar.add("prodid", PRODID)
    calendar.add("version", "2.0")
    calendar.add_component(component)
    return calendar.to_ical()


def _set_attendees(component: Event, attendees: list[str] | str | None) -> None:
    if attendees is None:
        return
    if isinstance(attendees, str):
        attendees = [part.strip() for part in attendees.replace(";", ",").split(",")]
    component.pop("attendee", None)
    for entry in attendees:
        address = entry.strip()
        if not address:
            continue
        name = ""
        if "<" in address and ">" in address:
            name, _, rest = address.partition("<")
            address = rest.rstrip(">").strip()
            name = name.strip()
        value = vCalAddress(f"MAILTO:{address}")
        if name:
            value.params["CN"] = vText(name)
        value.params["ROLE"] = vText("REQ-PARTICIPANT")
        value.params["PARTSTAT"] = vText("NEEDS-ACTION")
        value.params["RSVP"] = vText("TRUE")
        component.add("attendee", value, encode=0)


def build_event(
    *,
    summary: str,
    start: datetime | date,
    end: datetime | date,
    all_day: bool = False,
    description: str = "",
    location: str = "",
    attendees: list[str] | str | None = None,
    organizer: str = "",
    recurrence: str = "",
    uid: str = "",
) -> tuple[str, bytes]:
    """Build a new event; returns ``(uid, ics bytes)``."""
    if not summary.strip():
        raise EventError("An event needs a title (summary).")
    if end < start:
        raise EventError("The event ends before it starts.")

    component = Event()
    event_uid = uid or f"{uuid.uuid4()}@mail-mcp-gateway"
    component.add("uid", event_uid)
    component.add("dtstamp", datetime.now(UTC))
    component.add("summary", summary.strip())
    if all_day:
        component.add("dtstart", start.date() if isinstance(start, datetime) else start)
        component.add("dtend", end.date() if isinstance(end, datetime) else end)
    else:
        component.add("dtstart", start)
        component.add("dtend", end)
    if description:
        component.add("description", description)
    if location:
        component.add("location", location)
    if recurrence:
        component.add("rrule", _parse_rrule(recurrence))
    if organizer:
        value = vCalAddress(f"MAILTO:{organizer}")
        component.add("organizer", value, encode=0)
    _set_attendees(component, attendees)
    return event_uid, _wrap(component)


def _parse_rrule(value: str) -> dict[str, Any]:
    """Turn ``FREQ=WEEKLY;COUNT=10`` (or just ``weekly``) into an RRULE dict."""
    text = value.strip()
    if "=" not in text:
        shorthand = text.upper()
        if shorthand not in ("DAILY", "WEEKLY", "MONTHLY", "YEARLY"):
            raise EventError(
                f"{value!r} is not a recurrence I understand. Use 'weekly', or a "
                "full rule such as 'FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10'."
            )
        return {"FREQ": [shorthand]}
    rule: dict[str, Any] = {}
    for part in text.replace("RRULE:", "").split(";"):
        if not part.strip():
            continue
        name, _, raw = part.partition("=")
        rule[name.strip().upper()] = [v.strip() for v in raw.split(",") if v.strip()]
    if "FREQ" not in rule:
        raise EventError("A recurrence rule needs a FREQ, e.g. 'FREQ=WEEKLY'.")
    return rule


def edit_event(
    raw: bytes,
    *,
    summary: str | None = None,
    start: datetime | date | None = None,
    end: datetime | date | None = None,
    all_day: bool | None = None,
    description: str | None = None,
    location: str | None = None,
    attendees: list[str] | str | None = None,
    status: str | None = None,
    recurrence: str | None = None,
) -> bytes:
    """Apply changes to an existing resource, keeping everything else intact."""
    try:
        calendar = Calendar.from_ical(raw)
    except Exception as e:
        raise EventError(f"This calendar entry could not be read: {e}") from e

    components = list(calendar.walk("VEVENT"))
    if not components:
        raise EventError("That calendar entry holds no event.")
    component = components[0]

    def replace(name: str, value: Any) -> None:
        component.pop(name, None)
        component.add(name, value)

    if summary is not None:
        replace("summary", summary)
    if description is not None:
        replace("description", description)
    if location is not None:
        replace("location", location)
    if status is not None:
        replace("status", status.upper())
    if recurrence is not None:
        component.pop("rrule", None)
        if recurrence:
            component.add("rrule", _parse_rrule(recurrence))
    if start is not None or end is not None or all_day is not None:
        current_start = component.decoded("dtstart") if component.get("dtstart") else None
        current_end = component.decoded("dtend") if component.get("dtend") else None
        new_start = start if start is not None else current_start
        new_end = end if end is not None else current_end
        if new_start is None or new_end is None:
            raise EventError("Changing the time needs both a start and an end.")
        if new_end < new_start:
            raise EventError("The event would end before it starts.")
        whole_day = (
            all_day
            if all_day is not None
            else isinstance(new_start, date) and not isinstance(new_start, datetime)
        )
        if whole_day:
            new_start = new_start.date() if isinstance(new_start, datetime) else new_start
            new_end = new_end.date() if isinstance(new_end, datetime) else new_end
        replace("dtstart", new_start)
        replace("dtend", new_end)
    if attendees is not None:
        _set_attendees(component, attendees)

    replace("dtstamp", datetime.now(UTC))
    sequence = int(component.get("sequence", 0) or 0)
    replace("sequence", sequence + 1)
    return _wrap(component)


def set_participation(raw: bytes, address: str, answer: str) -> bytes:
    """Set this account's PARTSTAT on an invitation (accept, decline, tentative)."""
    partstat = PARTSTAT_BY_ANSWER.get(answer.strip().lower())
    if partstat is None:
        raise EventError(
            f"{answer!r} is not an answer I understand. Use accept, decline or tentative."
        )
    try:
        calendar = Calendar.from_ical(raw)
    except Exception as e:
        raise EventError(f"This calendar entry could not be read: {e}") from e

    components = list(calendar.walk("VEVENT"))
    if not components:
        raise EventError("That calendar entry holds no event.")
    component = components[0]

    wanted = address.strip().lower()
    entries = component.get("attendee")
    entries = entries if isinstance(entries, list) else ([entries] if entries else [])
    matched = False
    for entry in entries:
        email = str(entry).replace("mailto:", "").replace("MAILTO:", "").strip().lower()
        if email == wanted:
            entry.params["PARTSTAT"] = vText(partstat)
            entry.params.pop("RSVP", None)
            matched = True
    if not matched:
        raise EventError(
            f"{address} is not an attendee of this event, so there is nothing to answer."
        )
    component.pop("attendee", None)
    for entry in entries:
        component.add("attendee", entry, encode=0)
    component.pop("dtstamp", None)
    component.add("dtstamp", datetime.now(UTC))
    return _wrap(component)
