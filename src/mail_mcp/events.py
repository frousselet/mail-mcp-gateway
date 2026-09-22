"""Reading and writing iCalendar events.

CalDAV moves ``VEVENT`` components around; this module is the boundary between
those and the plain values the MCP tools exchange. Parsing and serialisation go
through the ``icalendar`` library rather than hand-rolled text handling, so
line folding, escaping, parameters and timezones behave.

Updates re-use the resource that came off the server and change only the
properties asked for: an event carries fields no agent knows about (alarms,
custom X- properties, scheduling state), and rewriting it from scratch would
silently drop them. That goes for the whole resource, not just one event: a
recurring event is stored as its master plus one VEVENT per modified
occurrence, and next to them the VTIMEZONE definitions their times refer to.
All of that is written back.

Recurring events are expanded into their occurrences for reading, so a daily
meeting shows up on every day of the window it repeats in, with the moved and
cancelled occurrences applied.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import recurring_ical_events
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

    data = raw if isinstance(raw, bytes) else str(raw).encode()
    return [
        _record(component, href=href, etag=etag, calendar=calendar, raw=data)
        for component in parsed.walk("VEVENT")
    ]


def _record(
    component, *, href: str, etag: str, calendar: str, raw: bytes, rrule: str = ""
) -> EventRecord:
    start = component.decoded("dtstart", None) if component.get("dtstart") else None
    if component.get("dtend"):
        end = component.decoded("dtend", None)
    elif component.get("duration") and start is not None:
        end = start + component.decoded("duration")
    elif start is not None and not isinstance(start, datetime):
        # RFC 5545 3.6.1: an all-day event with neither DTEND nor DURATION
        # lasts one day; a timed one lasts no time at all.
        end = start + timedelta(days=1)
    else:
        end = None
    recurrence_id = component.get("recurrence-id")
    return EventRecord(
        uid=_text(component, "uid"),
        summary=_text(component, "summary"),
        start=start,
        end=end,
        all_day=isinstance(start, date) and not isinstance(start, datetime),
        location=_text(component, "location"),
        description=_text(component, "description"),
        status=_text(component, "status"),
        organizer=_text(component, "organizer").replace("mailto:", "").replace(
            "MAILTO:", ""
        ),
        attendees=_attendees(component),
        recurrence=_rrule_text(component) or rrule,
        recurrence_id=(
            _isoformat(component.decoded("recurrence-id"))
            if recurrence_id is not None
            else ""
        ),
        url=_text(component, "url"),
        href=href,
        etag=etag,
        calendar=calendar,
        raw=raw,
    )


def expand_events(
    raw: bytes | str,
    start: datetime,
    end: datetime,
    *,
    href: str = "",
    etag: str = "",
    calendar: str = "",
) -> list[EventRecord]:
    """The occurrences of a resource that fall in ``[start, end)``.

    A CalDAV time-range query matches a recurring event when any occurrence
    overlaps, but hands back the unexpanded resource: the master with its
    first date and its rule. Expanding it here (rather than asking the server
    to, which not every server supports) gives every occurrence in the window
    its own dates, applies the modified ones (RECURRENCE-ID), and leaves out
    the removed ones (EXDATE).
    """
    if not raw:
        return []
    try:
        parsed = Calendar.from_ical(raw)
    except Exception as e:
        raise EventError(f"This calendar entry could not be read: {e}") from e
    data = raw if isinstance(raw, bytes) else str(raw).encode()
    rules = {
        _text(component, "uid"): _rrule_text(component)
        for component in parsed.walk("VEVENT")
        if component.get("rrule")
    }
    try:
        occurrences = recurring_ical_events.of(parsed).between(start, end)
    except Exception:
        # A rule the library cannot follow: show the resource as it is rather
        # than lose the event.
        return parse_events(raw, href=href, etag=etag, calendar=calendar)
    return [
        _record(
            component,
            href=href,
            etag=etag,
            calendar=calendar,
            raw=data,
            rrule=rules.get(_text(component, "uid"), ""),
        )
        for component in occurrences
    ]


def master_of(records: list[EventRecord]) -> EventRecord | None:
    """The master event of a resource: the one that is not an override."""
    for record in records:
        if not record.recurrence_id:
            return record
    return records[0] if records else None


# ---------------------------------------------------------------------------
# Building and editing
# ---------------------------------------------------------------------------


def _serialise(calendar: Calendar) -> bytes:
    """Write a calendar, with a VTIMEZONE for every TZID its times use.

    RFC 5545 requires one, and a client that cannot resolve a TZID shows the
    event at the wrong time. Existing definitions are kept as they are (an
    Outlook zone such as "Romance Standard Time" only exists in them).
    """
    try:
        calendar.add_missing_timezones()
    except Exception:  # an unknown zone name: leave it as it came
        pass
    return calendar.to_ical()


def _wrap(component: Event) -> bytes:
    calendar = Calendar()
    calendar.add("prodid", PRODID)
    calendar.add("version", "2.0")
    calendar.add_component(component)
    return _serialise(calendar)


def _read_calendar(raw: bytes) -> tuple[Calendar, list[Event]]:
    try:
        calendar = Calendar.from_ical(raw)
    except Exception as e:
        raise EventError(f"This calendar entry could not be read: {e}") from e
    components = list(calendar.walk("VEVENT"))
    if not components:
        raise EventError("That calendar entry holds no event.")
    return calendar, components


def _is_day(value: Any) -> bool:
    return isinstance(value, date) and not isinstance(value, datetime)


def _day(value: datetime | date) -> date:
    return value.date() if isinstance(value, datetime) else value


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
        # DTEND of an all-day event is the day after the last one (RFC 5545
        # 3.6.1): "the 24th to the 26th" is DTEND 27th, a single day is +1.
        first, last = _day(start), _day(end)
        component.add("dtstart", first)
        component.add("dtend", max(last, first) + timedelta(days=1))
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
    """Apply changes to an existing resource, keeping everything else intact.

    The change goes to the master event; the modified occurrences stored next
    to it, and the timezone definitions, are written back untouched.

    For an all-day event ``end`` is the last day, inclusive, as a person says
    it; it is stored as the day after, as iCalendar wants.
    """
    calendar, components = _read_calendar(raw)
    component = next(
        (c for c in components if c.get("recurrence-id") is None), components[0]
    )

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
        new_start, new_end = _new_times(component, start, end, all_day)
        replace("dtstart", new_start)
        component.pop("duration", None)
        replace("dtend", new_end)
    if attendees is not None:
        _set_attendees(component, attendees)

    replace("dtstamp", datetime.now(UTC))
    sequence = int(component.get("sequence", 0) or 0)
    replace("sequence", sequence + 1)
    return _serialise(calendar)


def _new_times(
    component,
    start: datetime | date | None,
    end: datetime | date | None,
    all_day: bool | None,
) -> tuple[datetime | date, datetime | date]:
    """Work out DTSTART and DTEND after a change of time.

    The kind of event (all day or timed) stays what it was unless ``all_day``
    says otherwise, and moving only the start keeps the duration.
    """
    current_start = component.decoded("dtstart") if component.get("dtstart") else None
    if component.get("dtend"):
        current_end = component.decoded("dtend")
    elif component.get("duration") and current_start is not None:
        current_end = current_start + component.decoded("duration")
    elif current_start is not None and _is_day(current_start):
        current_end = current_start + timedelta(days=1)
    else:
        current_end = current_start

    was_day = _is_day(current_start)
    whole_day = all_day if all_day is not None else was_day

    if whole_day:
        first = _day(start) if start is not None else (
            _day(current_start) if current_start is not None else None
        )
        if first is None:
            raise EventError("Changing the time needs a start.")
        if end is not None:
            after_last = _day(end) + timedelta(days=1)
        elif was_day and current_start is not None and current_end is not None:
            after_last = first + (_day(current_end) - _day(current_start))
        else:
            after_last = first + timedelta(days=1)
        if after_last <= first:
            raise EventError("The event would end before it starts.")
        return first, after_last

    if start is None and was_day:
        raise EventError(
            "To turn an all-day event into a timed one, give its new start time."
        )
    new_start = start if start is not None else current_start
    if new_start is None:
        raise EventError("Changing the time needs a start.")
    if _is_day(new_start):
        raise EventError("A timed event needs a start time, not just a date.")
    if end is not None:
        new_end = end
    elif not was_day and current_start is not None and current_end is not None:
        new_end = new_start + (current_end - current_start)
    else:
        new_end = new_start + timedelta(hours=1)
    if _is_day(new_end):
        raise EventError("A timed event needs an end time, not just a date.")
    if new_end < new_start:
        raise EventError("The event would end before it starts.")
    return new_start, new_end


def set_participation(raw: bytes, address: str, answer: str) -> bytes:
    """Set this account's PARTSTAT on an invitation (accept, decline, tentative)."""
    partstat = PARTSTAT_BY_ANSWER.get(answer.strip().lower())
    if partstat is None:
        raise EventError(
            f"{answer!r} is not an answer I understand. Use accept, decline or tentative."
        )
    calendar, components = _read_calendar(raw)

    # The answer is for the whole series: the master and every modified
    # occurrence carry their own attendee list.
    wanted = address.strip().lower()
    matched = False
    for component in components:
        entries = component.get("attendee")
        entries = entries if isinstance(entries, list) else ([entries] if entries else [])
        touched = False
        for entry in entries:
            email = str(entry).replace("mailto:", "").replace("MAILTO:", "").strip().lower()
            if email == wanted:
                entry.params["PARTSTAT"] = vText(partstat)
                entry.params.pop("RSVP", None)
                touched = True
        if not touched:
            continue
        matched = True
        component.pop("attendee", None)
        for entry in entries:
            component.add("attendee", entry, encode=0)
        component.pop("dtstamp", None)
        component.add("dtstamp", datetime.now(UTC))
    if not matched:
        raise EventError(
            f"{address} is not an attendee of this event, so there is nothing to answer."
        )
    return _serialise(calendar)
