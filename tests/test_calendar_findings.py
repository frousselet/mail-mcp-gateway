"""Regressions for the calendar side of the review.

A recurring meeting must be busy on every day it repeats, answering an
invitation must not wipe the moved occurrences, a one-day booking must last
a day, and a write the server redirected must not be reported as done.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest
from icalendar import Calendar

from mail_mcp import server
from mail_mcp.caldav_client import CalDavClient, CalDavError
from mail_mcp.calendars import CalendarAccount, CalendarConfigError, CalendarSet
from mail_mcp.events import build_event, edit_event, expand_events, set_participation

PARIS = ZoneInfo("Europe/Paris")
PERSONAL = "/calendars/ada/personal/"

STANDUP = b"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//test//EN
BEGIN:VTIMEZONE
TZID:Romance Standard Time
BEGIN:STANDARD
DTSTART:16010101T030000
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:16010101T020000
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
UID:standup-123
SUMMARY:Standup
DTSTART;TZID=Romance Standard Time:20250106T090000
DTEND;TZID=Romance Standard Time:20250106T100000
RRULE:FREQ=DAILY
ORGANIZER:mailto:boss@example.test
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.test
END:VEVENT
BEGIN:VEVENT
UID:standup-123
RECURRENCE-ID;TZID=Romance Standard Time:20260923T090000
SUMMARY:Standup (moved)
DTSTART;TZID=Romance Standard Time:20260923T140000
DTEND;TZID=Romance Standard Time:20260923T150000
ORGANIZER:mailto:boss@example.test
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.test
END:VEVENT
END:VCALENDAR
""".replace(b"\n", b"\r\n")


@pytest.fixture
def caldav_server():
    from fake_caldav import FakeCalDAVState, build_app

    state = FakeCalDAVState()
    state.app = build_app(state)
    return state


@pytest.fixture
def calendar_account(caldav_server) -> CalendarAccount:
    return CalendarAccount(
        address=caldav_server.username,
        account_id="cal_test",
        url="https://caldav.test",
        secret=caldav_server.password,
        timezone="Europe/Paris",
        default_calendar="Personal",
    )


@pytest.fixture
def tools(monkeypatch, calendar_account, caldav_server):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_CALENDARS", CalendarSet([calendar_account], "cal_test"))
    transport = httpx.ASGITransport(app=caldav_server.app)
    server._ENV_CALDAV.clear()
    server._ENV_CALDAV["cal_test"] = CalDavClient(calendar_account, transport=transport)
    yield server
    server._ENV_CALDAV.clear()


def _stored(caldav_server, href: str) -> Calendar:
    calendar = caldav_server.calendars[PERSONAL]
    return Calendar.from_ical(calendar.entries[href][0])


# --- recurring events are expanded --------------------------------------------


def test_a_daily_meeting_occurs_on_each_day_of_the_window():
    occurrences = expand_events(
        STANDUP, datetime(2026, 9, 22, tzinfo=PARIS), datetime(2026, 9, 25, tzinfo=PARIS)
    )
    starts = [(o.summary, o.start.astimezone(PARIS).strftime("%d %H:%M")) for o in occurrences]
    assert starts == [
        ("Standup", "22 09:00"),
        ("Standup (moved)", "23 14:00"),
        ("Standup", "24 09:00"),
    ]


async def test_list_events_shows_occurrences_not_the_first_date(tools, caldav_server):
    caldav_server.seed(PERSONAL, STANDUP, "standup")
    out = await tools.list_events(start="2026-09-22", end="2026-09-22")
    assert "2026-09-22 09:00" in out
    assert "2025-01-06" not in out


async def test_find_free_time_sees_every_occurrence(tools, caldav_server):
    caldav_server.seed(PERSONAL, STANDUP, "standup")
    out = await tools.find_free_time(
        start="2026-09-22", end="2026-09-22", duration_minutes=60
    )
    assert "09:00" not in out.split("free slot")[1].splitlines()[1]
    assert "10:00" in out


# --- writes keep the whole resource -------------------------------------------


def test_answering_keeps_the_moved_occurrence_and_the_timezone():
    updated = Calendar.from_ical(set_participation(STANDUP, "ada@example.test", "accept"))
    events = list(updated.walk("VEVENT"))
    assert len(events) == 2, "the override was dropped"
    assert all("ACCEPTED" in str(e.get("attendee").params["PARTSTAT"]) for e in events)
    assert [tz.get("tzid") for tz in updated.walk("VTIMEZONE")] == ["Romance Standard Time"]


def test_editing_changes_the_master_and_leaves_the_override():
    updated = Calendar.from_ical(edit_event(STANDUP, summary="Daily"))
    by_kind = {bool(e.get("recurrence-id")): str(e.get("summary")) for e in updated.walk("VEVENT")}
    assert by_kind == {False: "Daily", True: "Standup (moved)"}


def test_a_new_event_carries_its_timezone_definition():
    _, ics = build_event(
        summary="Point",
        start=datetime(2026, 9, 24, 10, tzinfo=PARIS),
        end=datetime(2026, 9, 24, 11, tzinfo=PARIS),
    )
    parsed = Calendar.from_ical(ics)
    assert [str(tz.get("tzid")) for tz in parsed.walk("VTIMEZONE")] == ["Europe/Paris"]


# --- all-day events -----------------------------------------------------------


def test_a_one_day_event_lasts_a_day():
    _, ics = build_event(
        summary="Off",
        start=datetime(2026, 9, 24, tzinfo=PARIS),
        end=datetime(2026, 9, 24, tzinfo=PARIS),
        all_day=True,
    )
    event = Calendar.from_ical(ics).walk("VEVENT")[0]
    assert event.decoded("dtstart") == date(2026, 9, 24)
    assert event.decoded("dtend") == date(2026, 9, 25)


async def test_a_trip_to_the_26th_blocks_the_26th(tools, caldav_server):
    out = await tools.create_event(
        summary="Trip", start="2026-09-24", end="2026-09-26", all_day=True
    )
    assert "2026-09-24 to 2026-09-26 (all day)" in out
    (href,) = caldav_server.calendars[PERSONAL].entries
    event = _stored(caldav_server, href).walk("VEVENT")[0]
    assert event.decoded("dtend") == date(2026, 9, 27)


async def test_moving_an_all_day_event_keeps_it_all_day(tools, caldav_server):
    await tools.create_event(summary="Off", start="2026-09-24", all_day=True)
    (href,) = caldav_server.calendars[PERSONAL].entries
    uid = str(_stored(caldav_server, href).walk("VEVENT")[0].get("uid"))

    out = await tools.update_event(uid=uid, start="2026-09-28")

    assert not out.startswith("Error:"), out
    event = _stored(caldav_server, href).walk("VEVENT")[0]
    assert event.decoded("dtstart") == date(2026, 9, 28)
    assert event.decoded("dtend") == date(2026, 9, 29)


def test_moving_only_the_start_of_a_timed_event_keeps_its_length():
    _, ics = build_event(
        summary="Point",
        start=datetime(2026, 9, 24, 10, tzinfo=PARIS),
        end=datetime(2026, 9, 24, 11, 30, tzinfo=PARIS),
    )
    updated = Calendar.from_ical(
        edit_event(ics, start=datetime(2026, 9, 25, 14, tzinfo=PARIS))
    ).walk("VEVENT")[0]
    assert updated.decoded("dtend") - updated.decoded("dtstart") == timedelta(minutes=90)


def test_an_all_day_event_without_dtend_is_busy_all_day():
    ics = (
        b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:d\r\n"
        b"SUMMARY:Holiday\r\nDTSTART;VALUE=DATE:20260922\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    (event,) = expand_events(
        ics, datetime(2026, 9, 22, tzinfo=PARIS), datetime(2026, 9, 23, tzinfo=PARIS)
    )
    slots = server._free_slots(
        [event],
        datetime(2026, 9, 22, tzinfo=PARIS),
        datetime(2026, 9, 22, 23, 59, tzinfo=PARIS),
        minutes=30,
        tz="Europe/Paris",
        day_start_hour=9,
        day_end_hour=18,
    )
    assert slots == []


# --- lookups and writes are exact --------------------------------------------


async def test_a_uid_is_matched_exactly_not_as_a_substring(tools, caldav_server):
    _, longer = build_event(
        summary="Wrong one",
        start=datetime(2026, 9, 24, 10, tzinfo=PARIS),
        end=datetime(2026, 9, 24, 11, tzinfo=PARIS),
        uid="abc-extended",
    )
    caldav_server.seed(PERSONAL, longer, "a-wrong")
    _, exact = build_event(
        summary="Right one",
        start=datetime(2026, 9, 25, 10, tzinfo=PARIS),
        end=datetime(2026, 9, 25, 11, tzinfo=PARIS),
        uid="abc",
    )
    caldav_server.seed(PERSONAL, exact, "b-right")

    out = await tools.get_event(uid="abc")
    assert "Right one" in out and "Wrong one" not in out


async def test_a_redirected_write_is_not_reported_as_done(tools, caldav_server):
    await tools.create_event(summary="Point", start="2026-09-24T10:00")
    (href,) = caldav_server.calendars[PERSONAL].entries
    uid = str(_stored(caldav_server, href).walk("VEVENT")[0].get("uid"))
    caldav_server.redirect_writes = "/elsewhere/"

    out = await tools.update_event(uid=uid, summary="Changed")

    assert out.startswith("Error:") and "nothing was written" in out
    event = _stored(caldav_server, href).walk("VEVENT")[0]
    assert str(event.get("summary")) == "Point"


async def test_a_refusal_does_not_echo_the_remote_page(calendar_account):
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(405, text="INTERNAL SECRET: admin-token=abc123")

    client = CalDavClient(calendar_account, transport=httpx.MockTransport(answer))
    with pytest.raises(CalDavError) as excinfo:
        await client.check()
    await client.close()
    assert "admin-token" not in str(excinfo.value)


# --- the URL ------------------------------------------------------------------


def test_plain_http_is_refused_except_on_localhost():
    account = CalendarAccount(address="a@example.test", url="http://caldav.example.test",
                              secret="x")
    with pytest.raises(CalendarConfigError, match="https"):
        account.validate()
    CalendarAccount(address="a@example.test", url="http://127.0.0.1:5232",
                    secret="x").validate()
