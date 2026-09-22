"""The calendar tools, driven against the fake CalDAV server."""

from __future__ import annotations

import httpx
import pytest

from mail_mcp import server
from mail_mcp.caldav_client import CalDavClient
from mail_mcp.calendars import CalendarAccount, CalendarSet
from mail_mcp.events import build_event, parse_when


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
    """Single-account mode, with the CalDAV client pointed at the fake server."""
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_CALENDARS", CalendarSet([calendar_account], "cal_test"))
    transport = httpx.ASGITransport(app=caldav_server.app)
    server._ENV_CALDAV.clear()
    server._ENV_CALDAV["cal_test"] = CalDavClient(calendar_account, transport=transport)
    yield server
    server._ENV_CALDAV.clear()


def unfold(ics: bytes) -> bytes:
    """Undo RFC 5545 line folding, so a value can be searched for whole."""
    return ics.replace(b"\r\n ", b"").replace(b"\n ", b"")


def _seed(caldav_server, summary, start, end, calendar="/calendars/ada/personal/", **kwargs):
    uid, ics = build_event(
        summary=summary,
        start=parse_when(start, "Europe/Paris"),
        end=parse_when(end, "Europe/Paris"),
        **kwargs,
    )
    caldav_server.seed(calendar, ics, summary.lower().replace(" ", "-"))
    return uid


async def test_list_calendars(tools):
    out = await tools.list_calendars()
    assert "Personal" in out
    assert "Team (read-only)" in out
    assert "read-only" in out


async def test_list_events_in_a_window(tools, caldav_server):
    _seed(caldav_server, "Point budget", "2026-09-24T10:00", "2026-09-24T11:00")
    _seed(caldav_server, "Trop tard", "2026-12-01T10:00", "2026-12-01T11:00")

    out = await tools.list_events(start="2026-09-24", end="2026-09-25")
    assert "Point budget" in out
    assert "Trop tard" not in out
    assert "2026-09-24 10:00 to 11:00" in out


async def test_list_events_rejects_a_backwards_window(tools):
    out = await tools.list_events(start="2026-09-25", end="2026-09-24")
    assert "ends before it starts" in out


async def test_search_events(tools, caldav_server):
    _seed(caldav_server, "Déjeuner Bob", "2026-09-24T12:00", "2026-09-24T13:00",
          location="Chez Marcel")
    _seed(caldav_server, "Revue produit", "2026-09-24T15:00", "2026-09-24T16:00")

    assert "Déjeuner Bob" in await tools.search_events(query="déjeuner",
                                                        start="2026-09-01", end="2026-10-01")
    assert "Déjeuner Bob" in await tools.search_events(query="marcel",
                                                        start="2026-09-01", end="2026-10-01")
    missing = await tools.search_events(query="rien", start="2026-09-01", end="2026-10-01")
    assert "No event" in missing


async def test_get_event(tools, caldav_server):
    uid = _seed(
        caldav_server, "Conseil", "2026-09-24T09:00", "2026-09-24T10:30",
        location="Salle 2", description="Ordre du jour joint",
        attendees=["Bob <bob@example.test>"],
    )
    out = await tools.get_event(uid=uid)
    assert "Conseil" in out
    assert "Salle 2" in out
    assert "bob@example.test" in out
    assert "Ordre du jour joint" in out


async def test_get_event_searches_other_calendars(tools, caldav_server):
    uid = _seed(caldav_server, "Ailleurs", "2026-09-24T09:00", "2026-09-24T10:00",
                calendar="/calendars/ada/work/")
    out = await tools.get_event(uid=uid)
    assert "Ailleurs" in out
    assert "Work" in out


async def test_missing_event_is_explained(tools):
    out = await tools.get_event(uid="nope@example.test")
    assert out.startswith("Error:")
    assert "No event with UID" in out


async def test_create_event(tools, caldav_server):
    out = await tools.create_event(
        summary="Atelier",
        start="2026-09-24T14:00",
        duration_minutes=90,
        location="Paris",
        attendees="bob@example.test, carol@example.test",
    )
    assert "Created **Atelier**" in out
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    assert any(b"Atelier" in ics for ics, _ in stored.values())
    assert any(b"bob@example.test" in unfold(ics) for ics, _ in stored.values())
    # The end was derived from the duration.
    assert "2026-09-24T14:00:00+02:00 to 2026-09-24T15:30:00+02:00" in out


async def test_create_all_day_event(tools, caldav_server):
    out = await tools.create_event(summary="Congés", start="2026-10-01", end="2026-10-03",
                                   all_day=True)
    assert "Created **Congés**" in out
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    assert any(b"DTSTART;VALUE=DATE:20261001" in ics for ics, _ in stored.values())


async def test_create_recurring_event(tools, caldav_server):
    out = await tools.create_event(summary="Standup", start="2026-09-24T09:30",
                                   duration_minutes=15, recurrence="FREQ=WEEKLY;COUNT=8")
    assert "Repeats: FREQ=WEEKLY;COUNT=8" in out
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    assert any(b"RRULE:FREQ=WEEKLY;COUNT=8" in ics for ics, _ in stored.values())


async def test_bad_recurrence_is_explained(tools):
    out = await tools.create_event(summary="x", start="2026-09-24T09:00",
                                   recurrence="every other tuesday")
    assert out.startswith("Error:")
    assert "not a recurrence I understand" in out


async def test_bad_time_is_explained(tools):
    out = await tools.create_event(summary="x", start="la semaine prochaine")
    assert out.startswith("Error:")
    assert "not a date or time I understand" in out


async def test_update_event(tools, caldav_server):
    uid = _seed(caldav_server, "Avant", "2026-09-24T10:00", "2026-09-24T11:00")
    out = await tools.update_event(uid=uid, summary="Après", location="Lyon")
    assert "Updated **Après**" in out
    assert "title, location" in out
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    assert any(b"Lyon" in ics for ics, _ in stored.values())


async def test_move_an_event_in_time(tools, caldav_server):
    uid = _seed(caldav_server, "Décalé", "2026-09-24T10:00", "2026-09-24T11:00")
    out = await tools.update_event(uid=uid, start="2026-09-25T15:00", end="2026-09-25T16:00")
    assert "Updated" in out
    listing = await tools.list_events(start="2026-09-25", end="2026-09-26")
    assert "2026-09-25 15:00 to 16:00" in listing


async def test_delete_event(tools, caldav_server):
    uid = _seed(caldav_server, "A supprimer", "2026-09-24T10:00", "2026-09-24T11:00")
    out = await tools.delete_event(uid=uid)
    assert "Deleted" in out
    assert caldav_server.calendars["/calendars/ada/personal/"].entries == {}


async def test_respond_to_an_invitation(tools, caldav_server):
    uid = _seed(
        caldav_server, "Invitation", "2026-09-24T10:00", "2026-09-24T11:00",
        organizer="boss@example.test",
        attendees=["ada@example.test", "bob@example.test"],
    )
    out = await tools.respond_to_event(uid=uid, response="accept")
    assert "as accept" in out
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    ics = next(iter(stored.values()))[0].decode()
    assert "PARTSTAT=ACCEPTED" in ics
    assert ics.count("PARTSTAT=ACCEPTED") == 1  # only mine


async def test_responding_when_not_invited_is_explained(tools, caldav_server):
    uid = _seed(caldav_server, "Pas pour moi", "2026-09-24T10:00", "2026-09-24T11:00",
                attendees=["bob@example.test"])
    out = await tools.respond_to_event(uid=uid, response="accept")
    assert out.startswith("Error:")
    assert "not an attendee" in out


async def test_unknown_response_is_explained(tools, caldav_server):
    uid = _seed(caldav_server, "Invitation", "2026-09-24T10:00", "2026-09-24T11:00",
                attendees=["ada@example.test"])
    out = await tools.respond_to_event(uid=uid, response="peut-être")
    assert "not an answer I understand" in out


async def test_find_free_time(tools, caldav_server):
    _seed(caldav_server, "Matin", "2026-09-24T09:00", "2026-09-24T11:00")
    _seed(caldav_server, "Après-midi", "2026-09-24T14:00", "2026-09-24T15:00")

    out = await tools.find_free_time(
        start="2026-09-24", end="2026-09-24", duration_minutes=60
    )
    assert "2026-09-24 11:00 to 14:00" in out
    assert "2026-09-24 15:00 to 18:00" in out
    assert "2026-09-24 09:00" not in out


async def test_find_free_time_respects_the_requested_length(tools, caldav_server):
    _seed(caldav_server, "Bloc", "2026-09-24T09:00", "2026-09-24T17:30")
    out = await tools.find_free_time(
        start="2026-09-24", end="2026-09-24", duration_minutes=60
    )
    assert "No free slot" in out


async def test_read_only_account_refuses_every_write(tools, calendar_account, caldav_server):
    calendar_account.read_only = True
    uid = _seed(caldav_server, "Intouchable", "2026-09-24T10:00", "2026-09-24T11:00")
    for out in (
        await tools.create_event(summary="x", start="2026-09-24T10:00"),
        await tools.update_event(uid=uid, summary="y"),
        await tools.delete_event(uid=uid),
        await tools.respond_to_event(uid=uid, response="accept"),
    ):
        assert "read-only" in out
    assert caldav_server.calendars["/calendars/ada/personal/"].entries


async def test_list_accounts_shows_calendars(tools, monkeypatch):
    from mail_mcp.accounts import AccountSet

    monkeypatch.setattr(server, "_ENV_ACCOUNTS", AccountSet())
    out = await tools.list_accounts()
    assert "ada@example.test" in out
    assert "calendar account" in out
    assert "No mailbox is attached" in out
