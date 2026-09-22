"""CalDavClient against a real (if tiny) CalDAV server."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from mail_mcp.caldav_client import CalDavClient, CalDavError
from mail_mcp.calendars import CalendarAccount
from mail_mcp.events import build_event, edit_event, parse_when


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
    )


@pytest.fixture
async def client(calendar_account, caldav_server):
    transport = httpx.ASGITransport(app=caldav_server.app)
    client = CalDavClient(calendar_account, transport=transport)
    yield client
    await client.close()


def _ics(summary="Réunion", start="2026-09-24T10:00", end="2026-09-24T11:00", **kwargs):
    return build_event(
        summary=summary,
        start=parse_when(start, "Europe/Paris"),
        end=parse_when(end, "Europe/Paris"),
        **kwargs,
    )


async def test_discovery_finds_the_calendar_home(client, caldav_server):
    home = await client.calendar_home()
    assert home.endswith("/calendars/ada/")
    methods = [method for method, _ in caldav_server.requests]
    assert methods.count("PROPFIND") == 2  # principal, then home


async def test_bad_password_is_explained(calendar_account, caldav_server):
    calendar_account.secret = "wrong"
    transport = httpx.ASGITransport(app=caldav_server.app)
    client = CalDavClient(calendar_account, transport=transport)
    with pytest.raises(CalDavError) as excinfo:
        await client.list_calendars()
    assert "login rejected" in str(excinfo.value).lower()
    assert "app-specific password" in str(excinfo.value)
    await client.close()


async def test_listing_keeps_event_calendars_only(client):
    calendars = await client.list_calendars()
    names = [calendar.name for calendar in calendars]
    assert "Personal" in names and "Work" in names
    assert "Reminders" not in names  # VTODO collection
    shared = next(c for c in calendars if c.name.startswith("Team"))
    assert shared.read_only is True


async def test_calendar_selection(client, calendar_account):
    assert (await client.resolve_calendar("Work")).name == "Work"
    assert (await client.resolve_calendar("/calendars/ada/work/")).name == "Work"
    calendar_account.default_calendar = "Work"
    assert (await client.resolve_calendar()).name == "Work"
    with pytest.raises(CalDavError, match="No calendar named"):
        await client.resolve_calendar("Nope")


async def test_events_in_a_time_range(client, caldav_server):
    _, inside = _ics(summary="Inside the window")
    _, outside = _ics(summary="Far away", start="2027-01-05T10:00", end="2027-01-05T11:00")
    caldav_server.seed("/calendars/ada/personal/", inside, "a")
    caldav_server.seed("/calendars/ada/personal/", outside, "b")

    events, calendar = await client.events_between(
        datetime(2026, 9, 24, tzinfo=UTC),
        datetime(2026, 9, 25, tzinfo=UTC),
        calendar="Personal",
    )
    assert calendar.name == "Personal"
    assert [event.summary for event in events] == ["Inside the window"]
    assert events[0].etag
    assert events[0].href.endswith("a.ics")


async def test_events_are_sorted_by_start(client, caldav_server):
    for name, start in (("later", "2026-09-24T16:00"), ("earlier", "2026-09-24T08:00")):
        _, ics = _ics(summary=name, start=start, end=start.replace("T0", "T1"))
        caldav_server.seed("/calendars/ada/personal/", ics, name)
    events, _ = await client.events_between(
        datetime(2026, 9, 24, tzinfo=UTC),
        datetime(2026, 9, 25, tzinfo=UTC),
        calendar="Personal",
    )
    assert [event.summary for event in events] == ["earlier", "later"]


async def test_find_by_uid(client, caldav_server):
    uid, ics = _ics(summary="Findable")
    caldav_server.seed("/calendars/ada/personal/", ics, "findable")
    found, _ = await client.find_by_uid(uid, calendar="Personal")
    assert found is not None
    assert found.summary == "Findable"
    missing, _ = await client.find_by_uid("nope@example.test", calendar="Personal")
    assert missing is None


async def test_create_event(client, caldav_server):
    uid, ics = _ics(summary="Nouveau point", attendees=["bob@example.test"])
    href, calendar = await client.create(ics, uid, calendar="Personal")
    assert calendar.name == "Personal"
    stored = caldav_server.calendars["/calendars/ada/personal/"].entries
    assert href in stored
    assert b"Nouveau point" in stored[href][0]


async def test_creating_the_same_event_twice_is_refused(client, caldav_server):
    uid, ics = _ics()
    await client.create(ics, uid, calendar="Personal")
    with pytest.raises(CalDavError):
        await client.create(ics, uid, calendar="Personal")


async def test_create_into_a_read_only_calendar_is_refused(client):
    uid, ics = _ics()
    with pytest.raises(CalDavError, match="read-only on the server"):
        await client.create(ics, uid, calendar="Team (read-only)")


async def test_update_uses_the_etag(client, caldav_server):
    uid, ics = _ics(summary="Avant")
    href, _ = await client.create(ics, uid, calendar="Personal")
    event = await client.fetch(href, "Personal")

    updated = edit_event(event.raw, summary="Après")
    await client.replace(href, updated, etag=event.etag)
    assert b"Apr" in caldav_server.calendars["/calendars/ada/personal/"].entries[href][0]

    # The stale ETag must now be refused rather than clobbering the change.
    with pytest.raises(CalDavError, match="changed underneath it"):
        await client.replace(href, updated, etag=event.etag)


async def test_delete(client, caldav_server):
    uid, ics = _ics()
    href, _ = await client.create(ics, uid, calendar="Personal")
    event = await client.fetch(href, "Personal")
    await client.delete(href, etag=event.etag)
    assert href not in caldav_server.calendars["/calendars/ada/personal/"].entries


async def test_read_only_account_refuses_every_write(calendar_account, caldav_server):
    calendar_account.read_only = True
    transport = httpx.ASGITransport(app=caldav_server.app)
    client = CalDavClient(calendar_account, transport=transport)
    uid, ics = _ics()
    for call in (
        client.create(ics, uid, calendar="Personal"),
        client.replace("/calendars/ada/personal/x.ics", ics),
        client.delete("/calendars/ada/personal/x.ics"),
    ):
        with pytest.raises(CalDavError, match="read-only"):
            await call
    await client.close()


async def test_check_reports_what_was_found(client):
    report = await client.check()
    assert report["ok"] is True
    assert report["home"].endswith("/calendars/ada/")
    assert {c["name"] for c in report["calendars"]} == {
        "Personal",
        "Work",
        "Team (read-only)",
    }


async def test_unreachable_server_is_explained(calendar_account):
    calendar_account.url = "https://caldav.invalid-host-for-tests.test"
    client = CalDavClient(calendar_account)  # no transport: the host cannot resolve
    with pytest.raises(CalDavError, match="Cannot reach the CalDAV server"):
        await client.list_calendars()
    await client.close()


# ---------------------------------------------------------------------------
# Read-modify-write: the validator must come from the resource, not the query
# ---------------------------------------------------------------------------


async def test_write_survives_a_server_whose_report_etags_are_stale(client, caldav_server):
    """iCloud hands out calendar-query ETags that do not match the resource."""
    caldav_server.stale_report_etags = True
    uid, ics = _ics(summary="Avant")
    href, _ = await client.create(ics, uid, calendar="Personal")

    # The UID lookup now reports a validator the server will not honour.
    found, _ = await client.find_by_uid(uid, calendar="Personal")
    stored_etag = caldav_server.calendars["/calendars/ada/personal/"].entries[href][1]
    assert found.etag != stored_etag

    # Writing against that validator is exactly what used to fail in the field.
    with pytest.raises(CalDavError, match="changed underneath it"):
        await client.replace(
            href, edit_event(found.raw, summary="Après"), etag=found.etag
        )

    # Writing through update_resource re-reads first, so it still works.
    await client.update_resource(
        href, lambda raw: edit_event(raw, summary="Après"), calendar="Personal"
    )
    body = caldav_server.calendars["/calendars/ada/personal/"].entries[href][0]
    assert b"Apr" in body


async def test_a_lost_race_is_replayed_once(client, caldav_server):
    uid, ics = _ics(summary="Avant")
    href, _ = await client.create(ics, uid, calendar="Personal")
    caldav_server.conflict_puts = 1  # the first conditional write loses

    await client.update_resource(
        href, lambda raw: edit_event(raw, summary="Après"), calendar="Personal"
    )
    body = caldav_server.calendars["/calendars/ada/personal/"].entries[href][0]
    assert b"Apr" in body
    assert caldav_server.conflict_puts == 0


async def test_a_persistent_conflict_is_reported_honestly(client, caldav_server):
    uid, ics = _ics(summary="Avant")
    href, _ = await client.create(ics, uid, calendar="Personal")
    caldav_server.conflict_puts = 99  # something else keeps writing

    with pytest.raises(CalDavError, match="something else is editing this event"):
        await client.update_resource(
            href, lambda raw: edit_event(raw, summary="Après"), calendar="Personal"
        )


async def test_weak_validators_are_not_used_for_if_match():
    from mail_mcp.caldav_client import usable_etag

    assert usable_etag('"abc"') == '"abc"'
    assert usable_etag('W/"abc"') == ""
    assert usable_etag("  ") == ""
    assert usable_etag(None) == ""


async def test_delete_re_reads_before_removing(client, caldav_server):
    caldav_server.stale_report_etags = True
    uid, ics = _ics(summary="A supprimer")
    href, _ = await client.create(ics, uid, calendar="Personal")
    await client.delete_resource(href, calendar="Personal")
    assert href not in caldav_server.calendars["/calendars/ada/personal/"].entries
