"""Attaching a calendar account through the web UI."""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager

from mail_mcp import server, web
from mail_mcp.caldav_client import CalDavClient

USER_ID = "usr_calendar"


@pytest.fixture
def caldav_server(monkeypatch):
    from fake_caldav import FakeCalDAVState, build_app

    state = FakeCalDAVState()
    app = build_app(state)

    def factory(account):
        return CalDavClient(account, transport=httpx.ASGITransport(app=app))

    monkeypatch.setattr(web, "CalDavClient", factory)
    return state


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setattr(web, "_uid", lambda request: USER_ID)
    async with LifespanManager(web.build_app()) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://gateway.test", follow_redirects=False
        ) as http:
            yield http


def _form(caldav_server, **overrides) -> dict[str, str]:
    form = {
        "address": caldav_server.username,
        "secret": caldav_server.password,
        "url": "https://caldav.test",
        "timezone": "Europe/Paris",
        "default_calendar": "Personal",
    }
    form.update(overrides)
    return form


async def _new_connector(client, label="With calendars") -> str:
    response = await client.post("/connections/new", data={"label": label})
    client_id = re.search(r"(mail_[0-9a-f]+)", response.text).group(1)
    return server.STORE.get_connection_by_client_id(client_id).connection_id


async def test_the_form_is_reachable(client):
    connection_id = await _new_connector(client)
    response = await client.get(f"/connections/{connection_id}/calendar")
    assert response.status_code == 200
    assert "Add a calendar" in response.text
    assert "app-specific password" in response.text


async def test_attach_a_calendar(client, caldav_server):
    connection_id = await _new_connector(client)
    response = await client.post(
        f"/connections/{connection_id}/calendars", data=_form(caldav_server)
    )
    assert response.status_code == 200
    assert "calendars are now available" in response.text

    stored = server.STORE.get_connection(connection_id)
    assert [c.address for c in stored.calendars] == [caldav_server.username]
    assert stored.calendars[0].timezone == "Europe/Paris"
    assert stored.default_calendar_id == stored.calendars[0].account_id
    # And it shows on the dashboard.
    dashboard = await client.get("/")
    assert caldav_server.username in dashboard.text
    assert "Europe/Paris" in dashboard.text


async def test_a_calendar_that_does_not_connect_is_not_saved(client, caldav_server):
    connection_id = await _new_connector(client)
    response = await client.post(
        f"/connections/{connection_id}/calendars",
        data=_form(caldav_server, secret="wrong"),
    )
    assert response.status_code == 400
    assert "login rejected" in response.text.lower()
    assert "was not saved" in response.text
    assert server.STORE.get_connection(connection_id).calendars == []


async def test_incomplete_calendar_is_refused_before_connecting(client, caldav_server):
    connection_id = await _new_connector(client)
    response = await client.post(
        f"/connections/{connection_id}/calendars",
        data=_form(caldav_server, address="ada@unknown-provider.test", url=""),
    )
    assert response.status_code == 400
    assert "No CalDAV server known" in response.text


async def test_the_test_endpoint_lists_the_calendars(client, caldav_server):
    response = await client.post("/test-calendar", json=_form(caldav_server))
    payload = response.json()
    assert payload["ok"] is True
    assert "Personal" in payload["message"]
    assert {c["name"] for c in payload["calendars"]} >= {"Personal", "Work"}

    bad = await client.post("/test-calendar", json=_form(caldav_server, secret="nope"))
    assert bad.json()["ok"] is False


async def test_remove_a_calendar(client, caldav_server):
    connection_id = await _new_connector(client)
    await client.post(f"/connections/{connection_id}/calendars", data=_form(caldav_server))
    calendar_id = server.STORE.get_connection(connection_id).calendars[0].account_id

    response = await client.post(
        "/calendars/delete",
        data={"connection_id": connection_id, "calendar_id": calendar_id},
    )
    assert response.status_code == 303
    assert server.STORE.get_connection(connection_id).calendars == []


async def test_another_user_cannot_touch_it(client, caldav_server, monkeypatch):
    connection_id = await _new_connector(client)
    await client.post(f"/connections/{connection_id}/calendars", data=_form(caldav_server))

    monkeypatch.setattr(web, "_uid", lambda request: "usr_intruder")
    response = await client.get(f"/connections/{connection_id}/calendar")
    assert "no longer exists" in response.text
    await client.post(
        "/calendars/delete",
        data={
            "connection_id": connection_id,
            "calendar_id": server.STORE.get_connection(connection_id)
            .calendars[0]
            .account_id,
        },
    )
    assert server.STORE.get_connection(connection_id).calendars
