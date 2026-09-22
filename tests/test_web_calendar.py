"""Attaching a calendar account through the web UI."""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient

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
        async with FormClient(
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
    assert response.status_code == 303
    return re.search(
        r"/connections/([^/]+)/credentials", response.headers["location"]
    ).group(1)


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
    assert response.status_code == 303
    assert response.headers["location"] == "/connectors?notice=calendar_added"
    dashboard = await client.get(response.headers["location"])
    assert "Calendar added" in dashboard.text

    stored = server.STORE.get_connection(connection_id)
    assert [c.address for c in stored.calendars] == [caldav_server.username]
    assert stored.calendars[0].timezone == "Europe/Paris"
    assert stored.default_calendar_id == stored.calendars[0].account_id
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

    confirmation = await client.get(
        "/calendars/remove",
        params={"connection_id": connection_id, "calendar_id": calendar_id},
    )
    assert "Remove this calendar" in confirmation.text

    response = await client.post(
        "/calendars/delete",
        data={
            "connection_id": connection_id,
            "calendar_id": calendar_id,
            "confirm": "yes",
        },
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
            "confirm": "yes",
        },
    )
    assert server.STORE.get_connection(connection_id).calendars


# ---------------------------------------------------------------------------
# Passkeys: the account must not be a single point of failure
# ---------------------------------------------------------------------------


async def test_registering_a_known_email_again_is_refused(client, monkeypatch):
    """It used to mint a second, empty account and hide the user's own work."""
    store = server.STORE
    await store.create_user("taken@example.test")

    monkeypatch.setattr(web, "_uid", lambda request: None)
    response = await client.post(
        "/webauthn/register/begin", json={"email": "taken@example.test"}
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["error"]
    assert "Sign in with your passkey" in response.json()["error"]


async def test_a_signed_in_user_can_start_adding_another_passkey(client):
    page = await client.get("/register")
    assert page.status_code == 200
    assert "Add a passkey" in page.text

    response = await client.post(
        "/webauthn/register/begin", json={"email": "owner@example.test"}
    )
    assert response.status_code == 200
    assert "challenge" in response.json()


async def test_the_account_page_lists_passkeys_and_refuses_to_remove_the_last(client):
    store = server.STORE
    await store.add_credential(USER_ID, "cred-one", "pk", 0)

    page = await client.get("/account")
    assert page.status_code == 200
    assert "cred-one"[:12] in page.text
    assert "only passkey" in page.text

    removed = await client.post(
        "/account/passkeys/delete", data={"credential_id": "cred-one"}
    )
    assert removed.status_code == 303
    assert store.get_credential("cred-one") is not None  # kept: it is the last one

    await store.add_credential(USER_ID, "cred-two", "pk", 0)
    await client.post("/account/passkeys/delete", data={"credential_id": "cred-one"})
    assert store.get_credential("cred-one") is None
    assert store.get_credential("cred-two") is not None


async def test_passkeys_of_other_users_cannot_be_removed(client, monkeypatch):
    store = server.STORE
    await store.add_credential("usr_victim", "victim-one", "pk", 0)
    await store.add_credential("usr_victim", "victim-two", "pk", 0)

    await client.post("/account/passkeys/delete", data={"credential_id": "victim-one"})
    assert store.get_credential("victim-one") is not None
