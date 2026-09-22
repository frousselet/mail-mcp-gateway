"""The onboarding path: create a connector, attach a mailbox, see it listed."""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager

from mail_mcp import server, smtp_client, web

USER_ID = "usr_onboarding"


@pytest.fixture
async def client(monkeypatch):
    # Stand in for a signed-in session; passkey verification has its own path.
    monkeypatch.setattr(web, "_uid", lambda request: USER_ID)
    async with LifespanManager(web.build_app()) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://gateway.test",
            follow_redirects=False,
        ) as http:
            yield http


@pytest.fixture
def smtp_ok(monkeypatch):
    """The fake IMAP server has no SMTP counterpart; accept SMTP checks."""

    async def fake_check(account):
        return {"ok": True, "host": f"{account.smtp_host}:{account.smtp_port}"}

    monkeypatch.setattr(smtp_client, "check", fake_check)


def _mailbox_form(imap_server, password: str | None = None) -> dict[str, str]:
    return {
        "address": imap_server.state.username,
        "secret": password or imap_server.state.password,
        "imap_host": imap_server.host,
        "imap_port": str(imap_server.port),
        "imap_security": "none",
        "smtp_host": "127.0.0.1",
        "smtp_port": "587",
        "smtp_security": "starttls",
        "auth": "password",
    }


async def _new_connector(client: httpx.AsyncClient, label: str = "Work") -> str:
    """Create a connector and return its id, read back from the page it shows."""
    response = await client.post("/connections/new", data={"label": label})
    assert response.status_code == 200, response.text
    assert "Connector ready" in response.text
    client_id = re.search(r"(mail_[0-9a-f]+)", response.text).group(1)
    connection = server.STORE.get_connection_by_client_id(client_id)
    assert connection is not None
    assert connection.label == label
    assert connection.client_secret in response.text
    return connection.connection_id


async def test_connector_creation_requires_a_name(client):
    response = await client.post("/connections/new", data={"label": "  "})
    assert response.status_code == 400
    assert "Give the connector a name" in response.text


async def test_attach_a_mailbox_and_see_it_listed(client, imap_server, smtp_ok):
    connection_id = await _new_connector(client)

    form = await client.get(f"/connections/{connection_id}")
    assert form.status_code == 200
    assert "Add a mailbox" in form.text

    response = await client.post(
        f"/connections/{connection_id}/mailboxes", data=_mailbox_form(imap_server)
    )
    assert response.status_code == 200, response.text
    assert "is now available to this connector" in response.text
    assert imap_server.state.username in response.text

    stored = server.STORE.get_connection(connection_id)
    assert [a.address for a in stored.accounts] == [imap_server.state.username]
    assert stored.default_account_id == stored.accounts[0].account_id


async def test_a_mailbox_that_does_not_connect_is_not_saved(
    client, imap_server, smtp_ok
):
    connection_id = await _new_connector(client)
    response = await client.post(
        f"/connections/{connection_id}/mailboxes",
        data=_mailbox_form(imap_server, password="wrong"),
    )
    assert response.status_code == 400
    assert "login rejected" in response.text.lower()
    assert "was not saved" in response.text
    assert server.STORE.get_connection(connection_id).accounts == []


async def test_incomplete_mailbox_is_refused_before_any_connection(client):
    connection_id = await _new_connector(client)
    response = await client.post(
        f"/connections/{connection_id}/mailboxes",
        data={"address": "not-an-email", "secret": "x"},
    )
    assert response.status_code == 400
    assert "not a valid email address" in response.text


async def test_several_mailboxes_on_one_connector(client, imap_server, smtp_ok):
    connection_id = await _new_connector(client, "All mail")
    first = _mailbox_form(imap_server)
    await client.post(f"/connections/{connection_id}/mailboxes", data=first)

    # The fake server accepts one account; a second entry differs by label only,
    # which is enough to prove two mailboxes coexist on one connector.
    second = dict(first, from_name="Second identity")
    await client.post(f"/connections/{connection_id}/mailboxes", data=second)

    stored = server.STORE.get_connection(connection_id)
    assert len(stored.accounts) == 2
    assert stored.accounts[1].from_name == "Second identity"


async def test_mailbox_removal(client, imap_server, smtp_ok):
    connection_id = await _new_connector(client)
    await client.post(
        f"/connections/{connection_id}/mailboxes", data=_mailbox_form(imap_server)
    )
    account_id = server.STORE.get_connection(connection_id).accounts[0].account_id

    response = await client.post(
        "/mailboxes/delete",
        data={"connection_id": connection_id, "account_id": account_id},
    )
    assert response.status_code == 303
    assert server.STORE.get_connection(connection_id).accounts == []


async def test_rotating_the_secret_shows_a_new_one(client):
    connection_id = await _new_connector(client)
    before = server.STORE.get_connection(connection_id).client_secret
    response = await client.post("/connections/rotate", data={"connection_id": connection_id})
    after = server.STORE.get_connection(connection_id).client_secret
    assert response.status_code == 200
    assert after != before
    assert after in response.text


async def test_test_endpoint_reports_failures_without_saving(client, imap_server, smtp_ok):
    response = await client.post("/test", json=_mailbox_form(imap_server, password="nope"))
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert "login rejected" in payload["message"].lower()

    response = await client.post("/test", json=_mailbox_form(imap_server))
    assert response.json()["ok"] is True


async def test_discover_requires_a_full_address(client):
    response = await client.post("/discover", json={"address": "nope"})
    assert response.status_code == 400


async def test_discover_uses_the_offline_presets(client):
    response = await client.post("/discover", json={"address": "someone@gmail.com"})
    payload = response.json()
    assert payload["found"] is True
    assert payload["settings"]["imap_host"] == "imap.gmail.com"
    assert payload["settings"]["source"] == "preset"


async def test_connectors_of_other_users_are_invisible(client, monkeypatch):
    connection_id = await _new_connector(client, "Mine")
    monkeypatch.setattr(web, "_uid", lambda request: "usr_someone_else")

    dashboard = await client.get("/")
    assert "Mine" not in dashboard.text

    response = await client.get(f"/connections/{connection_id}")
    assert "no longer exists" in response.text
    response = await client.post(
        "/connections/delete", data={"connection_id": connection_id}
    )
    assert response.status_code == 303
    assert server.STORE.get_connection(connection_id) is not None
