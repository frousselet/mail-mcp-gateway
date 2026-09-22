"""The onboarding path: create a connector, attach a mailbox, see it listed."""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient

from mail_mcp import server, smtp_client, web

USER_ID = "usr_onboarding"


@pytest.fixture
async def client(monkeypatch):
    # Stand in for a signed-in session; passkey verification has its own path.
    monkeypatch.setattr(web, "_uid", lambda request: USER_ID)
    async with LifespanManager(web.build_app()) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with FormClient(
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
    """Create a connector and return its id, read back from the redirect."""
    response = await client.post("/connections/new", data={"label": label})
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    connection_id = re.search(r"/connections/([^/]+)/credentials", location).group(1)
    connection = server.STORE.get_connection(connection_id)
    assert connection is not None
    assert connection.label == label

    # The credentials page is a plain GET, so a refresh cannot re-create anything.
    page = await client.get(location)
    assert page.status_code == 200
    assert connection.client_secret in page.text
    assert connection.client_id in page.text
    return connection_id


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
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/?notice=mailbox_added"
    dashboard = await client.get(response.headers["location"])
    assert "Mailbox added" in dashboard.text
    assert imap_server.state.username in dashboard.text

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

    # Removal is confirmed on a real page, not by a confirm() dialog.
    confirmation = await client.get(
        "/mailboxes/remove",
        params={"connection_id": connection_id, "account_id": account_id},
    )
    assert confirmation.status_code == 200
    assert "Remove this mailbox" in confirmation.text
    assert server.STORE.get_connection(connection_id).accounts  # nothing yet

    unconfirmed = await client.post(
        "/mailboxes/delete",
        data={"connection_id": connection_id, "account_id": account_id},
    )
    assert unconfirmed.status_code == 400
    assert server.STORE.get_connection(connection_id).accounts  # still nothing

    response = await client.post(
        "/mailboxes/delete",
        data={
            "connection_id": connection_id,
            "account_id": account_id,
            "confirm": "yes",
        },
    )
    assert response.status_code == 303
    assert server.STORE.get_connection(connection_id).accounts == []


async def test_rotating_the_secret_is_confirmed_then_shown(client):
    connection_id = await _new_connector(client)
    before = server.STORE.get_connection(connection_id).client_secret

    confirmation = await client.get(
        "/connections/rotate", params={"connection_id": connection_id}
    )
    assert "Issue a new secret" in confirmation.text
    assert server.STORE.get_connection(connection_id).client_secret == before

    response = await client.post(
        "/connections/rotate", data={"connection_id": connection_id, "confirm": "yes"}
    )
    assert response.status_code == 303
    after = server.STORE.get_connection(connection_id).client_secret
    assert after != before
    page = await client.get(response.headers["location"])
    assert after in page.text


async def test_the_client_secret_can_be_looked_up_again(client):
    """It is stored encrypted, not hashed, so pretending otherwise only hurt."""
    connection_id = await _new_connector(client)
    secret = server.STORE.get_connection(connection_id).client_secret
    page = await client.get(f"/connections/{connection_id}/credentials")
    assert page.status_code == 200
    assert secret in page.text


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
        "/connections/delete",
        data={"connection_id": connection_id, "confirm": "yes"},
    )
    assert response.status_code == 303
    assert server.STORE.get_connection(connection_id) is not None

    # And its credentials are not readable by them either.
    credentials = await client.get(f"/connections/{connection_id}/credentials")
    assert "no longer exists" in credentials.text


# ---------------------------------------------------------------------------
# The browser-facing hardening
# ---------------------------------------------------------------------------


async def test_html_responses_carry_a_strict_csp(client):
    response = await client.get("/")
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_the_mcp_endpoint_is_not_given_html_headers(client):
    response = await client.post(
        "/mcp",
        headers={"Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 401
    assert "content-security-policy" not in response.headers


async def test_the_assets_are_served_with_a_cacheable_fingerprint(client):
    from mail_mcp import assets

    css = await client.get("/assets/app.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert "immutable" in css.headers["cache-control"]
    assert css.headers["etag"] == f'"{assets.CSS_VERSION}"'

    again = await client.get(
        "/assets/app.css", headers={"If-None-Match": f'"{assets.CSS_VERSION}"'}
    )
    assert again.status_code == 304

    js = await client.get("/assets/app.js")
    assert js.status_code == 200
    assert js.headers["content-type"].startswith("text/javascript")


async def test_the_session_cookie_is_secure_by_default(monkeypatch):
    from starlette.middleware.sessions import SessionMiddleware

    monkeypatch.delenv("MAIL_INSECURE_COOKIE", raising=False)
    app = web.build_app()
    session = next(
        m for m in app.user_middleware if m.cls is SessionMiddleware
    )
    assert session.kwargs["https_only"] is True

    monkeypatch.setenv("MAIL_INSECURE_COOKIE", "1")
    relaxed = next(
        m for m in web.build_app().user_middleware if m.cls is SessionMiddleware
    )
    assert relaxed.kwargs["https_only"] is False


async def test_the_session_key_survives_a_restart(monkeypatch):
    monkeypatch.delenv("MAIL_SECRET_KEY", raising=False)
    assert web._session_secret() == web._session_secret()
    assert web._session_secret() == server.STORE.session_secret()


async def test_signing_out_retires_the_cookie_that_was_already_issued(monkeypatch):
    """Clearing the session only tells this browser to forget; a copy would live on.

    No `client` fixture here: that one stubs out _uid, which is the function
    under test.
    """
    store = server.STORE
    await store.create_user("epoch@example.test")
    uid = store.find_user_by_email("epoch@example.test")

    # A cookie minted before the sign-out.
    stale_session = {"uid": uid, "email": "epoch@example.test", "epoch": 0}
    request = type("R", (), {"session": stale_session})()
    monkeypatch.setattr(web, "_store", lambda: store)
    assert web._uid(request) == uid

    await store.bump_session_epoch(uid)
    assert web._uid(request) is None, "the pre-sign-out cookie still worked"


async def test_a_probe_failure_never_echoes_the_remote_response(client, imap_server):
    response = await client.post(
        "/test", json=_mailbox_form(imap_server, password="wrong")
    )
    payload = response.json()
    assert payload["ok"] is False
    assert "login rejected" in payload["message"].lower()
    # The server's own words stay in the log, not in the browser.
    assert "app password" not in payload["message"]


async def test_pages_with_secrets_are_not_cached(client):
    connection_id = await _new_connector(client)
    page = await client.get(f"/connections/{connection_id}/credentials")
    assert page.headers["cache-control"] == "no-store"
    assert (await client.get("/logs")).headers["cache-control"] == "no-store"
    # The fingerprinted assets stay cacheable; that is the point of the hash.
    assert "immutable" in (await client.get("/assets/app.css")).headers["cache-control"]
