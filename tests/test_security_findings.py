"""Regressions for the OAuth, store and web side of the review."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient, session_csrf
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from mail_mcp import server, web
from mail_mcp.accounts import MailAccount
from mail_mcp.oauth import MailOAuthProvider
from mail_mcp.store import (
    MAX_CODES_PER_CLIENT,
    ConnectionStore,
    MailboxRegistry,
    OAuthCode,
)

USER_ID = "usr_security"


@pytest.fixture
def store(store_path) -> ConnectionStore:
    return ConnectionStore(store_path)


def _xoauth_account() -> MailAccount:
    return MailAccount(
        address="ada@gmail.test",
        imap_host="imap.gmail.test",
        smtp_host="smtp.gmail.test",
        auth="xoauth2",
        oauth_provider="google",
        oauth_client_id="client-id",
        oauth_client_secret="GOOGLE-CLIENT-SECRET",
        secret="refresh-token",
    )


# --- secrets at rest -----------------------------------------------------------


async def test_the_oauth_client_secret_is_encrypted_at_rest(store, store_path):
    connection = await store.create_connection(owner_id="u", label="x")
    await store.add_account(connection.connection_id, _xoauth_account())

    assert "GOOGLE-CLIENT-SECRET" not in Path(store_path).read_text()
    reloaded = ConnectionStore(store_path).get_connection(connection.connection_id)
    assert reloaded.accounts[0].oauth_client_secret == "GOOGLE-CLIENT-SECRET"


async def test_a_plaintext_secret_from_an_older_store_is_sealed_on_start(store, store_path):
    connection = await store.create_connection(owner_id="u", label="x")
    await store.add_account(connection.connection_id, _xoauth_account())
    data = json.loads(Path(store_path).read_text())
    (record,) = data["connections"][connection.connection_id]["accounts"].values()
    record.pop("oauth_client_secret_enc")
    record["oauth_client_secret"] = "OLD-PLAINTEXT"
    Path(store_path).write_text(json.dumps(data))

    migrated = ConnectionStore(store_path)

    assert "OLD-PLAINTEXT" not in Path(store_path).read_text()
    connection = migrated.get_connection(connection.connection_id)
    assert connection.accounts[0].oauth_client_secret == "OLD-PLAINTEXT"


# --- authorization codes ------------------------------------------------------


async def test_pending_codes_are_capped_per_client(store):
    for n in range(MAX_CODES_PER_CLIENT * 3):
        await store.save_code(
            OAuthCode(
                code=f"code-{n}", client_id="mail_x", redirect_uri="https://r",
                code_challenge="c", expires_at=time.time() + 300 + n,
            )
        )
    assert len(store._data["codes"]) == MAX_CODES_PER_CLIENT
    assert store.get_code(f"code-{MAX_CODES_PER_CLIENT * 3 - 1}") is not None
    assert store.get_code("code-0") is None


async def test_expired_codes_are_dropped_when_a_new_one_arrives(store):
    await store.save_code(
        OAuthCode(code="old", client_id="a", redirect_uri="https://r",
                  code_challenge="c", expires_at=time.time() - 1)
    )
    await store.save_code(
        OAuthCode(code="new", client_id="b", redirect_uri="https://r",
                  code_challenge="c", expires_at=time.time() + 300)
    )
    assert store.get_code("old") is None and store.get_code("new") is not None


async def test_an_omitted_redirect_uri_is_remembered_as_omitted(store):
    connection = await store.create_connection(owner_id="u", label="x")
    provider = MailOAuthProvider(store)
    client = await provider.get_client(connection.client_id)
    redirect = await provider.authorize(
        client,
        AuthorizationParams(
            state="s", scopes=["mail"], code_challenge="x" * 43,
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            redirect_uri_provided_explicitly=False,
        ),
    )
    code = redirect.split("code=")[1].split("&")[0]
    loaded = await provider.load_authorization_code(client, code)
    assert loaded.redirect_uri_provided_explicitly is False


# --- refresh token reuse ------------------------------------------------------


async def _authorized(store) -> tuple[MailOAuthProvider, OAuthClientInformationFull, str, list]:
    connection = await store.create_connection(owner_id="u", label="x")
    reused: list[str] = []
    provider = MailOAuthProvider(store, on_reuse=reused.append)
    client = await provider.get_client(connection.client_id)
    redirect = await provider.authorize(
        client,
        AuthorizationParams(
            state="s", scopes=["mail"], code_challenge="x" * 43,
            redirect_uri="https://claude.ai/api/mcp/auth_callback",
            redirect_uri_provided_explicitly=True,
        ),
    )
    code = await provider.load_authorization_code(
        client, redirect.split("code=")[1].split("&")[0]
    )
    tokens = await provider.exchange_authorization_code(client, code)
    return provider, client, tokens.refresh_token, reused


async def test_a_replayed_refresh_token_revokes_the_whole_line(store):
    provider, client, first_refresh, reused = await _authorized(store)

    loaded = await provider.load_refresh_token(client, first_refresh)
    thief = await provider.exchange_refresh_token(client, loaded, [])
    assert await provider.load_access_token(thief.access_token) is not None

    # The rightful client (or the thief) presents the old one again.
    assert await provider.load_refresh_token(client, first_refresh) is None

    assert await provider.load_access_token(thief.access_token) is None
    assert await provider.load_refresh_token(client, thief.refresh_token) is None
    assert reused == [client.client_id]


async def test_a_normal_rotation_keeps_working(store):
    provider, client, refresh, reused = await _authorized(store)
    for _ in range(3):
        loaded = await provider.load_refresh_token(client, refresh)
        assert loaded is not None
        refresh = (await provider.exchange_refresh_token(client, loaded, [])).refresh_token
    assert reused == []


# --- live clients of a deleted connector ---------------------------------------


class _FakeClient:
    def __init__(self, last_used: float = 0.0):
        self.closed = False
        self._last_used = last_used

    async def close(self):
        self.closed = True


async def test_forgetting_a_connection_closes_its_clients(store):
    connection = await store.create_connection(owner_id="u", label="x")
    registry = MailboxRegistry(store)
    registry.account_set_for_client_id(connection.client_id)
    fake = _FakeClient()
    registry._entries[connection.client_id].clients["box"] = fake

    await store.delete_connection(connection.connection_id)
    registry.forget(connection.client_id)
    for task in list(registry._closing):
        await task

    assert fake.closed
    assert connection.client_id not in registry._entries


async def test_idle_clients_are_reaped(store):
    connection = await store.create_connection(owner_id="u", label="x")
    registry = MailboxRegistry(store)
    registry.account_set_for_client_id(connection.client_id)
    idle, busy = _FakeClient(time.time() - 3600), _FakeClient(time.time())
    registry._entries[connection.client_id].clients.update(idle=idle, busy=busy)

    assert await registry.reap_idle(idle_seconds=600) == 1
    assert idle.closed and not busy.closed


# --- the browser side -----------------------------------------------------------


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setattr(web, "_uid", lambda request: USER_ID)
    async with LifespanManager(web.build_app()) as manager, FormClient(
        transport=httpx.ASGITransport(app=manager.app),
        base_url="https://gateway.test",
        follow_redirects=False,
    ) as http:
        yield http


async def test_a_form_without_the_token_is_refused(client):
    await client.get("/assets/app.css")
    response = await client.post(
        "/connections/new", data={"label": "Forged", "csrf": "wrong"}
    )
    assert response.status_code == 403
    assert "Nothing was changed" in response.text


async def test_a_cross_site_post_is_refused_even_with_the_token(client):
    await client.get("/assets/app.css")
    response = await client.post(
        "/connections/new",
        data={"label": "Forged", "csrf": session_csrf(client)},
        headers={"Sec-Fetch-Site": "same-site"},
    )
    assert response.status_code == 403


async def test_a_post_from_another_origin_is_refused(client):
    response = await client.post(
        "/connections/new", data={"label": "Forged"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


async def test_a_json_endpoint_cannot_be_reached_with_text_plain(client):
    response = await client.post(
        "/test", content=b'{"address": "a@b.c"}', headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 403


async def test_every_post_form_carries_the_token(client):
    connection = await client.post("/connections/new", data={"label": "Forms"})
    page = await client.get(connection.headers["location"])
    token = session_csrf(client)
    assert token
    for form in page.text.split("<form")[1:]:
        if 'method="post"' in form.split(">")[0]:
            assert f'name="csrf" value="{token}"' in form


async def test_signing_out_needs_a_post(client):
    page = await client.get("/logout")
    assert page.status_code == 200
    assert 'action="/logout"' in page.text and 'method="post"' in page.text


async def test_the_passkey_origin_is_not_taken_from_the_request_once_pinned(
    client, monkeypatch
):
    monkeypatch.delenv("MAIL_PUBLIC_URL", raising=False)
    monkeypatch.setattr(server.STORE, "pinned_origin", lambda: "https://gateway.test")
    response = await client.post(
        "/webauthn/register/begin",
        json={"email": "rp@example.test"},
        headers={"X-Forwarded-Host": "evil.attacker.test", "Host": "evil.attacker.test"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["rp"]["id"] == "gateway.test"


async def test_the_public_url_decides_the_passkey_origin(client, monkeypatch):
    monkeypatch.setenv("MAIL_PUBLIC_URL", "https://mail.example.org")
    response = await client.post(
        "/webauthn/register/begin",
        json={"email": "rp2@example.test"},
        headers={"X-Forwarded-Host": "evil.attacker.test"},
    )
    assert response.json()["rp"]["id"] == "mail.example.org"


# --- single-mailbox HTTP ---------------------------------------------------------


def test_single_mailbox_http_refuses_to_listen_beyond_loopback(monkeypatch):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.delenv("MAIL_INSECURE_HTTP", raising=False)
    assert "without authentication" in server._unprotected_http("0.0.0.0")
    assert server._unprotected_http("127.0.0.1") == ""
    monkeypatch.setenv("MAIL_INSECURE_HTTP", "1")
    assert server._unprotected_http("0.0.0.0") == ""


def test_single_mailbox_http_checks_the_host_header(monkeypatch):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.delenv("MAIL_ALLOWED_HOSTS", raising=False)
    settings = server.transport_security()
    assert settings.enable_dns_rebinding_protection
    assert "localhost:*" in settings.allowed_hosts


def test_the_compose_single_profile_stays_on_loopback():
    compose = (Path(__file__).parent.parent / "docker-compose.yml").read_text()
    single = compose.split("mail-mcp-single:")[1].split("mail-mcp-stdio:")[0]
    assert '"127.0.0.1:${MCP_PORT:-8000}:8000"' in single
    assert "NO authentication" in compose


async def test_connection_tests_are_rate_limited(client):
    statuses = [
        (await client.post("/discover", json={"address": "a@icloud.com"})).status_code
        for _ in range(web.PROBES_PER_MINUTE + 1)
    ]
    assert statuses[:-1] == [200] * web.PROBES_PER_MINUTE
    assert statuses[-1] == 429
