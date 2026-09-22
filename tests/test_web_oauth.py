"""End to end: OAuth 2.1 flow, then real MCP tool calls over the HTTP endpoint."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient

from mail_mcp import server, web
from mail_mcp.accounts import MailAccount

REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


def _sse_payload(response: httpx.Response) -> dict:
    """Read the single JSON-RPC message out of a streamable-http response."""
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    raise AssertionError(f"no JSON-RPC payload in: {response.text[:300]}")


@pytest.fixture
async def client():
    # The MCP endpoint needs the app lifespan (its session manager task group).
    # A fresh app per test: the SDK's session manager can only run once.
    async with LifespanManager(web.build_app()) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with FormClient(
            transport=transport,
            base_url="https://gateway.test",
            follow_redirects=False,
        ) as http:
            yield http


@pytest.fixture
async def connection(imap_server):
    """A connector owned by a user, serving the fake IMAP mailbox."""
    store = server.STORE
    user_id = await store.create_user("owner@example.test")
    connection = await store.create_connection(owner_id=user_id, label="Test connector")
    await store.add_account(
        connection.connection_id,
        MailAccount(
            address=imap_server.state.username,
            imap_host=imap_server.host,
            imap_port=imap_server.port,
            imap_security="none",
            smtp_host="127.0.0.1",
            smtp_port=1,
            smtp_security="none",
            secret=imap_server.state.password,
            verify_ssl=False,
            timeout=10,
        ),
        owner_id=user_id,
    )
    yield store.get_connection(connection.connection_id)
    await store.delete_connection(connection.connection_id)


async def _token(client: httpx.AsyncClient, connection) -> str:
    verifier, challenge = _pkce()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "scope": "mail",
        },
    )
    assert response.status_code in (302, 307), response.text
    location = response.headers["location"]
    assert location.startswith(REDIRECT_URI)
    assert "state=xyz" in location
    code = re.search(r"code=([^&]+)", location).group(1)

    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": connection.client_id,
            "client_secret": connection.client_secret,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


async def _mcp_session(client: httpx.AsyncClient, token: str) -> str:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
    }
    response = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1.0"},
            },
        },
    )
    assert response.status_code == 200, response.text
    session_id = response.headers["mcp-session-id"]
    await client.post(
        "/mcp",
        headers={**headers, "mcp-session-id": session_id},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return session_id


async def _call(client, token, session_id, name, arguments=None):
    response = await client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": session_id,
        },
        json={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
    assert response.status_code == 200, response.text
    payload = _sse_payload(response)
    assert "error" not in payload, payload
    return "\n".join(
        block.get("text", "") for block in payload["result"]["content"]
    )


async def test_mcp_requires_a_token(client):
    response = await client.post(
        "/mcp",
        headers={"Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 401
    assert "Bearer" in response.headers.get("www-authenticate", "")


async def test_oauth_metadata_follows_the_request_host(client):
    response = await client.get("/.well-known/oauth-authorization-server")
    metadata = response.json()
    assert metadata["issuer"] == "https://gateway.test"
    assert metadata["authorization_endpoint"] == "https://gateway.test/authorize"
    assert metadata["code_challenge_methods_supported"] == ["S256"]

    response = await client.get("/.well-known/oauth-protected-resource")
    assert response.json()["resource"] == "https://gateway.test/mcp"


async def test_unknown_client_is_rejected(client):
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "mail_does_not_exist",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": "abc",
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code >= 400


async def test_wrong_client_secret_is_rejected(client, connection):
    verifier, challenge = _pkce()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mail",
        },
    )
    code = re.search(r"code=([^&]+)", response.headers["location"]).group(1)
    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": connection.client_id,
            "client_secret": "wrong-secret",
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert response.status_code >= 400


async def test_full_flow_lists_and_reads_mail(client, connection, imap_server):
    token = await _token(client, connection)
    session_id = await _mcp_session(client, token)

    accounts = await _call(client, token, session_id, "list_accounts")
    assert imap_server.state.username in accounts

    folders = await _call(client, token, session_id, "list_folders")
    assert "INBOX" in folders
    assert "Archives/Été 2024" in folders

    listing = await _call(
        client, token, session_id, "list_messages", {"limit": 5}
    )
    assert "Invoice #42" in listing
    assert "Déjeuner jeudi ?" in listing
    assert "UNREAD" in listing

    found = await _call(
        client, token, session_id, "search_messages", {"subject": "Invoice"}
    )
    assert "Invoice #42" in found
    assert "Déjeuner" not in found

    message = await _call(
        client, token, session_id, "get_message", {"uid": 1, "folder": "INBOX"}
    )
    assert "Please find invoice 42" in message

    marked = await _call(
        client,
        token,
        session_id,
        "mark_messages",
        {"uids": [2], "action": "read"},
    )
    assert "Marked 1 message" in marked
    assert "\\Seen" in imap_server.state.folders["INBOX"].messages[2][1]

    moved = await _call(
        client,
        token,
        session_id,
        "move_messages",
        {"uids": [3], "destination": "trash"},
    )
    assert "Moved 1 message" in moved
    assert len(imap_server.state.folders["Trash"].messages) == 1


async def test_refresh_token_rotates(client, connection):
    verifier, challenge = _pkce()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mail",
        },
    )
    code = re.search(r"code=([^&]+)", response.headers["location"]).group(1)
    first = (
        await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": connection.client_id,
                "client_secret": connection.client_secret,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
    ).json()

    second = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
            "client_id": connection.client_id,
            "client_secret": connection.client_secret,
        },
    )
    assert second.status_code == 200, second.text
    tokens = second.json()
    assert tokens["access_token"] != first["access_token"]
    # The old refresh token must not work twice.
    replay = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
            "client_id": connection.client_id,
            "client_secret": connection.client_secret,
        },
    )
    assert replay.status_code >= 400


async def test_web_pages_require_a_session(client):
    assert (await client.get("/")).status_code == 303
    assert (await client.post("/discover", json={"address": "a@b.c"})).status_code == 401
    assert (await client.post("/test", json={})).status_code == 401


async def test_an_expired_access_token_does_not_kill_the_connector(client, connection):
    """The failure mode: one call an hour later, and the connector is dead."""
    import time as _time

    from mail_mcp import server

    verifier, challenge = _pkce()
    response = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": connection.client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mail",
        },
    )
    code = re.search(r"code=([^&]+)", response.headers["location"]).group(1)
    tokens = (
        await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": connection.client_id,
                "client_secret": connection.client_secret,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
    ).json()

    # Age the access token past its expiry, the way an hour of idling would.
    store = server.STORE
    token_hash = store._hash(tokens["access_token"])
    store._data["tokens"][token_hash]["expires_at"] = _time.time() - 1

    # A call with the stale token is rejected, as it should be.
    stale = await client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert stale.status_code == 401

    # ...and the refresh token still works, so the agent recovers by itself.
    refreshed = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": connection.client_id,
            "client_secret": connection.client_secret,
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["access_token"] != tokens["access_token"]
