"""The /logs view, fed by real MCP tool calls."""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient

from mail_mcp import server, web
from mail_mcp.accounts import MailAccount
from mail_mcp.activity import ActivityLog

OWNER = "usr_logs"


@pytest.fixture
def activity_log(tmp_path, monkeypatch) -> ActivityLog:
    """A log of this test's own, so entries cannot leak between tests."""
    log = ActivityLog(str(tmp_path / "activity.jsonl"), max_entries=500)
    monkeypatch.setattr(server, "ACTIVITY", log)
    return log


@pytest.fixture
async def connection(imap_server, activity_log):
    store = server.STORE
    connection = await store.create_connection(owner_id=OWNER, label="Logged connector")
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
        owner_id=OWNER,
    )
    yield store.get_connection(connection.connection_id)
    await store.delete_connection(connection.connection_id)


@pytest.fixture
async def client():
    async with LifespanManager(web.build_app()) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with FormClient(
            transport=transport, base_url="https://gateway.test", follow_redirects=False
        ) as http:
            yield http


async def _run_tools(client, connection, calls):
    """Drive real MCP calls so the middleware records them."""
    from tests.test_web_oauth import _call, _mcp_session, _token

    token = await _token(client, connection)
    session_id = await _mcp_session(client, token)
    for name, arguments in calls:
        await _call(client, token, session_id, name, arguments)


async def test_logs_require_a_session(client):
    assert (await client.get("/logs")).status_code == 303


async def test_tool_calls_show_up_in_the_view(
    client, connection, activity_log, monkeypatch
):
    await _run_tools(
        client,
        connection,
        [
            ("list_folders", {}),
            ("search_messages", {"subject": "Invoice"}),
            ("get_message", {"uid": 9999}),  # fails: no such message
        ],
    )

    monkeypatch.setattr(web, "_uid", lambda request: OWNER)
    response = await client.get("/logs")
    assert response.status_code == 200
    body = response.text

    assert "list_folders" in body
    assert "search_messages" in body
    assert "subject=Invoice" in body
    assert "Logged connector" in body
    assert "ada@example.test" in body
    assert "Succeeded" in body and "Failed" in body
    assert "<b>3</b><span>recorded calls</span>" in body


async def test_filters_narrow_the_view(client, connection, activity_log, monkeypatch):
    await _run_tools(
        client, connection, [("list_folders", {}), ("list_messages", {"limit": 2})]
    )
    monkeypatch.setattr(web, "_uid", lambda request: OWNER)

    only = await client.get("/logs", params={"tool": "list_folders"})
    assert "list_folders" in only.text
    assert "<code>list_messages</code>" not in only.text

    failures = await client.get("/logs", params={"status": "error"})
    assert "No call matches these filters" in failures.text
    assert "Clear filters" in failures.text

    other_connector = await client.get(
        "/logs", params={"connection_id": "con_somebody_else"}
    )
    assert "No call matches these filters" in other_connector.text


async def test_another_user_sees_nothing(client, connection, activity_log, monkeypatch):
    await _run_tools(client, connection, [("list_folders", {})])

    monkeypatch.setattr(web, "_uid", lambda request: "usr_intruder")
    response = await client.get("/logs")
    assert response.status_code == 200
    assert "Logged connector" not in response.text
    assert "ada@example.test" not in response.text
    assert "Nothing recorded yet" in response.text


async def test_message_bodies_are_not_in_the_log(
    client, connection, activity_log, monkeypatch
):
    # Sending fails (no SMTP server in the fixture), but the call is recorded.
    await _run_tools(
        client,
        connection,
        [
            (
                "send_message",
                {
                    "to": "bob@example.test",
                    "subject": "Invoice 42",
                    "body": "Confidential payment details",
                },
            )
        ],
    )
    monkeypatch.setattr(web, "_uid", lambda request: OWNER)
    body = (await client.get("/logs")).text

    assert "send_message" in body
    assert "to=bob@example.test" in body
    assert "Invoice 42" in body
    assert "Confidential payment details" not in body


async def test_read_only_refusals_are_recorded_as_denied(
    client, connection, activity_log, monkeypatch
):
    stored = server.STORE.get_connection(connection.connection_id)
    account = stored.accounts[0]
    account.read_only = True
    await server.STORE.add_account(
        connection.connection_id, account, owner_id=OWNER
    )

    await _run_tools(
        client,
        connection,
        [("send_message", {"to": "bob@example.test", "subject": "x", "body": "y"})],
    )
    monkeypatch.setattr(web, "_uid", lambda request: OWNER)
    body = (await client.get("/logs")).text
    assert "Refused" in body
    assert "read-only" in body


async def test_the_view_escapes_recorded_values(
    client, connection, activity_log, monkeypatch
):
    await _run_tools(
        client,
        connection,
        [("search_messages", {"subject": '<script>alert("xss")</script>'})],
    )
    monkeypatch.setattr(web, "_uid", lambda request: OWNER)
    body = (await client.get("/logs")).text
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body
