"""ImapClient against a real (if tiny) IMAP server."""

from __future__ import annotations

import pytest

from mail_mcp.imap_client import ImapClient, ImapError
from mail_mcp.message import parse_headers, parse_message
from mail_mcp.search import build_criteria


@pytest.fixture
async def client(account):
    client = ImapClient(account)
    yield client
    await client.close()


async def test_login_failure_is_explained(account):
    account.secret = "wrong"
    client = ImapClient(account)
    with pytest.raises(ImapError) as excinfo:
        await client.check()
    assert "login rejected" in str(excinfo.value).lower()
    assert "app password" in str(excinfo.value)
    await client.close()


async def test_unreachable_server_is_explained(account):
    account.imap_port = 1
    client = ImapClient(account)
    with pytest.raises(ImapError, match="Cannot reach the IMAP server"):
        await client.check()
    await client.close()


async def test_list_folders_decodes_names_and_roles(client):
    folders = await client.list_folders()
    names = {folder.name for folder in folders}
    assert "INBOX" in names
    assert "Archives/Été 2024" in names  # modified UTF-7 decoded
    roles = {folder.role: folder.name for folder in folders if folder.role}
    assert roles["sent"] == "Sent"
    assert roles["trash"] == "Trash"
    assert roles["drafts"] == "Drafts"


async def test_resolve_folder_accepts_roles_and_display_names(client):
    assert await client.resolve_folder(None) == "INBOX"
    assert await client.resolve_folder("sent") == "Sent"
    assert await client.resolve_folder("Archives/Été 2024") == "Archives/&AMk-t&AOk- 2024"


async def test_status_counts(client):
    status = await client.status("INBOX")
    assert status["messages"] == 3
    assert status["unseen"] == 2


async def test_search_returns_newest_first(client):
    uids, total = await client.search("INBOX", build_criteria(), limit=10)
    assert total == 3
    assert uids == [3, 2, 1]


async def test_search_filters_unread(client):
    uids, _ = await client.search("INBOX", build_criteria(unread=True), limit=10)
    assert uids == [3, 2]


async def test_search_limit_applies(client):
    uids, total = await client.search("INBOX", build_criteria(), limit=2)
    assert total == 3
    assert uids == [3, 2]


async def test_fetch_summaries_parse_headers(client):
    uids, _ = await client.search("INBOX", build_criteria(), limit=10)
    summaries = await client.fetch_summaries("INBOX", uids)
    assert [item["uid"] for item in summaries] == [3, 2, 1]
    headers = parse_headers(summaries[1]["headers_raw"])
    assert headers["subject"] == "Déjeuner jeudi ?"
    assert headers["from"] == "Bob <bob@example.test>"
    assert summaries[0]["size"] > 0
    assert "\\Seen" in summaries[2]["flags"]


async def test_fetch_raw_returns_the_whole_message(client):
    raw = await client.fetch_raw("INBOX", 1)
    parsed = parse_message(raw)
    assert parsed.subject == "Invoice #42"
    assert "invoice 42" in parsed.body.lower()


async def test_fetch_unknown_uid_explains(client):
    with pytest.raises(ImapError, match="was not found"):
        await client.fetch_raw("INBOX", 999)


async def test_store_flags_marks_read(client, imap_server):
    await client.store_flags("INBOX", [2], ["\\Seen"], add=True)
    assert "\\Seen" in imap_server.state.folders["INBOX"].messages[2][1]
    status = await client.status("INBOX")
    assert status["unseen"] == 1


async def test_move_uses_the_move_capability(client, imap_server):
    moved = await client.move("INBOX", [1], "Trash")
    assert moved == 1
    assert 1 not in imap_server.state.folders["INBOX"].messages
    assert len(imap_server.state.folders["Trash"].messages) == 1


async def test_append_saves_a_copy(client, imap_server):
    await client.append("Sent", b"Subject: Hello\r\n\r\nBody\r\n", flags="\\Seen")
    assert imap_server.state.appended[0][0] == "Sent"
    assert b"Hello" in imap_server.state.appended[0][1]


async def test_create_folder(client, imap_server):
    await client.create_folder("Clients/Acme")
    assert "Clients/Acme" in imap_server.state.folders


async def test_expunge_is_targeted_with_uidplus(client, imap_server):
    await client.store_flags("INBOX", [3], ["\\Deleted"], add=True)
    scope = await client.expunge("INBOX", [3])
    assert scope == "uids"
    assert 3 not in imap_server.state.folders["INBOX"].messages
    assert 2 in imap_server.state.folders["INBOX"].messages


async def test_read_only_account_refuses_writes(account):
    account.read_only = True
    client = ImapClient(account)
    with pytest.raises(ImapError, match="read-only"):
        await client.store_flags("INBOX", [1], ["\\Seen"])
    await client.close()


async def test_reconnects_after_the_server_drops_the_link(client, imap_server):
    await client.status("INBOX")
    # Simulate a dead socket: close the client's connection behind its back.
    client._conn.sock.close()
    status = await client.status("INBOX")
    assert status["messages"] == 3
