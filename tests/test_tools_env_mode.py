"""Tools in single-mailbox mode (credentials from the environment).

SMTP is stubbed out (nothing is sent), but everything else runs against the
fake IMAP server, including the copy APPENDed to the Sent folder.
"""

from __future__ import annotations

import json

import pytest

from mail_mcp import server, smtp_client
from mail_mcp.accounts import AccountSet


@pytest.fixture
def tools(monkeypatch, account):
    """Point the server at the fake mailbox, in single-mailbox mode."""
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_ACCOUNTS", AccountSet([account], account.account_id))
    server._ENV_CLIENTS.clear()
    yield server
    server._ENV_CLIENTS.clear()


@pytest.fixture
def sent_messages(monkeypatch):
    """Capture what would have gone out over SMTP."""
    captured: list[dict] = []

    async def fake_send(mail_account, message, recipients, sender=None):
        captured.append(
            {"from": mail_account.address, "recipients": recipients, "raw": message}
        )
        return {"accepted": list(recipients), "refused": {}}

    monkeypatch.setattr(smtp_client, "send", fake_send)
    return captured


async def test_list_accounts(tools, account):
    out = await tools.list_accounts()
    assert account.address in out
    assert "(default)" in out


async def test_list_and_read(tools):
    listing = await tools.list_messages(limit=10)
    assert "Invoice #42" in listing
    assert "UID: `3`" in listing

    message = await tools.get_message(uid=2)
    assert "Déjeuner jeudi ?" in message
    assert "On se voit jeudi midi ?" in message


async def test_unread_filter_and_search(tools):
    unread = await tools.list_messages(unread_only=True)
    assert "UID: `1`" not in unread  # the only message already flagged \Seen
    assert "UID: `2`" in unread and "UID: `3`" in unread
    found = await tools.search_messages(sender="billing@acme.test")
    assert "Invoice #42" in found
    assert "Déjeuner" not in found


async def test_get_message_can_mark_as_read(tools, imap_server):
    await tools.get_message(uid=2, mark_as_read=True)
    assert "\\Seen" in imap_server.state.folders["INBOX"].messages[2][1]


async def test_folder_status_and_folders(tools):
    assert "3" in await tools.folder_status()
    folders = await tools.list_folders()
    assert "[sent]" in folders and "[trash]" in folders


async def test_send_message_saves_a_copy_to_sent(tools, imap_server, sent_messages):
    out = await tools.send_message(
        to="bob@example.test", subject="Hello", body="Hi Bob"
    )
    assert "Sent **Hello**" in out
    assert "A copy was saved to Sent." in out
    assert sent_messages[0]["recipients"] == ["bob@example.test"]
    assert imap_server.state.appended[0][0] == "Sent"
    assert b"Hi Bob" in imap_server.state.appended[0][1]


async def test_reply_threads_and_flags_the_original(tools, imap_server, sent_messages):
    out = await tools.reply_message(uid=1, body="Thanks, paid.")
    assert "Sent **Re: Invoice #42**" in out
    assert sent_messages[0]["recipients"] == ["billing@acme.test"]
    assert b"In-Reply-To: <msg1@example.test>" in sent_messages[0]["raw"]
    assert "\\Answered" in imap_server.state.folders["INBOX"].messages[1][1]


async def test_forward_carries_the_original(tools, sent_messages):
    out = await tools.forward_message(uid=1, to="carol@example.test", body="FYI")
    assert "Sent **Fwd: Invoice #42**" in out
    assert b"message/rfc822" in sent_messages[0]["raw"]


async def test_save_draft(tools, imap_server):
    out = await tools.save_draft(to="bob@example.test", subject="Later", body="Draft")
    assert "Draft saved to Drafts" in out
    assert imap_server.state.appended[0][0] == "Drafts"


async def test_delete_moves_to_trash_then_expunges(tools, imap_server):
    out = await tools.delete_messages(uids=[1])
    assert "Moved 1 message(s) to Trash" in out
    assert 1 not in imap_server.state.folders["INBOX"].messages

    out = await tools.delete_messages(uids=[2], permanent=True)
    assert "Permanently deleted" in out
    assert 2 not in imap_server.state.folders["INBOX"].messages


async def test_create_folder_and_move_into_it(tools, imap_server):
    await tools.create_folder(name="Clients")
    out = await tools.move_messages(uids=[3], destination="Clients")
    assert "Moved 1 message" in out
    assert len(imap_server.state.folders["Clients"].messages) == 1


async def test_get_thread_groups_the_conversation(tools):
    out = await tools.get_thread(uid=1)
    assert "Invoice #42" in out


async def test_unknown_action_is_explained(tools):
    out = await tools.mark_messages(uids=[1], action="burn")
    assert "unknown action" in out
    assert "flagged" in out


async def test_errors_come_back_as_text_not_exceptions(tools):
    out = await tools.get_message(uid=9999)
    assert out.startswith("Error:")
    assert "was not found" in out

    out = await tools.send_message(to="", subject="x", body="y")
    assert out.startswith("Error:")


async def test_read_only_account_refuses_to_send(tools, account, sent_messages):
    account.read_only = True
    out = await tools.send_message(to="bob@example.test", subject="x", body="y")
    assert "read-only" in out
    assert sent_messages == []


async def test_attachments_round_trip(tools, imap_server, sent_messages):
    import base64

    payload = base64.b64encode(b"col1,col2\n1,2\n").decode()
    await tools.send_message(
        to="bob@example.test",
        subject="Data",
        body="See attached",
        attachments=[{"filename": "data.csv", "content_base64": payload}],
    )
    assert b"data.csv" in sent_messages[0]["raw"]

    # The copy landed in Sent, so it can be read back and the part fetched.
    sent_folder = imap_server.state.folders["Sent"]
    uid = max(sent_folder.messages)
    out = await tools.get_message(uid=uid, folder="Sent")
    assert "data.csv" in out
    attachment = await tools.get_attachment(uid=uid, part_id="2", folder="Sent")
    assert "col1,col2" in attachment


async def test_no_mailbox_configured_is_explained(monkeypatch):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_ACCOUNTS", AccountSet())
    out = await server.list_folders()
    assert "no mailbox" in out.lower()


def test_env_configuration_builds_an_account(monkeypatch, tmp_path):
    monkeypatch.setenv("MAIL_ADDRESS", "ada@example.test")
    monkeypatch.setenv("MAIL_PASSWORD", "pw")
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.example.test")
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("MAIL_READ_ONLY", "yes")

    extra = tmp_path / "accounts.json"
    extra.write_text(
        json.dumps(
            [
                {
                    "address": "second@example.test",
                    "imap_host": "imap2.example.test",
                    "smtp_host": "smtp2.example.test",
                    "password": "pw2",
                },
                {"address": "broken@example.test"},
            ]
        )
    )
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(extra))

    account_set = server._env_account_set()
    addresses = [a.address for a in account_set.accounts]
    assert addresses == ["second@example.test", "ada@example.test"]
    assert account_set.resolve("ada@example.test").read_only is True
    assert account_set.resolve("second@example.test").secret == "pw2"
