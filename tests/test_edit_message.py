"""Modifying a message already in the mailbox, in any folder."""

from __future__ import annotations

import base64
from email import message_from_bytes, policy
from email.message import EmailMessage

import pytest

from mail_mcp import server
from mail_mcp.accounts import AccountSet
from mail_mcp.composer import edit_message, revise_draft
from mail_mcp.message import parse_message


@pytest.fixture
def tools(monkeypatch, account):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_ACCOUNTS", AccountSet([account], account.account_id))
    server._ENV_CLIENTS.clear()
    yield server
    server._ENV_CLIENTS.clear()


def _received(with_html: bool = False, with_file: bool = False) -> bytes:
    message = EmailMessage()
    message["Received"] = "from mx.example.test by imap.example.test"
    message["From"] = "Bob <bob@example.test>"
    message["To"] = "ada@example.test"
    message["Subject"] = "Devis 42"
    message["Date"] = "Tue, 22 Sep 2026 09:00:00 +0000"
    message["Message-ID"] = "<devis42@example.test>"
    message["X-Custom"] = "kept"
    message.set_content("Old text")
    if with_html:
        message.add_alternative("<p>Old text</p>", subtype="html")
    if with_file:
        message.add_attachment(b"%PDF-1.4 devis", maintype="application",
                               subtype="pdf", filename="devis.pdf")
    return message.as_bytes()


def _latest(mailbox) -> EmailMessage:
    uid = max(mailbox.messages)
    return message_from_bytes(mailbox.messages[uid][0], policy=policy.default)


# --- the rewrite itself --------------------------------------------------------


def test_a_new_subject_keeps_the_rest_of_the_message_as_it_was():
    raw = _received(with_file=True)
    revised = edit_message(parse_message(raw), subject="Devis 42 (signé)")

    assert revised["Subject"] == "Devis 42 (signé)"
    for header in ("From", "To", "Date", "Message-ID", "X-Custom", "Received"):
        assert revised[header] == message_from_bytes(raw, policy=policy.default)[header]
    assert [a.filename for a in parse_message(revised.as_bytes()).attachments] == ["devis.pdf"]


def test_a_new_body_keeps_headers_and_attachments_and_drops_the_stale_html():
    revised = parse_message(
        edit_message(
            parse_message(_received(with_html=True, with_file=True)), body="New text"
        ).as_bytes()
    )
    assert revised.text.strip() == "New text"
    assert revised.html == ""  # the old HTML would still say "Old text"
    assert revised.message_id == "<devis42@example.test>"
    assert [a.filename for a in revised.attachments] == ["devis.pdf"]


def test_attachments_can_be_replaced_or_removed():
    original = parse_message(_received(with_file=True))
    note = {"filename": "note.txt", "content_base64": base64.b64encode(b"hi").decode()}
    replaced = parse_message(edit_message(original, attachments=[note]).as_bytes())
    assert [a.filename for a in replaced.attachments] == ["note.txt"]
    removed = parse_message(edit_message(original, attachments=[]).as_bytes())
    assert removed.attachments == []


def test_recipients_with_a_comma_in_the_name_stay_whole():
    revised = edit_message(
        parse_message(_received()), to='"Doe, John" <john@example.test>, ada@example.test'
    )
    assert parse_message(revised.as_bytes()).to == [
        '"Doe, John" <john@example.test>', "ada@example.test"
    ]


def test_a_revised_draft_body_no_longer_carries_the_old_html():
    from mail_mcp.accounts import MailAccount

    account = MailAccount(address="ada@example.test", imap_host="i", smtp_host="s", secret="x")
    draft = parse_message(_received(with_html=True))
    assert revise_draft(account, draft, body="New").message.get_body(("html",)) is None


# --- the tool ------------------------------------------------------------------


async def test_edit_a_received_message_in_place(tools, imap_server):
    inbox = imap_server.state.folders["INBOX"]
    uid = inbox.add(_received(), {"\\Seen", "\\Flagged"})

    out = await tools.edit_message(uid=uid, subject="Devis 42 (validé)", body="Validé.")

    assert not out.startswith("Error:"), out
    assert uid not in inbox.messages
    revised = _latest(inbox)
    assert revised["Subject"] == "Devis 42 (validé)"
    assert revised["Message-ID"] == "<devis42@example.test>"
    assert revised.get_body(("plain",)).get_content().strip() == "Validé."
    assert {"\\Seen", "\\Flagged"} <= inbox.messages[max(inbox.messages)][1]
    assert len(imap_server.state.folders["Trash"].messages) == 1
    assert f"New uid: {max(inbox.messages)}" in out
    assert "anyone who already received" in out


async def test_edit_a_sent_message_and_keep_the_original(tools, imap_server):
    sent = imap_server.state.folders["Sent"]
    uid = sent.add(_received(), {"\\Seen"})

    out = await tools.edit_message(uid=uid, folder="Sent", cc="carol@example.test",
                                   keep_original=True)

    assert "kept where it was" in out
    assert uid in sent.messages and len(sent.messages) == 2
    assert _latest(sent)["Cc"] == "carol@example.test"


async def test_nothing_to_change_is_said(tools, imap_server):
    uid = imap_server.state.folders["INBOX"].add(_received())
    assert (await tools.edit_message(uid=uid)).startswith("Error: nothing to change")


async def test_a_read_only_mailbox_refuses(tools, account, imap_server):
    account.read_only = True
    uid = imap_server.state.folders["INBOX"].add(_received())
    out = await tools.edit_message(uid=uid, subject="x")
    assert "read-only" in out
    assert uid in imap_server.state.folders["INBOX"].messages
