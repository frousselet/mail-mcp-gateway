"""Building outgoing messages."""

from __future__ import annotations

import base64

import pytest

from mail_mcp.accounts import MailAccount
from mail_mcp.composer import ComposeError, build_forward, build_message, build_reply
from mail_mcp.message import parse_message


@pytest.fixture
def sender_account() -> MailAccount:
    return MailAccount(
        address="ada@example.test",
        from_name="Ada Lovelace",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        secret="x",
    )


def _original() -> object:
    from email.message import EmailMessage

    message = EmailMessage()
    message["Subject"] = "Invoice #42"
    message["From"] = "Billing <billing@acme.test>"
    message["To"] = "ada@example.test, Carol <carol@example.test>"
    message["Cc"] = "dave@example.test"
    message["Date"] = "Mon, 21 Sep 2026 09:15:00 +0000"
    message["Message-ID"] = "<invoice42@acme.test>"
    message.set_content("Please pay invoice 42.")
    return parse_message(message.as_bytes())


def test_build_message_sets_headers_and_recipients(sender_account):
    outgoing = build_message(
        sender_account,
        to="bob@example.test, Carol <carol@example.test>",
        cc="dave@example.test",
        bcc="audit@example.test",
        subject="Hello",
        body="Hi there",
    )
    message = outgoing.message
    assert message["From"] == "Ada Lovelace <ada@example.test>"
    assert message["Subject"] == "Hello"
    assert "Message-ID" in message
    # Bcc must not appear in the message, but must be in the envelope.
    assert message["Bcc"] is None
    assert outgoing.recipients == [
        "bob@example.test",
        "carol@example.test",
        "dave@example.test",
        "audit@example.test",
    ]


def test_message_without_recipient_is_refused(sender_account):
    with pytest.raises(ComposeError, match="recipient"):
        build_message(sender_account, subject="x", body="y")


def test_html_alternative_and_attachment(sender_account):
    payload = base64.b64encode(b"hello").decode()
    outgoing = build_message(
        sender_account,
        to="bob@example.test",
        subject="With files",
        body="text",
        html="<p>rich</p>",
        attachments=[{"filename": "a.txt", "content_base64": payload}],
    )
    parsed = parse_message(outgoing.as_bytes())
    assert "rich" in parsed.html
    assert [a.filename for a in parsed.attachments] == ["a.txt"]
    assert parsed.attachment_part("3").get_payload(decode=True) == b"hello"


def test_bad_base64_is_refused(sender_account):
    with pytest.raises(ComposeError, match="base64"):
        build_message(
            sender_account,
            to="bob@example.test",
            subject="x",
            body="y",
            attachments=[{"filename": "a.txt", "content_base64": "!!!not base64!!!"}],
        )


def test_reply_threads_and_quotes(sender_account):
    outgoing = build_reply(sender_account, _original(), body="Paid, thanks.")
    message = outgoing.message
    assert message["Subject"] == "Re: Invoice #42"
    assert message["In-Reply-To"] == "<invoice42@acme.test>"
    assert "<invoice42@acme.test>" in message["References"]
    assert outgoing.recipients == ["billing@acme.test"]
    body = parse_message(outgoing.as_bytes()).body
    assert "Paid, thanks." in body
    assert "> Please pay invoice 42." in body


def test_reply_all_copies_the_others_but_not_me(sender_account):
    outgoing = build_reply(sender_account, _original(), body="ok", reply_all=True)
    assert "carol@example.test" in outgoing.recipients
    assert "dave@example.test" in outgoing.recipients
    assert "ada@example.test" not in outgoing.recipients


def test_reply_without_quote(sender_account):
    outgoing = build_reply(
        sender_account, _original(), body="ok", quote_original=False
    )
    assert ">" not in parse_message(outgoing.as_bytes()).body


def test_forward_attaches_the_original(sender_account):
    outgoing = build_forward(sender_account, _original(), to="bob@example.test", body="FYI")
    parsed = parse_message(outgoing.as_bytes())
    assert parsed.subject == "Fwd: Invoice #42"
    assert "FYI" in parsed.body
    assert "Forwarded message" in parsed.body
    assert any(a.content_type == "message/rfc822" for a in parsed.attachments)


def test_a_draft_remembers_its_blind_recipients(sender_account):
    """Bcc must survive save_draft, or it is silently lost before sending."""
    draft = build_message(
        sender_account, to="bob@example.test", bcc="audit@example.test",
        subject="x", body="y", bcc_header=True,
    )
    assert draft.message["Bcc"] == "audit@example.test"

    # But a message on its way out must not carry them.
    outgoing = build_message(
        sender_account, to="bob@example.test", bcc="audit@example.test",
        subject="x", body="y",
    )
    assert outgoing.message["Bcc"] is None
    assert "audit@example.test" in outgoing.recipients


def test_revise_draft_keeps_what_is_not_passed(sender_account):
    from mail_mcp.composer import revise_draft

    draft = build_message(
        sender_account, to="bob@example.test", cc="carol@example.test",
        subject="Devis", body="Premier jet",
        attachments=[{"filename": "a.txt", "content_base64": "aGVsbG8="}],
        bcc_header=True,
    )
    original = parse_message(draft.as_bytes())

    revised = revise_draft(sender_account, original, body="Lorem ipsum")
    parsed = parse_message(revised.as_bytes())
    assert "Lorem ipsum" in parsed.body
    assert parsed.subject == "Devis"
    assert parsed.to == ["bob@example.test"]
    assert parsed.cc == ["carol@example.test"]
    assert [a.filename for a in parsed.attachments] == ["a.txt"]


def test_revise_draft_can_drop_the_attachments(sender_account):
    from mail_mcp.composer import revise_draft

    draft = build_message(
        sender_account, to="bob@example.test", subject="x", body="y",
        attachments=[{"filename": "a.txt", "content_base64": "aGVsbG8="}],
    )
    revised = revise_draft(
        sender_account, parse_message(draft.as_bytes()), attachments=[]
    )
    assert parse_message(revised.as_bytes()).attachments == []


def test_prepare_for_sending_moves_bcc_to_the_envelope(sender_account):
    from mail_mcp.composer import prepare_for_sending

    draft = build_message(
        sender_account, to="bob@example.test", cc="carol@example.test",
        bcc="audit@example.test", subject="x", body="y", bcc_header=True,
    )
    payload, recipients = prepare_for_sending(parse_message(draft.as_bytes()))
    assert set(recipients) == {"bob@example.test", "carol@example.test", "audit@example.test"}
    assert b"audit@example.test" not in payload.replace(b"\r\n ", b"")
    assert b"Date:" in payload


def test_prepare_for_sending_refuses_a_draft_with_nobody_to_send_to(sender_account):
    from email.message import EmailMessage

    from mail_mcp.composer import prepare_for_sending

    orphan = EmailMessage()
    orphan["Subject"] = "Notes to self"
    orphan["From"] = sender_account.address
    orphan.set_content("...")
    with pytest.raises(ComposeError, match="nobody to send it to"):
        prepare_for_sending(parse_message(orphan.as_bytes()))
