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
