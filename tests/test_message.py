"""Message parsing: encoded headers, multipart bodies, attachments, HTML."""

from __future__ import annotations

import base64
from email.message import EmailMessage

from mail_mcp.message import html_to_text, parse_headers, parse_message, truncate


def _multipart() -> bytes:
    message = EmailMessage()
    message["Subject"] = "Rapport d'activité"
    message["From"] = "Ada Lovelace <ada@example.test>"
    message["To"] = "bob@example.test, Carol <carol@example.test>"
    message["Cc"] = "dave@example.test"
    message["Date"] = "Tue, 22 Sep 2026 11:30:00 +0000"
    message["Message-ID"] = "<abc@example.test>"
    message["References"] = "<root@example.test> <mid@example.test>"
    message.set_content("Bonjour,\n\nVoici le rapport.\n")
    message.add_alternative("<p>Bonjour,</p><p>Voici le <b>rapport</b>.</p>", subtype="html")
    message.add_attachment(
        b"col1,col2\n1,2\n", maintype="text", subtype="csv", filename="data.csv"
    )
    message.add_attachment(
        b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="report.pdf"
    )
    return message.as_bytes()


def test_headers_are_decoded():
    raw = b"Subject: =?utf-8?B?" + base64.b64encode("Réunion".encode()).decode().encode()
    raw += b"?=\r\nFrom: =?utf-8?Q?Andr=C3=A9?= <andre@example.test>\r\n\r\n"
    headers = parse_headers(raw)
    assert headers["subject"] == "Réunion"
    assert headers["from"] == "André <andre@example.test>"
    assert headers["from_address"] == "andre@example.test"


def test_parse_multipart_message():
    parsed = parse_message(_multipart())
    assert parsed.subject == "Rapport d'activité"
    assert parsed.from_ == "Ada Lovelace <ada@example.test>"
    assert parsed.to == ["bob@example.test", "Carol <carol@example.test>"]
    assert parsed.cc == ["dave@example.test"]
    assert parsed.references == ["<root@example.test>", "<mid@example.test>"]
    assert "Voici le rapport." in parsed.body
    assert "<b>rapport</b>" in parsed.html


def test_attachments_are_listed_and_fetchable():
    parsed = parse_message(_multipart())
    names = {a.filename for a in parsed.attachments}
    assert names == {"data.csv", "report.pdf"}
    csv = next(a for a in parsed.attachments if a.filename == "data.csv")
    part = parsed.attachment_part(csv.part_id)
    assert part is not None
    assert part.get_payload(decode=True) == b"col1,col2\n1,2\n"
    assert csv.size == len(b"col1,col2\n1,2\n")


def test_html_only_message_falls_back_to_text():
    message = EmailMessage()
    message["Subject"] = "HTML only"
    message["From"] = "a@example.test"
    message.set_content(
        "<html><head><style>p{color:red}</style></head>"
        "<body><p>Hello</p><p>See <a href='https://example.test'>this</a></p></body></html>",
        subtype="html",
    )
    parsed = parse_message(message.as_bytes())
    assert parsed.text == ""
    body = parsed.body
    assert "Hello" in body
    assert "color:red" not in body
    assert "https://example.test" in body


def test_html_to_text_keeps_structure():
    text = html_to_text("<p>One</p><p>Two</p><script>alert(1)</script>")
    assert "One" in text and "Two" in text
    assert "alert" not in text


def test_truncate_cuts_on_a_line_boundary():
    text = "\n".join(f"line {i}" for i in range(50))
    cut, was_truncated = truncate(text, 100)
    assert was_truncated
    assert len(cut) <= 100
    assert not cut.endswith("lin")
    assert truncate("short", 0) == ("short", False)
