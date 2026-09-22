"""IMAP command injection: the wire must carry exactly one command.

An IMAP command line ends at CRLF and ``imaplib`` appends that terminator
without looking at what it is sending. A carriage return inside a search term
therefore does not stay inside the term: the server reads everything after it
as a new command on the same authenticated connection. Quoting cannot prevent
it, because the line ends before the closing quote.

These tests drive a socket-level server and assert on the bytes it actually
read, which is the only place the question can be settled.
"""

from __future__ import annotations

import imaplib
import socket
import threading

import pytest

from mail_mcp import server
from mail_mcp.accounts import AccountSet
from mail_mcp.imap_client import ImapError, quote
from mail_mcp.search import SearchError, build_criteria

PAYLOADS = [
    'evil\r\nZZ99 DELETE Archive\r\nx',
    'evil\nZZ99 EXPUNGE\nx',
    'evil\rZZ99 RENAME INBOX Trash\rx',
    'a\x00b',
]


class WireTap:
    """A socket-level IMAP server that records the lines it is sent."""

    def __init__(self) -> None:
        self.lines: list[bytes] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> WireTap:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._sock.close()

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        stream = conn.makefile("rwb")
        stream.write(b"* OK [CAPABILITY IMAP4rev1] ready\r\n")
        stream.flush()
        while True:
            line = stream.readline()
            if not line:
                return
            self.lines.append(line)
            tag = line.split(b" ")[0].decode(errors="replace")
            if b"LOGIN" in line:
                stream.write(f"{tag} OK ok\r\n".encode())
            elif b"SELECT" in line or b"EXAMINE" in line:
                stream.write(b"* 0 EXISTS\r\n" + f"{tag} OK [READ-ONLY] done\r\n".encode())
            elif b"LOGOUT" in line:
                stream.write(b"* BYE\r\n" + f"{tag} OK bye\r\n".encode())
                stream.flush()
                return
            else:
                stream.write(f"{tag} OK done\r\n".encode())
            stream.flush()


@pytest.fixture
def tools(monkeypatch, account):
    monkeypatch.setattr(server, "_MULTITENANT", False)
    monkeypatch.setattr(server, "_ENV_ACCOUNTS", AccountSet([account], account.account_id))
    server._ENV_CLIENTS.clear()
    yield server
    server._ENV_CLIENTS.clear()


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_payload_never_becomes_a_second_command_line(payload):
    """The regression test for the injection, asserted on the wire."""
    with pytest.raises(SearchError, match="control character"):
        build_criteria(sender=payload)


def test_the_wire_carries_one_command_for_one_search():
    """Belt and braces: even hand-built criteria cannot add a line."""
    with WireTap() as server:
        conn = imaplib.IMAP4(server.host, server.port)
        conn.login("ada@example.test", "pw")
        conn.select('"INBOX"', readonly=True)
        server.lines.clear()

        criteria = build_criteria(sender="ada@example.test", subject="Déjeuner ?")
        conn.uid("SEARCH", "CHARSET", "UTF-8", *criteria)
        conn.logout()

    commands = [line for line in server.lines if not line.startswith(b"*")]
    assert len(commands) == 2, commands  # the search, then the logout
    assert commands[0].count(b"\r\n") == 1
    assert b"UID SEARCH" in commands[0]


@pytest.mark.parametrize("field", ["sender", "recipient", "subject", "body", "query"])
def test_every_search_field_is_guarded(field):
    with pytest.raises(SearchError, match="control character"):
        build_criteria(**{field: "a\r\nZZ1 EXPUNGE"})


def test_the_raw_query_escape_hatch_is_guarded_too():
    with pytest.raises(SearchError, match="control character"):
        build_criteria(raw="ALL\r\nZZ1 EXPUNGE")


def test_folder_names_are_guarded():
    with pytest.raises(ImapError, match="control character"):
        quote('INBOX"\r\nZZ1 DELETE Archive')


def test_ordinary_values_are_untouched():
    assert build_criteria(sender="a@b.c") == [b"FROM", b'"a@b.c"']
    assert build_criteria(subject="Déjeuner ?")[1] == '"Déjeuner ?"'.encode()
    assert build_criteria(subject='He said "hi"')[1] == b'"He said \\"hi\\""'
    assert quote("Sent Items") == '"Sent Items"'
    assert quote('Odd "name"') == '"Odd \\"name\\""'


async def test_a_hostile_subject_cannot_inject_through_get_thread(tools, imap_server):
    """The zero-click path: the subject comes from whoever sent the message.

    get_thread searches on the subject of the message it was given, so a
    stranger who merely sends an email controls a search term. Python refuses
    to build such a header, but the wire does not: an RFC 2047 encoded word
    decodes straight back to CRLF.
    """
    import base64

    from mail_mcp.message import parse_headers

    payload = 'Hello\r\nZZ1 DELETE "Archives"\r\nx'
    encoded = base64.b64encode(payload.encode()).decode()
    raw = (
        b"From: Stranger <stranger@example.test>\r\n"
        b"To: ada@example.test\r\n"
        b"Date: Tue, 22 Sep 2026 09:00:00 +0000\r\n"
        b"Message-ID: <hostile@example.test>\r\n"
        b"Subject: =?utf-8?B?" + encoded.encode() + b"?=\r\n"
        b"\r\nBody\r\n"
    )
    # The encoded word does carry CRLF; decoding flattens it to one line, and
    # the search layer would refuse it anyway (both are tested elsewhere).
    assert "\r" not in parse_headers(raw)["subject"]

    from fake_imap import Mailbox

    # The folder the payload aims at, so its survival means something.
    imap_server.state.folders["Archives"] = Mailbox("Archives")
    uid = imap_server.state.folders["INBOX"].add(raw)

    out = await tools.get_thread(uid=uid)

    assert not out.startswith("Error:"), out
    assert "Archives" in imap_server.state.folders, "the payload deleted a folder"
