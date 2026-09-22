"""Modified UTF-7, checked against the RFC 3501 examples."""

import pytest

from mail_mcp import mutf7


@pytest.mark.parametrize(
    "decoded, encoded",
    [
        ("INBOX", "INBOX"),
        ("Sent Items", "Sent Items"),
        ("Éléments envoyés", "&AMk-l&AOk-ments envoy&AOk-s"),
        ("R&D", "R&-D"),
        ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
    ],
)
def test_round_trip(decoded, encoded):
    assert mutf7.encode(decoded) == encoded
    assert mutf7.decode(encoded) == decoded


def test_decode_accepts_bytes_and_broken_input():
    assert mutf7.decode(b"Archive") == "Archive"
    # An unterminated shift must not raise; it is kept verbatim.
    assert mutf7.decode("Bad&AMk") == "Bad&AMk"
