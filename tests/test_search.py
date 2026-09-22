"""Search criteria construction."""

from datetime import date, timedelta

import pytest

from mail_mcp.search import SearchError, build_criteria, describe, imap_date


def test_defaults_to_all():
    assert build_criteria() == [b"ALL"]


def test_named_filters_are_anded():
    criteria = build_criteria(subject="Facture", sender="acme.com", unread=True)
    assert describe(criteria) == 'FROM "acme.com" SUBJECT "Facture" UNSEEN'


def test_non_ascii_values_are_utf8_bytes():
    criteria = build_criteria(subject="Déjeuner")
    assert criteria[1] == '"Déjeuner"'.encode()


def test_quotes_are_escaped():
    assert describe(build_criteria(sender='a"b@c.d')) == 'FROM "a\\"b@c.d"'


def test_date_formats():
    assert imap_date("2024-01-15") == "15-Jan-2024"
    assert imap_date("15/01/2024") == "15-Jan-2024"
    assert imap_date(date(2024, 1, 15)) == "15-Jan-2024"
    assert imap_date("today") == imap_date(date.today())
    assert imap_date("7d") == imap_date(date.today() - timedelta(days=7))


def test_bad_date_is_explained():
    with pytest.raises(SearchError, match="not a date I understand"):
        imap_date("last tuesday")


def test_read_and_flag_filters_invert():
    assert describe(build_criteria(unread=False)) == "SEEN"
    assert describe(build_criteria(flagged=False)) == "UNFLAGGED"
