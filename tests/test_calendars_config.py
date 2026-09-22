"""Calendar account validation and selection."""

from __future__ import annotations

import pytest

from mail_mcp.calendars import CalendarAccount, CalendarConfigError, CalendarSet


def _account(**overrides) -> CalendarAccount:
    base = dict(address="ada@icloud.com", secret="app-specific")
    base.update(overrides)
    return CalendarAccount(**base)


def test_known_providers_need_no_url():
    account = _account()
    account.validate()
    assert account.entry_point() == "https://caldav.icloud.com"
    assert _account(address="ada@me.com").entry_point() == "https://caldav.icloud.com"
    assert _account(address="ada@fastmail.com").entry_point().endswith("fastmail.com")


def test_unknown_provider_needs_a_url():
    with pytest.raises(CalendarConfigError, match="No CalDAV server known"):
        _account(address="ada@example.test").validate()
    _account(address="ada@example.test", url="https://dav.example.test").validate()


def test_username_defaults_to_the_address():
    assert _account().username == "ada@icloud.com"
    assert _account(username="ada").username == "ada"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"secret": ""}, "password is required"),
        ({"address": ""}, "identity"),
        ({"url": "ftp://dav.example.test"}, "must start with https"),
        ({"timezone": "Mars/Olympus"}, "not a known timezone"),
    ],
)
def test_invalid_configurations_are_explained(overrides, message):
    with pytest.raises(CalendarConfigError, match=message):
        _account(**overrides).validate()


def test_secret_never_leaves_through_the_record():
    account = _account(secret="hunter2")
    assert "secret" not in account.to_record()
    assert "hunter2" not in str(account.public_dict())


def test_resolution_and_defaults():
    first = _account(account_id="cal_1", label="Perso")
    second = _account(address="ada@work.test", url="https://dav.work.test",
                      account_id="cal_2", label="Boulot")
    calendars = CalendarSet([first, second], default_account_id="cal_2")

    assert calendars.resolve().account_id == "cal_2"
    assert calendars.resolve("perso") is first
    assert calendars.resolve("ada@work.test") is second
    assert CalendarSet([first, second]).resolve() is first


def test_resolution_errors_are_actionable():
    with pytest.raises(CalendarConfigError, match="no calendar yet"):
        CalendarSet().resolve()
    with pytest.raises(CalendarConfigError, match=r"Available: ada@icloud\.com"):
        CalendarSet([_account(account_id="cal_1")]).resolve("nope")
