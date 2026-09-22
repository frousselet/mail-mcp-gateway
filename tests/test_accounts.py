"""Account validation and selection."""

from __future__ import annotations

import pytest

from mail_mcp.accounts import AccountConfigError, AccountSet, MailAccount


def _account(**overrides) -> MailAccount:
    base = dict(
        address="ada@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        secret="pw",
    )
    base.update(overrides)
    return MailAccount(**base)


def test_usernames_default_to_the_address():
    account = _account()
    assert account.imap_username == "ada@example.test"
    assert account.smtp_username == "ada@example.test"
    assert account.label == "ada@example.test"


def test_sender_uses_the_display_name():
    assert _account(from_name="Ada").sender() == "Ada <ada@example.test>"
    assert _account().sender() == "ada@example.test"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"address": "not-an-email"}, "not a valid email"),
        ({"imap_host": ""}, "IMAP host is required"),
        ({"smtp_host": ""}, "SMTP host is required"),
        ({"secret": ""}, "password is required"),
        ({"imap_security": "quantum"}, "IMAP security must be"),
        ({"imap_port": 70000}, "IMAP port must be"),
        ({"auth": "xoauth2", "oauth_provider": "aol"}, "oauth_provider"),
    ],
)
def test_invalid_configurations_are_explained(overrides, message):
    with pytest.raises(AccountConfigError, match=message):
        _account(**overrides).validate()


def test_xoauth2_needs_a_client_id():
    account = _account(auth="xoauth2", oauth_provider="google", secret="refresh")
    with pytest.raises(AccountConfigError, match="client ID"):
        account.validate()
    account.oauth_client_id = "id"
    account.validate()


def test_secret_never_leaves_through_the_record_or_public_view():
    account = _account(secret="hunter2")
    assert "secret" not in account.to_record()
    assert "hunter2" not in str(account.public_dict())


def test_resolution_by_address_label_or_id():
    first = _account(account_id="box_1", label="Work")
    second = _account(address="perso@example.test", account_id="box_2", label="Perso")
    account_set = AccountSet([first, second], default_account_id="box_2")

    assert account_set.resolve().account_id == "box_2"
    assert account_set.resolve("box_1") is first
    assert account_set.resolve("WORK") is first
    assert account_set.resolve("perso@example.test") is second


def test_resolution_errors_are_actionable():
    with pytest.raises(AccountConfigError, match="no mailbox yet"):
        AccountSet().resolve()
    with pytest.raises(AccountConfigError, match=r"Available: ada@example\.test"):
        AccountSet([_account(account_id="box_1")]).resolve("nope@example.test")


def test_default_falls_back_to_the_first_account():
    first = _account(account_id="box_1")
    second = _account(address="b@example.test", account_id="box_2")
    assert AccountSet([first, second]).resolve() is first
