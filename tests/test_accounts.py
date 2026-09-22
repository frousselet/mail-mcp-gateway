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


# ---------------------------------------------------------------------------
# Sending identities: iCloud+ custom domains, aliases
# ---------------------------------------------------------------------------


def test_from_address_overrides_the_login_address():
    account = _account(address="ada@icloud.com", from_address="francois@rslt.fr")
    assert account.default_sender() == "francois@rslt.fr"
    assert account.sender() == "francois@rslt.fr"
    assert account.imap_username == "ada@icloud.com"  # login is untouched


def test_identities_list_the_default_first_without_duplicates():
    account = _account(
        address="ada@icloud.com",
        from_address="francois@rslt.fr",
        aliases=["contact@rslt.fr", "ada@icloud.com", "  "],
    )
    assert account.sending_identities() == [
        "francois@rslt.fr",
        "ada@icloud.com",
        "contact@rslt.fr",
    ]


def test_aliases_accept_a_comma_separated_string():
    account = _account(aliases="one@example.test; two@example.test\nthree@example.test")
    assert account.sending_identities()[1:] == [
        "one@example.test",
        "two@example.test",
        "three@example.test",
    ]


def test_resolving_a_sender_accepts_a_display_form_and_any_case():
    account = _account(aliases=["Contact@RSLT.fr"])
    assert account.resolve_sender("contact@rslt.fr") == "Contact@RSLT.fr"
    assert account.resolve_sender("Someone <CONTACT@rslt.fr>") == "Contact@RSLT.fr"


def test_sending_as_an_unknown_address_is_refused():
    account = _account(address="ada@example.test")
    with pytest.raises(AccountConfigError, match="is not an address"):
        account.resolve_sender("boss@othercompany.test")


def test_display_name_applies_to_whichever_identity_is_used():
    account = _account(from_name="Ada", aliases=["contact@example.test"])
    assert account.sender("contact@example.test") == "Ada <contact@example.test>"
