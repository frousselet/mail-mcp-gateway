"""The encrypted store: connections, mailboxes, secrets, OAuth records."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from mail_mcp.accounts import MailAccount
from mail_mcp.store import ConnectionStore, OAuthCode, OAuthTokenRecord


def _account(address: str = "ada@example.test") -> MailAccount:
    return MailAccount(
        address=address,
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        secret="hunter2",
    )


@pytest.fixture
def store(store_path) -> ConnectionStore:
    return ConnectionStore(store_path)


async def test_connection_round_trip(store, store_path):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    assert connection.client_id.startswith("mail_")
    assert len(connection.client_secret) > 20

    found = store.get_connection_by_client_id(connection.client_id)
    assert found is not None
    assert found.client_secret == connection.client_secret
    assert found.label == "Work"

    # Secrets must not be readable in the file.
    raw = json.loads(Path(store_path).read_text())
    record = raw["connections"][connection.connection_id]
    assert connection.client_secret not in json.dumps(raw)
    assert record["client_secret_enc"] != connection.client_secret


async def test_mailbox_secrets_are_encrypted_at_rest(store, store_path):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    await store.add_account(connection.connection_id, _account(), owner_id="usr_1")

    assert "hunter2" not in Path(store_path).read_text()
    reloaded = store.get_connection(connection.connection_id)
    assert reloaded.accounts[0].secret == "hunter2"
    assert reloaded.default_account_id == reloaded.accounts[0].account_id


async def test_several_mailboxes_per_connection(store):
    connection = await store.create_connection(owner_id="usr_1", label="All mail")
    first = await store.add_account(
        connection.connection_id, _account("one@example.test"), owner_id="usr_1"
    )
    second = await store.add_account(
        connection.connection_id, _account("two@example.test"), owner_id="usr_1"
    )
    reloaded = store.get_connection(connection.connection_id)
    assert [a.address for a in reloaded.accounts] == [
        "one@example.test",
        "two@example.test",
    ]
    assert reloaded.default_account_id == first.account_id

    await store.set_default_account(
        connection.connection_id, second.account_id, owner_id="usr_1"
    )
    assert store.get_connection(connection.connection_id).default_account_id == (
        second.account_id
    )


async def test_revision_changes_when_mailboxes_change(store):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    before = store.get_connection(connection.connection_id).revision
    await store.add_account(connection.connection_id, _account(), owner_id="usr_1")
    assert store.get_connection(connection.connection_id).revision > before


async def test_owner_isolation(store):
    mine = await store.create_connection(owner_id="usr_1", label="Mine")
    await store.create_connection(owner_id="usr_2", label="Theirs")

    assert [c.label for c in store.list_connections(owner_id="usr_1")] == ["Mine"]
    # Another user cannot delete or edit it.
    assert await store.delete_connection(mine.connection_id, owner_id="usr_2") is False
    assert await store.add_account(
        mine.connection_id, _account(), owner_id="usr_2"
    ) is None
    assert store.get_connection(mine.connection_id) is not None


async def test_rotate_secret_invalidates_tokens(store):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    await store.save_token(
        OAuthTokenRecord(
            token="at_x", client_id=connection.client_id, expires_at=time.time() + 60
        )
    )
    assert store.get_token("at_x") is not None

    new_secret = await store.rotate_client_secret(connection.connection_id, "usr_1")
    assert new_secret != connection.client_secret
    assert store.get_token("at_x") is None
    assert store.get_connection(connection.connection_id).client_secret == new_secret


async def test_deleting_a_connection_revokes_its_tokens(store):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    await store.save_token(
        OAuthTokenRecord(
            token="at_y", client_id=connection.client_id, expires_at=time.time() + 60
        )
    )
    await store.delete_connection(connection.connection_id, owner_id="usr_1")
    assert store.get_token("at_y") is None
    assert store.get_connection_by_client_id(connection.client_id) is None


async def test_tokens_and_codes_are_stored_hashed(store, store_path):
    await store.save_code(
        OAuthCode(
            code="code_secret",
            client_id="mail_x",
            redirect_uri="https://claude.ai/cb",
            code_challenge="abc",
            expires_at=time.time() + 60,
        )
    )
    await store.save_token(
        OAuthTokenRecord(token="at_secret", client_id="mail_x", expires_at=time.time() + 60),
        refresh_token="rt_secret",
    )
    contents = Path(store_path).read_text()
    for secret in ("code_secret", "at_secret", "rt_secret"):
        assert secret not in contents
    assert store.get_code("code_secret") is not None
    assert store.get_token("at_secret").client_id == "mail_x"
    assert store.get_refresh_access_hash("rt_secret") is not None

    await store.revoke("at_secret")
    assert store.get_token("at_secret") is None
    assert store.get_refresh_access_hash("rt_secret") is None


async def test_purge_expired(store):
    await store.save_token(
        OAuthTokenRecord(token="at_old", client_id="mail_x", expires_at=time.time() - 1)
    )
    await store.save_token(
        OAuthTokenRecord(token="at_new", client_id="mail_x", expires_at=time.time() + 600)
    )
    assert await store.purge_expired() == 1
    assert store.get_token("at_new") is not None


async def test_store_survives_a_reload(store, store_path):
    connection = await store.create_connection(owner_id="usr_1", label="Work")
    await store.add_account(connection.connection_id, _account(), owner_id="usr_1")

    reopened = ConnectionStore(store_path)
    reloaded = reopened.get_connection_by_client_id(connection.client_id)
    assert reloaded is not None
    assert reloaded.accounts[0].secret == "hunter2"
    assert reloaded.client_secret == connection.client_secret
