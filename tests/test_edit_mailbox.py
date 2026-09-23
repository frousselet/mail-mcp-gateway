"""Changing the settings of a mailbox already attached to a connector."""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager
from conftest import FormClient
from test_web_onboarding import _mailbox_form, _new_connector

from mail_mcp import server, smtp_client, web

USER_ID = "usr_edit_mailbox"


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setattr(web, "_uid", lambda request: USER_ID)
    async with LifespanManager(web.build_app()) as manager, FormClient(
        transport=httpx.ASGITransport(app=manager.app),
        base_url="https://gateway.test",
        follow_redirects=False,
    ) as http:
        yield http


@pytest.fixture(autouse=True)
def smtp_ok(monkeypatch):
    async def fake_check(account):
        return {"ok": True, "host": f"{account.smtp_host}:{account.smtp_port}"}

    monkeypatch.setattr(smtp_client, "check", fake_check)


async def _attached(client, imap_server) -> tuple[str, str]:
    connection_id = await _new_connector(client, "Edit me")
    response = await client.post(
        f"/connections/{connection_id}/mailboxes", data=_mailbox_form(imap_server)
    )
    assert response.status_code == 303, response.text
    box = server.STORE.get_connection(connection_id).accounts[0]
    return connection_id, box.account_id


def _edit_form(imap_server, connection_id, account_id, **changes) -> dict[str, str]:
    form = {**_mailbox_form(imap_server), "connection_id": connection_id,
            "account_id": account_id, "secret": ""}
    form.update(changes)
    return form


async def test_the_connectors_page_offers_to_edit_each_mailbox(client, imap_server):
    connection_id, account_id = await _attached(client, imap_server)
    page = await client.get("/connectors")
    assert f"/mailboxes/edit?connection_id={connection_id}&amp;account_id={account_id}" in page.text


async def test_the_edit_form_starts_from_the_current_settings_without_the_password(
    client, imap_server
):
    connection_id, account_id = await _attached(client, imap_server)
    page = await client.get(
        f"/mailboxes/edit?connection_id={connection_id}&account_id={account_id}"
    )
    assert page.status_code == 200
    assert "Edit a mailbox" in page.text and "Save changes" in page.text
    assert f'value="{imap_server.host}"' in page.text
    assert f'value="{imap_server.port}"' in page.text
    assert imap_server.state.password not in page.text
    assert "Leave empty to keep the current one" in page.text
    assert 'action="/mailboxes/update"' in page.text


async def test_settings_change_and_an_empty_password_keeps_the_stored_one(
    client, imap_server
):
    connection_id, account_id = await _attached(client, imap_server)
    before = server.STORE.get_connection(connection_id)

    response = await client.post(
        "/mailboxes/update",
        data=_edit_form(
            imap_server, connection_id, account_id,
            from_name="Ada L.", aliases="contact@example.test", read_only="1",
        ),
    )

    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/connectors?notice=mailbox_updated"
    after = server.STORE.get_connection(connection_id)
    box = after.accounts[0]
    assert (box.account_id, box.from_name, box.read_only) == (account_id, "Ada L.", True)
    assert box.aliases == ["contact@example.test"]
    assert box.secret == imap_server.state.password
    assert after.default_account_id == account_id
    assert after.revision > before.revision  # live connections are rebuilt


async def test_settings_that_do_not_connect_change_nothing(client, imap_server):
    connection_id, account_id = await _attached(client, imap_server)
    response = await client.post(
        "/mailboxes/update",
        data=_edit_form(imap_server, connection_id, account_id, secret="wrong"),
    )
    assert response.status_code == 400
    assert "Nothing was changed" in response.text
    assert "Edit a mailbox" in response.text  # still the edit form, values kept
    box = server.STORE.get_connection(connection_id).accounts[0]
    assert box.secret == imap_server.state.password


async def test_a_new_password_replaces_the_old_one(client, imap_server):
    connection_id, account_id = await _attached(client, imap_server)
    imap_server.state.password = "rotated"
    response = await client.post(
        "/mailboxes/update",
        data=_edit_form(imap_server, connection_id, account_id, secret="rotated"),
    )
    assert response.status_code == 303, response.text
    assert server.STORE.get_connection(connection_id).accounts[0].secret == "rotated"


async def test_the_test_button_uses_the_stored_password_when_the_field_is_empty(
    client, imap_server
):
    connection_id, account_id = await _attached(client, imap_server)
    result = await client.post(
        "/test", json=_edit_form(imap_server, connection_id, account_id)
    )
    assert result.json()["ok"] is True, result.json()


async def test_another_user_cannot_edit_it(client, imap_server, monkeypatch):
    connection_id, account_id = await _attached(client, imap_server)
    monkeypatch.setattr(web, "_uid", lambda request: "usr_intruder")

    page = await client.get(
        f"/mailboxes/edit?connection_id={connection_id}&account_id={account_id}"
    )
    assert "no longer exists" in page.text
    await client.post(
        "/mailboxes/update",
        data=_edit_form(imap_server, connection_id, account_id, read_only="1"),
    )
    assert server.STORE.get_connection(connection_id).accounts[0].read_only is False
    # Nor borrow its stored password through the test button.
    result = await client.post("/test", json=_edit_form(imap_server, connection_id, account_id))
    assert result.json()["ok"] is False


async def test_the_store_keeps_both_secrets_when_they_are_not_retyped(store_path):
    from mail_mcp.accounts import MailAccount
    from mail_mcp.store import ConnectionStore

    store = ConnectionStore(store_path)
    connection = await store.create_connection(owner_id="u", label="x")
    original = MailAccount(
        address="ada@gmail.test", imap_host="imap.gmail.test", smtp_host="smtp.gmail.test",
        auth="xoauth2", oauth_provider="google", oauth_client_id="id",
        oauth_client_secret="CLIENT-SECRET", secret="REFRESH",
    )
    await store.add_account(connection.connection_id, original)

    changed = MailAccount(
        address="ada@gmail.test", imap_host="imap.gmail.test", smtp_host="smtp.gmail.test",
        auth="xoauth2", oauth_provider="google", oauth_client_id="id",
        account_id=original.account_id, read_only=True,
    )
    await store.update_account(connection.connection_id, changed)

    box = ConnectionStore(store_path).get_connection(connection.connection_id).accounts[0]
    assert (box.secret, box.oauth_client_secret, box.read_only) == (
        "REFRESH", "CLIENT-SECRET", True
    )
