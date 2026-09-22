"""The server-rendered pages: they must render, and must escape user input."""

from __future__ import annotations

from mail_mcp import ui


def _connection(label: str = "Work", accounts: list | None = None) -> dict:
    return {
        "connection_id": "con_1",
        "client_id": "mail_abc",
        "label": label,
        "mcp_url": "https://gateway.test/mcp",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        "accounts": accounts
        if accounts is not None
        else [
            {
                "account_id": "box_1",
                "address": "ada@example.test",
                "imap": "imap.example.test:993 (ssl)",
                "smtp": "smtp.example.test:587 (starttls)",
                "auth": "password",
                "read_only": False,
                "is_default": True,
            }
        ],
    }


def test_register_and_login_pages_render():
    assert "Create passkey" in ui.register_page()
    assert "doRegister" in ui.register_page()
    assert "Sign in with passkey" in ui.login_page()
    # The shared helpers must be present wherever they are called.
    assert "async function postJSON" in ui.login_page()


def test_dashboard_lists_connectors_and_mailboxes():
    html = ui.dashboard_page("owner@example.test", [_connection()])
    assert "Work" in html
    assert "ada@example.test" in html
    assert "https://gateway.test/mcp" in html
    assert "mail_abc" in html
    assert "(default)" in html


def test_dashboard_without_connectors_explains_what_to_do():
    html = ui.dashboard_page("owner@example.test", [])
    assert "No connector yet" in html


def test_connector_without_mailboxes_says_so():
    html = ui.dashboard_page("owner@example.test", [_connection(accounts=[])])
    assert "No mailbox yet" in html


def test_user_input_is_escaped():
    evil = '<script>alert("xss")</script>'
    html = ui.dashboard_page(evil, [_connection(label=evil)])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_mailbox_form_has_the_fields_the_javascript_reads():
    html = ui.mailbox_form_page(_connection())
    for field in (
        "address", "secret", "imap_host", "imap_port", "imap_security",
        "smtp_host", "smtp_port", "smtp_security", "auth", "verify_ssl",
        "oauth_provider", "oauth_client_id",
    ):
        assert f'id="{field}"' in html, field
    assert "detect()" in html and "testConn()" in html


def test_credentials_page_shows_the_secret_once():
    html = ui.credentials_page("https://gateway.test", _connection(), "s3cr3t")
    assert "s3cr3t" in html
    assert "https://gateway.test/mcp" in html
    assert "not shown again" in html
