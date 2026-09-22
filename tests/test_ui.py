"""The rendered pages: structure, escaping, and the invariants that keep them safe."""

from __future__ import annotations

import re
from itertools import pairwise

import pytest

from mail_mcp import ui

PAGES_UNDER_TEST = "all pages this module can render"


def _connection(label: str = "Work", accounts: list | None = None, calendars: list | None = None) -> dict:
    return {
        "connection_id": "con_1",
        "client_id": "mail_abc",
        "label": label,
        "email": "owner@example.test",
        "mcp_url": "https://gateway.test/mcp",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        "activity": {"last_used": "3 minutes ago", "calls_7d": 12, "errors_7d": 1},
        "accounts": accounts
        if accounts is not None
        else [
            {
                "account_id": "box_1",
                "address": "ada@example.test",
                "imap": "imap.example.test:993 (ssl)",
                "smtp": "smtp.example.test:587 (starttls)",
                "auth": "password",
                "sends_as": ["ada@example.test"],
                "read_only": False,
                "is_default": True,
            }
        ],
        "calendars": calendars if calendars is not None else [],
    }


NOW = 1790000000.0


def _overview(tmp: str | None = None):
    import tempfile
    from pathlib import Path

    from mail_mcp.activity import ActivityEntry, ActivityLog, overview

    log = ActivityLog(str(Path(tmp or tempfile.mkdtemp()) / "a.jsonl"), max_entries=500)
    for index in range(30):
        log.append(ActivityEntry(
            ts=NOW - index * 5000, tool=["search_messages", "send_message"][index % 2],
            status="error" if index == 3 else "ok", owner_id="u",
            connection_id="con_1", connection_label="Work",
            account="ada@example.test", duration_ms=100 + index,
            detail="IMAP login rejected" if index == 3 else "",
        ))
    return overview(log, "u", now=NOW)


def _home(connections, **kwargs) -> str:
    return ui.home_page(
        "owner@example.test", connections=connections, overview=_overview(),
        now=NOW, **kwargs,
    )


def _every_page() -> dict[str, str]:
    """One of each page, so the invariants below are checked across the module."""
    entry = {
        "ts": 1790000000.0,
        "when": "2026-09-22 16:00:00 UTC",
        "tool": "send_message",
        "status": "ok",
        "account": "ada@example.test",
        "connection_id": "con_1",
        "connection_label": "Work",
        "arguments": {"to": "bob@example.test", "subject": "Devis"},
        "detail": "",
        "duration_ms": 120,
    }
    return {
        "register": ui.register_page(),
        "register_signed_in": ui.register_page(signed_in=True),
        "login": ui.login_page(),
        "connectors": ui.connectors_page("owner@example.test", [_connection()]),
        "home": _home([_connection(), _connection(label="Idle", accounts=[])]),
        "home_empty": _home([]),
        "mailbox_form": ui.mailbox_form_page(_connection()),
        "calendar_form": ui.calendar_form_page(_connection()),
        "credentials": ui.credentials_page("https://gateway.test", _connection(), "s3cr3t"),
        "confirm": ui.confirm_page(
            title="Remove this mailbox",
            question="Remove ada@example.test?",
            detail="The agent loses access.",
            action="/mailboxes/delete",
            fields={"connection_id": "con_1", "account_id": "box_1"},
            confirm_label="Remove mailbox",
        ),
        "account": ui.account_page(
            "owner@example.test",
            [
                {
                    "credential_id": "abc",
                    "short_id": "abc...",
                    "created_at": 1790000000,
                    "added": "2026-09-22 16:00 UTC",
                    "last_used": "3 minutes ago",
                }
            ],
        ),
        "logs": ui.logs_page(
            "owner@example.test",
            [entry],
            connections=[("con_1", "Work")],
            stats={"total": 1, "errors": 0, "last_24h": 1, "tools": ["send_message"],
                   "accounts": ["ada@example.test"]},
            filters={"connection_id": "", "account": "", "tool": "", "status": ""},
            limit=100,
        ),
    }


# ---------------------------------------------------------------------------
# Invariants that hold for every page
# ---------------------------------------------------------------------------


def test_no_inline_event_handlers_or_styles():
    """A strict CSP forbids both; a page that needs them would break silently."""
    for name, html in _every_page().items():
        assert " onclick=" not in html, name
        assert " onchange=" not in html, name
        assert " onsubmit=" not in html, name
        assert " style=" not in html, name
        assert "<style" not in html, name
        assert "javascript:" not in html, name


def test_every_page_has_its_own_title_and_landmarks():
    seen: set[str] = set()
    for name, html in _every_page().items():
        title = re.search(r"<title>(.*?)</title>", html).group(1)
        assert title.endswith("- Mail MCP Gateway"), name
        seen.add(title)
        assert '<main id="main">' in html, name
        assert 'class="skip" href="#main"' in html, name
        assert "<h1>" in html, name
    assert len(seen) >= 8, "pages must be distinguishable by their tab title"


def test_pages_link_the_versioned_assets_and_inline_nothing():
    for name, html in _every_page().items():
        assert '<link rel="stylesheet" href="/assets/app.css?v=' in html, name
        assert '<script src="/assets/app.js?v=' in html, name
        assert "<script>" not in html, name


def test_headings_do_not_skip_levels():
    for name, html in _every_page().items():
        levels = [int(level) for level in re.findall(r"<h([1-6])[ >]", html)]
        assert levels[0] == 1, name
        for previous, current in pairwise(levels):
            assert current <= previous + 1, f"{name}: h{previous} -> h{current}"


def test_tables_are_labelled_and_scoped():
    for name, html in _every_page().items():
        for table in re.findall(r"<table.*?</table>", html, re.S):
            assert "<caption" in table, name
            assert "<thead>" in table, name
            headers = re.findall(r"<th\b[^>]*>", table)  # <thead> must not count
            for header in headers:
                assert 'scope="col"' in header or 'scope="row"' in header, (name, header)


def test_no_button_nested_in_a_link():
    for name, html in _every_page().items():
        assert not re.search(r"<a\b[^>]*>\s*<button", html), name


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


EVIL = "a'+alert(document.domain)+'b@x.io"


def test_user_values_are_escaped_everywhere():
    html = ui.connectors_page(
        "<script>alert(1)</script>",
        [_connection(label="<img src=x onerror=alert(1)>")],
    )
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_an_address_with_an_apostrophe_cannot_reach_a_script_context():
    """The old confirm() handler decoded &#x27; back into a quote and broke out."""
    html = ui.connectors_page(
        "owner@example.test",
        [_connection(accounts=[{
            "account_id": "box_1", "address": EVIL, "imap": "i", "smtp": "s",
            "auth": "password", "sends_as": [EVIL], "read_only": False,
            "is_default": True,
        }])],
    )
    assert "alert(document.domain)" not in html.replace("&#x27;", "'").replace(
        "&amp;#x27;", "'"
    ) or "confirm(" not in html
    # Stronger: there is no script context on the page at all.
    assert "confirm(" not in html
    assert "<script>" not in html
    assert EVIL not in html  # it is present, but escaped
    assert "a&#x27;+alert" in html


# ---------------------------------------------------------------------------
# Page content
# ---------------------------------------------------------------------------


def test_register_and_login_pages_drive_the_passkey_flow():
    register = ui.register_page()
    assert 'data-action="register"' in register
    assert 'id="email"' in register
    assert 'role="alert"' in register
    assert 'data-action="login"' in ui.login_page()


def test_register_page_asks_for_the_invite_code_only_when_one_is_required():
    assert 'id="code"' in ui.register_page(invite_required=True)
    assert 'id="code"' not in ui.register_page(invite_required=False)


def test_connectors_page_says_what_the_agent_may_do_in_words():
    writable = ui.connectors_page("owner@example.test", [_connection()])
    assert "Can send and delete" in writable

    read_only = _connection(accounts=[{
        "account_id": "box_1", "address": "ada@example.test", "imap": "i", "smtp": "s",
        "auth": "password", "sends_as": ["ada@example.test"], "read_only": True,
        "is_default": True,
    }])
    assert "Read only" in ui.connectors_page("owner@example.test", [read_only])


def test_connectors_page_shows_last_use_and_flags_an_unfinished_connector():
    assert "3 minutes ago" in ui.connectors_page("owner@example.test", [_connection()])
    empty = ui.connectors_page("owner@example.test", [_connection(accounts=[])])
    assert "no mailbox and no calendar" in empty


def test_the_home_page_is_a_dashboard():
    html = _home([_connection()])
    for expected in (
        "Calls, last 24 hours", "Success rate", "Typical response",
        "Calls per day, last 14 days", "Most used tools", "Busiest accounts",
        "Needs attention", "Latest calls", "Manage connectors",
    ):
        assert expected in html, expected
    assert "IMAP login rejected" in html  # the failure is shown, with its reason
    assert 'aria-current="page">Dashboard' in html


def test_the_dashboard_names_what_each_connector_needs():
    html = _home([_connection(label="Empty", accounts=[])])
    assert "Not finished" in html and "Attach a mailbox or a calendar" in html
    assert "/connections/con_1" in html


def test_the_dashboard_warns_about_open_sign_up_only_when_it_is_open():
    assert "MAIL_ONBOARD_CODE" in _home([_connection()], open_registration=True)
    assert "MAIL_ONBOARD_CODE" not in _home([_connection()], open_registration=False)


def test_a_first_visit_gets_a_guided_start():
    html = _home([])
    assert "Get started" in html and 'action="/connections/new"' in html


def test_dashboard_values_are_escaped():
    html = _home([_connection(label="<img src=x onerror=alert(1)>")])
    assert "<img src=x" not in html


def test_connectors_page_without_connectors_explains_what_one_is():
    html = ui.connectors_page("owner@example.test", [])
    assert "No connector yet" in html
    assert "one connection for one agent" in html


def test_mailbox_form_has_the_fields_the_script_reads():
    html = ui.mailbox_form_page(_connection())
    for field in (
        "address", "secret", "imap_host", "imap_port", "imap_security",
        "smtp_host", "smtp_port", "smtp_security", "auth", "verify_ssl",
        "oauth_provider", "oauth_client_id", "from_address", "aliases", "read_only",
    ):
        assert f'id="{field}"' in html, field
    assert 'data-action="detect"' in html
    assert 'data-action="test-mailbox"' in html


def test_the_secret_input_is_a_sibling_of_its_label():
    """The script retitles the label; an input inside it would be destroyed."""
    html = ui.mailbox_form_page(_connection())
    label = re.search(r'<label for="secret" id="secret_label">.*?</label>', html, re.S)
    assert label is not None
    assert "<input" not in label.group(0)
    assert 'id="secret_label_text"' in label.group(0)


def test_read_only_is_not_buried_in_advanced():
    for html in (ui.mailbox_form_page(_connection()), ui.calendar_form_page(_connection())):
        scope = re.search(r'<fieldset class="scope">.*?</fieldset>', html, re.S).group(0)
        assert 'id="read_only"' in scope
        advanced = re.search(r"<details.*?</details>", html, re.S)
        assert advanced is None or 'id="read_only"' not in advanced.group(0)


@pytest.mark.parametrize(
    "page_function", [ui.mailbox_form_page, ui.calendar_form_page]
)
def test_forms_give_back_what_was_typed_except_the_password(page_function):
    typed = {
        "address": "ada@example.test",
        "imap_host": "imap.example.test",
        "smtp_host": "smtp.example.test",
        "url": "https://dav.example.test",
        "timezone": "America/Chicago",
        "read_only": "1",
        "secret": "hunter2",
    }
    html = page_function(_connection(), error="Login rejected.", values=typed)
    assert "ada@example.test" in html
    assert "Login rejected." in html
    assert 'name="read_only" value="1" checked' in html
    assert "hunter2" not in html
    assert "type it again" in html


def test_calendar_form_does_not_preselect_a_timezone():
    """A prefilled Europe/Paris silently books a Chicago user three hours off."""
    html = ui.calendar_form_page(_connection())
    timezone_input = re.search(r'<input id="timezone"[^>]*>', html).group(0)
    assert 'value=""' in timezone_input
    assert "placeholder=" in timezone_input


def test_credentials_page_is_repeatable_and_copyable():
    html = ui.credentials_page("https://gateway.test", _connection(), "s3cr3t")
    assert "s3cr3t" in html
    assert "https://gateway.test/mcp" in html
    assert 'data-action="copy"' in html
    assert "come back to this page" in html
    assert "not shown again" not in html


def test_confirm_page_carries_the_fields_and_says_what_happens():
    html = ui.confirm_page(
        title="Delete this connector",
        question="Delete 'Work'?",
        detail="Any agent connected through it loses access immediately.",
        action="/connections/delete",
        fields={"connection_id": "con_1"},
        confirm_label="Delete connector",
    )
    assert 'name="confirm" value="yes"' in html
    assert 'name="connection_id" value="con_1"' in html
    assert 'action="/connections/delete"' in html
    assert "loses access immediately" in html
    assert "Cancel, keep it" in html


def test_account_page_warns_while_there_is_only_one_passkey():
    single = ui.account_page("owner@example.test", [{
        "credential_id": "abc", "short_id": "abc...", "created_at": 1790000000,
        "added": "2026-09-22 16:00 UTC", "last_used": "never",
    }])
    assert "only passkey" in single
    assert "Add a passkey" in single

    two = ui.account_page("owner@example.test", [
        {"credential_id": "a", "short_id": "a...", "created_at": 1, "added": "x", "last_used": "never"},
        {"credential_id": "b", "short_id": "b...", "created_at": 2, "added": "y", "last_used": "never"},
    ])
    assert "only passkey" not in two
    assert two.count("Remove") >= 2


def test_logs_page_distinguishes_empty_from_filtered_out():
    common = dict(
        connections=[("con_1", "Work")],
        stats={"total": 0, "errors": 0, "last_24h": 0, "tools": [], "accounts": []},
        limit=100,
    )
    nothing = ui.logs_page("o@x.test", [], filters={}, filtered=False, **common)
    assert "Nothing recorded yet" in nothing

    filtered = ui.logs_page(
        "o@x.test", [], filters={"tool": "send_message"}, filtered=True,
        **{**common, "stats": {"total": 9, "errors": 0, "last_24h": 0, "tools": [], "accounts": []}},
    )
    assert "No call matches these filters" in filtered
    assert "Clear filters" in filtered


def test_log_filters_do_not_submit_on_change():
    html = ui.logs_page(
        "o@x.test", [], connections=[], stats={"total": 0, "errors": 0, "last_24h": 0,
        "tools": [], "accounts": []}, filters={}, limit=50,
    )
    assert "this.form.submit()" not in html
    assert "Apply" in html
