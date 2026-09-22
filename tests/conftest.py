"""Shared fixtures.

The multi-user flag and the store path are set before anything imports
``mail_mcp.server``: that module decides at import time whether the MCP
endpoint is OAuth-protected, and the store is created with it. Tests that want
the single-mailbox path flip ``server._MULTITENANT`` at runtime instead.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ["MAIL_MULTITENANT"] = "1"
# The fake servers listen on 127.0.0.1, which multi-user mode refuses by
# default; the tests of that refusal turn this off for themselves.
os.environ["MAIL_ALLOW_PRIVATE_TARGETS"] = "1"
os.environ.setdefault("MAIL_LOG_LEVEL", "WARNING")
_TEST_DATA = Path(tempfile.mkdtemp(prefix="mail-mcp-tests-"))
os.environ["MAIL_STORE"] = str(_TEST_DATA / "store.json")

import httpx  # noqa: E402
import pytest  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))

from fake_imap import FakeIMAPServer  # noqa: E402

from mail_mcp.accounts import MailAccount  # noqa: E402


@pytest.fixture
def imap_server():
    with FakeIMAPServer() as server:
        yield server


@pytest.fixture
def account(imap_server) -> MailAccount:
    return MailAccount(
        address=imap_server.state.username,
        account_id="box_test",
        imap_host=imap_server.host,
        imap_port=imap_server.port,
        imap_security="none",
        smtp_host="127.0.0.1",
        smtp_port=1,
        smtp_security="none",
        secret=imap_server.state.password,
        verify_ssl=False,
        timeout=10,
    )


@pytest.fixture
def store_path(tmp_path, monkeypatch) -> str:
    """A throwaway store file for tests that build their own store."""
    monkeypatch.delenv("MAIL_SECRET_KEY", raising=False)
    return str(tmp_path / "store.json")


@pytest.fixture(autouse=True)
def _no_real_credentials(monkeypatch):
    """Never let an ambient mailbox configuration leak into a test."""
    for name in ("MAIL_ADDRESS", "MAIL_PASSWORD", "MAIL_ACCOUNTS_FILE"):
        monkeypatch.delenv(name, raising=False)


def session_csrf(client: httpx.AsyncClient) -> str:
    """The anti-forgery token in a client's session cookie.

    Starlette's session cookie is signed, not encrypted: its first segment is
    the base64 JSON of the session, which is all a test needs to read.
    """
    import base64
    import json

    cookie = client.cookies.get("mail_mcp_session") or ""
    payload = cookie.split(".")[0]
    if not payload:
        return ""
    data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
    return data.get("csrf", "")


class FormClient(httpx.AsyncClient):
    """A test client that fills in the form token, as the pages do.

    Every form the UI renders carries it; tests that post forms by hand get it
    added here, and the tests of the check itself pass ``csrf`` explicitly.
    """

    async def post(self, url, *args, data=None, **kwargs):
        if isinstance(data, dict) and "csrf" not in data:
            if not session_csrf(self):
                await self.get("/assets/app.css")
            data = {**data, "csrf": session_csrf(self)}
        return await super().post(url, *args, data=data, **kwargs)


@pytest.fixture(autouse=True)
def _fresh_probe_budget():
    """Each test starts with a full allowance of connection tests."""
    web = sys.modules.get("mail_mcp.web")
    if web is not None:
        web._probe_log.clear()
    yield
