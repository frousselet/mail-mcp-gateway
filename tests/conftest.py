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
