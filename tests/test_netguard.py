"""The gateway does not connect to private addresses on a user's behalf."""

from __future__ import annotations

import httpx
import pytest

from mail_mcp import discovery, netguard
from mail_mcp.accounts import MailAccount
from mail_mcp.caldav_client import CalDavClient, CalDavError
from mail_mcp.calendars import CalendarAccount
from mail_mcp.imap_client import ImapClient, ImapError
from mail_mcp.smtp_client import SmtpError
from mail_mcp.smtp_client import check as smtp_check


@pytest.fixture
def guarded(monkeypatch):
    monkeypatch.setenv("MAIL_MULTITENANT", "1")
    monkeypatch.delenv(netguard.ALLOW_ENV, raising=False)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.7", "172.17.0.1", "192.168.1.10", "169.254.169.254",
     "100.64.0.1", "::1", "fd00::1", "::ffff:127.0.0.1", "0.0.0.0"],
)
def test_private_and_local_addresses_are_forbidden(address):
    assert netguard.forbidden_address(address)


def test_public_addresses_are_not():
    assert not netguard.forbidden_address("17.253.144.10")
    assert not netguard.forbidden_address("2a01:4f8::1")


def test_localhost_by_name_is_refused(guarded):
    with pytest.raises(netguard.TargetError, match="MAIL_ALLOW_PRIVATE_TARGETS"):
        netguard.check_host("localhost")


def test_the_operator_can_allow_private_targets(monkeypatch):
    monkeypatch.setenv("MAIL_MULTITENANT", "1")
    monkeypatch.setenv(netguard.ALLOW_ENV, "1")
    netguard.check_host("127.0.0.1")


def test_single_mailbox_mode_is_not_guarded(monkeypatch):
    monkeypatch.delenv("MAIL_MULTITENANT", raising=False)
    monkeypatch.delenv(netguard.ALLOW_ENV, raising=False)
    netguard.check_host("127.0.0.1")


async def test_imap_to_a_private_host_is_refused_before_connecting(guarded):
    account = MailAccount(
        address="a@b.example", imap_host="127.0.0.1", imap_port=6379,
        imap_security="none", smtp_host="smtp.b.example", secret="p",
    )
    client = ImapClient(account)
    with pytest.raises(ImapError, match="local or private address"):
        await client.check()
    await client.close()


async def test_smtp_to_a_private_host_is_refused(guarded):
    account = MailAccount(
        address="a@b.example", imap_host="imap.b.example", smtp_host="10.0.0.7",
        smtp_port=25, smtp_security="none", secret="p",
    )
    with pytest.raises(SmtpError, match="local or private address"):
        await smtp_check(account)


async def test_caldav_to_the_metadata_service_is_refused(guarded):
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    account = CalendarAccount(
        address="a@b.example", url="https://169.254.169.254/latest/", secret="p"
    )
    client = CalDavClient(account, transport=httpx.MockTransport(answer))
    with pytest.raises(CalDavError, match="local or private address"):
        await client.check()
    await client.close()
    assert seen == [], "a request left before the check"


async def test_a_redirect_to_a_private_host_is_refused(guarded):
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(301, headers={"Location": "https://10.0.0.7/dav/"})

    account = CalendarAccount(
        address="a@b.example", url="https://203.0.113.10/dav/", secret="p"
    )
    client = CalDavClient(account, transport=httpx.MockTransport(answer))
    with pytest.raises(CalDavError, match="local or private address"):
        await client.check()
    await client.close()
    assert "10.0.0.7" not in seen


@pytest.mark.parametrize(
    "address",
    ["x@127.0.0.1:8443", "x@internal/../admin", "x@[::1]", "x@exa mple.com", "x@"],
)
async def test_discovery_only_takes_a_domain_name(address, monkeypatch):
    async def fail(*_args, **_kwargs):
        raise AssertionError("an HTTP request was made")

    monkeypatch.setattr(httpx.AsyncClient, "get", fail)
    assert await discovery.discover(address) is None
