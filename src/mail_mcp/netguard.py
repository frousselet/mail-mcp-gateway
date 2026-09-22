"""Where the gateway may connect on somebody else's say-so.

In multi-user mode anyone who can sign in types a host name into a form, and
the gateway connects to it: IMAP, SMTP, CalDAV, autoconfig. Without a rule,
that turns the gateway into a way to reach what sits next to it (the Docker
network, a cloud metadata service, a database on localhost) and to read back
what those answer.

The rule: a host that resolves to a loopback, private, link-local, shared,
multicast or reserved address is refused. It is checked when the connection is
made, not only when the form is saved, and on every redirect hop. An operator
whose mail server really is on the local network sets
``MAIL_ALLOW_PRIVATE_TARGETS=1``.

Single-mailbox mode is not guarded: there the operator typed the host into the
environment themselves.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit

ALLOW_ENV = "MAIL_ALLOW_PRIVATE_TARGETS"

# Not all of these are flagged ``is_private`` by every Python version.
_ALSO_FORBIDDEN = (
    ipaddress.ip_network("100.64.0.0/10"),  # shared address space (CGNAT)
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("fc00::/7"),
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


class TargetError(ValueError):
    """Raised when a host is one the gateway will not connect to."""


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def enforced() -> bool:
    return _truthy("MAIL_MULTITENANT") and not _truthy(ALLOW_ENV)


def forbidden_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or any(ip in network for network in _ALSO_FORBIDDEN if network.version == ip.version)
    )


def check_host(host: str) -> None:
    """Refuse ``host`` if it resolves to an address the gateway must not reach.

    Blocking (it resolves the name): call it from a worker thread, or through
    :func:`acheck_host`. A name that does not resolve is let through: the
    connection that follows fails on its own, with a clearer message.
    """
    if not enforced() or not host:
        return
    name = host.strip().strip("[]").rstrip(".")
    if name.lower() == "localhost" or name.lower().endswith(".localhost"):
        raise TargetError(_refusal(host, "localhost"))
    if forbidden_address(name):
        raise TargetError(_refusal(host, name))
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return
    for info in infos:
        address = str(info[4][0])
        if forbidden_address(address):
            raise TargetError(_refusal(host, address))


async def acheck_host(host: str) -> None:
    import asyncio

    await asyncio.to_thread(check_host, host)


def check_url(url: str) -> None:
    check_host(urlsplit(url).hostname or "")


def valid_domain(domain: str) -> bool:
    """A plain DNS name: no port, path, credentials, spaces or bare IP."""
    return bool(_HOSTNAME_RE.match(domain or ""))


def _refusal(host: str, address: str) -> str:
    return (
        f"{host} points to a local or private address ({address}). This gateway "
        "does not connect to those on a user's behalf; its operator can allow it "
        f"with {ALLOW_ENV}=1."
    )
