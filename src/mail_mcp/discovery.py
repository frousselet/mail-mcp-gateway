"""Find the IMAP/SMTP settings for an email address.

Server settings are *discovered*, not guessed: the lookup order follows what
mail clients do, so a freshly typed address usually needs no manual input.

1. A small table of well-known providers (instant, offline).
2. The Mozilla ISPDB (``autoconfig.thunderbird.net``), the database Thunderbird
   ships with: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
3. The domain's own autoconfig endpoints, as defined by the same spec:
   ``https://autoconfig.<domain>/mail/config-v1.1.xml`` and
   ``https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml``.

Anything found is only a starting point: the web UI shows the settings, lets
the user edit every field, and tests them against the real servers before the
mailbox is saved.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import httpx

from mail_mcp.accounts import SECURITY_NONE, SECURITY_SSL, SECURITY_STARTTLS

logger = logging.getLogger("mail-mcp.discovery")

ISPDB_URL = "https://autoconfig.thunderbird.net/v1.1/{domain}"
DOMAIN_AUTOCONFIG_URLS = (
    "https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}",
    "https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={email}",
)


@dataclass
class ServerSettings:
    """Discovered (or hand-written) settings for one mailbox."""

    imap_host: str = ""
    imap_port: int = 993
    imap_security: str = SECURITY_SSL
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = SECURITY_STARTTLS
    username_is_address: bool = True
    source: str = ""
    provider_name: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "imap_host": self.imap_host,
            "imap_port": self.imap_port,
            "imap_security": self.imap_security,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_security": self.smtp_security,
            "username_is_address": self.username_is_address,
            "source": self.source,
            "provider_name": self.provider_name,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Offline presets
# ---------------------------------------------------------------------------
# Kept deliberately short: the ISPDB above covers thousands of domains and is
# maintained upstream. These few are here so the common cases resolve without a
# network round-trip, and each is re-checked by the connection test anyway.

_PRESETS: dict[str, ServerSettings] = {
    "gmail.com": ServerSettings(
        "imap.gmail.com", 993, SECURITY_SSL, "smtp.gmail.com", 587, SECURITY_STARTTLS,
        provider_name="Gmail",
        notes=["Gmail rejects your normal password: create an App Password "
               "(Google Account > Security > 2-Step Verification > App passwords), "
               "or use XOAUTH2."],
    ),
    "googlemail.com": ServerSettings(
        "imap.gmail.com", 993, SECURITY_SSL, "smtp.gmail.com", 587, SECURITY_STARTTLS,
        provider_name="Gmail",
    ),
    "outlook.com": ServerSettings(
        "outlook.office365.com", 993, SECURITY_SSL,
        "smtp.office365.com", 587, SECURITY_STARTTLS,
        provider_name="Outlook / Microsoft 365",
        notes=["Microsoft disabled password (basic) auth for most tenants: use "
               "XOAUTH2 unless your tenant still allows app passwords."],
    ),
    "hotmail.com": ServerSettings(
        "outlook.office365.com", 993, SECURITY_SSL,
        "smtp.office365.com", 587, SECURITY_STARTTLS,
        provider_name="Outlook / Microsoft 365",
    ),
    "icloud.com": ServerSettings(
        "imap.mail.me.com", 993, SECURITY_SSL,
        "smtp.mail.me.com", 587, SECURITY_STARTTLS,
        provider_name="iCloud Mail",
        notes=["iCloud requires an app-specific password (appleid.apple.com)."],
    ),
    "me.com": ServerSettings(
        "imap.mail.me.com", 993, SECURITY_SSL,
        "smtp.mail.me.com", 587, SECURITY_STARTTLS,
        provider_name="iCloud Mail",
    ),
    "fastmail.com": ServerSettings(
        "imap.fastmail.com", 993, SECURITY_SSL,
        "smtp.fastmail.com", 465, SECURITY_SSL,
        provider_name="Fastmail",
        notes=["Fastmail requires an app password with the Mail scope."],
    ),
    "yahoo.com": ServerSettings(
        "imap.mail.yahoo.com", 993, SECURITY_SSL,
        "smtp.mail.yahoo.com", 465, SECURITY_SSL,
        provider_name="Yahoo Mail",
        notes=["Yahoo requires a generated app password."],
    ),
    # Proton Mail is only reachable through the local Proton Mail Bridge, which
    # listens on 127.0.0.1 with a self-signed certificate.
    "proton.me": ServerSettings(
        "127.0.0.1", 1143, SECURITY_STARTTLS, "127.0.0.1", 1025, SECURITY_STARTTLS,
        provider_name="Proton Mail Bridge",
        notes=["Requires Proton Mail Bridge running on the same host; use the "
               "bridge-generated password and turn certificate verification off."],
    ),
    "protonmail.com": ServerSettings(
        "127.0.0.1", 1143, SECURITY_STARTTLS, "127.0.0.1", 1025, SECURITY_STARTTLS,
        provider_name="Proton Mail Bridge",
    ),
}


def preset_for(domain: str) -> ServerSettings | None:
    preset = _PRESETS.get(domain.lower())
    if preset is None:
        return None
    # Return a copy so callers can edit freely.
    copy = ServerSettings(**{**preset.as_dict(), "notes": list(preset.notes)})
    copy.source = "preset"
    return copy


# ---------------------------------------------------------------------------
# Thunderbird autoconfig XML
# ---------------------------------------------------------------------------


def _socket_type(value: str | None) -> str:
    mapping = {
        "ssl": SECURITY_SSL,
        "starttls": SECURITY_STARTTLS,
        "plain": SECURITY_NONE,
        "none": SECURITY_NONE,
    }
    return mapping.get((value or "").strip().lower(), SECURITY_SSL)


def parse_autoconfig(xml_text: str, source: str = "autoconfig") -> ServerSettings | None:
    """Parse a Thunderbird ``clientConfig`` document into settings.

    Only IMAP incoming servers are considered (POP3 cannot back the tools this
    gateway exposes). The first SMTP outgoing server wins.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.debug("autoconfig parse error: %s", e)
        return None

    settings = ServerSettings(source=source)
    provider = root.find(".//emailProvider")
    if provider is not None:
        settings.provider_name = (provider.findtext("displayName") or "").strip()

    for node in root.iter("incomingServer"):
        if (node.get("type") or "").lower() != "imap":
            continue
        host = (node.findtext("hostname") or "").strip()
        if not host:
            continue
        settings.imap_host = host
        settings.imap_port = int(node.findtext("port") or 993)
        settings.imap_security = _socket_type(node.findtext("socketType"))
        username = (node.findtext("username") or "%EMAILADDRESS%").strip()
        settings.username_is_address = username != "%EMAILLOCALPART%"
        break

    for node in root.iter("outgoingServer"):
        host = (node.findtext("hostname") or "").strip()
        if not host:
            continue
        settings.smtp_host = host
        settings.smtp_port = int(node.findtext("port") or 587)
        settings.smtp_security = _socket_type(node.findtext("socketType"))
        break

    if not settings.imap_host:
        return None
    if not settings.smtp_host:
        settings.notes.append(
            "The provider published no SMTP server; fill the outgoing server in by hand."
        )
    return settings


async def discover(email: str, timeout: float = 6.0) -> ServerSettings | None:
    """Look up settings for ``email``; returns ``None`` when nothing is found."""
    address = email.strip()
    domain = address.rpartition("@")[2].lower()
    if not domain:
        return None

    preset = preset_for(domain)
    if preset is not None:
        return preset

    urls = [ISPDB_URL.format(domain=domain)] + [
        url.format(domain=domain, email=address) for url in DOMAIN_AUTOCONFIG_URLS
    ]
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls:
            try:
                response = await client.get(url)
            except httpx.HTTPError as e:
                logger.debug("autoconfig lookup failed for %s: %s", url, e)
                continue
            if response.status_code != 200 or not response.text.strip():
                continue
            source = "ispdb" if "thunderbird.net" in url else "domain-autoconfig"
            settings = parse_autoconfig(response.text, source=source)
            if settings is not None:
                logger.info("Discovered settings for %s via %s", domain, source)
                return settings
    return None
