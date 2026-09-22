"""Mail account configuration.

A *mail account* is one mailbox: an address, an IMAP server to read it and an
SMTP server to send from it. Accounts are grouped into *connections* (see
:mod:`mail_mcp.store`); one connection is exposed to an agent as one MCP
connector, so a connector can serve a single address or several at once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Transport security for a mail server socket.
SECURITY_SSL = "ssl"  # implicit TLS (IMAPS 993 / SMTPS 465)
SECURITY_STARTTLS = "starttls"  # explicit TLS (IMAP 143 / submission 587)
SECURITY_NONE = "none"  # plaintext, only sane for localhost bridges
SECURITY_CHOICES = (SECURITY_SSL, SECURITY_STARTTLS, SECURITY_NONE)

AUTH_PASSWORD = "password"
AUTH_XOAUTH2 = "xoauth2"
AUTH_CHOICES = (AUTH_PASSWORD, AUTH_XOAUTH2)

_ADDRESS_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AccountConfigError(ValueError):
    """Raised when an account configuration is incomplete or inconsistent."""


@dataclass
class MailAccount:
    """Everything needed to read and send mail for one address.

    ``secret`` holds the password (``auth="password"``) or the OAuth 2 refresh
    token (``auth="xoauth2"``). It is only ever kept in memory here; the store
    encrypts it at rest.
    """

    address: str
    account_id: str = ""
    label: str = ""
    from_name: str = ""
    # The address mail goes out as, when it differs from the login address.
    # iCloud+ custom domains are the usual case: you authenticate as your Apple
    # ID but write as you@yourdomain.
    from_address: str = ""
    # Other addresses this mailbox is allowed to send as (aliases, domain
    # addresses). A tool may pick any of these; anything else is refused.
    aliases: list[str] = field(default_factory=list)

    imap_host: str = ""
    imap_port: int = 993
    imap_security: str = SECURITY_SSL
    imap_username: str = ""

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = SECURITY_STARTTLS
    smtp_username: str = ""

    auth: str = AUTH_PASSWORD
    secret: str = ""

    # XOAUTH2 only: how to turn the stored refresh token into an access token.
    oauth_provider: str = ""  # "google" | "microsoft"
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_tenant: str = "common"  # Microsoft directory tenant

    verify_ssl: bool = True
    read_only: bool = False
    timeout: float = 30.0

    # Optional overrides; empty means "detect via SPECIAL-USE, then by name".
    sent_folder: str = ""
    drafts_folder: str = ""
    trash_folder: str = ""
    junk_folder: str = ""
    archive_folder: str = ""

    created_at: int = 0
    settings_source: str = ""  # how the server settings were found

    def __post_init__(self) -> None:
        self.address = self.address.strip()
        self.imap_username = (self.imap_username or self.address).strip()
        self.smtp_username = (self.smtp_username or self.address).strip()
        self.label = self.label.strip() or self.address
        self.from_address = self.from_address.strip()
        if isinstance(self.aliases, str):
            self.aliases = [
                part.strip()
                for part in self.aliases.replace(";", ",").replace("\n", ",").split(",")
            ]
        self.aliases = [alias.strip() for alias in self.aliases if alias and alias.strip()]

    # --- validation ---

    def validate(self) -> None:
        """Raise :class:`AccountConfigError` if the account cannot be used."""
        if not _ADDRESS_RE.match(self.address):
            raise AccountConfigError(f"{self.address!r} is not a valid email address.")
        if not self.imap_host:
            raise AccountConfigError("An IMAP host is required.")
        if not self.smtp_host:
            raise AccountConfigError("An SMTP host is required.")
        for name, value in (("IMAP", self.imap_security), ("SMTP", self.smtp_security)):
            if value not in SECURITY_CHOICES:
                raise AccountConfigError(
                    f"{name} security must be one of {', '.join(SECURITY_CHOICES)}."
                )
        if self.auth not in AUTH_CHOICES:
            raise AccountConfigError(f"auth must be one of {', '.join(AUTH_CHOICES)}.")
        if not self.secret:
            what = "password" if self.auth == AUTH_PASSWORD else "refresh token"
            raise AccountConfigError(f"A {what} is required.")
        if self.auth == AUTH_XOAUTH2:
            if self.oauth_provider not in ("google", "microsoft"):
                raise AccountConfigError(
                    "XOAUTH2 requires oauth_provider to be 'google' or 'microsoft'."
                )
            if not self.oauth_client_id:
                raise AccountConfigError("XOAUTH2 requires an OAuth client ID.")
        for port, name in ((self.imap_port, "IMAP"), (self.smtp_port, "SMTP")):
            if not 1 <= int(port) <= 65535:
                raise AccountConfigError(f"{name} port must be between 1 and 65535.")

    # --- identity ---

    def matches(self, selector: str) -> bool:
        """True when ``selector`` names this account (id, address or label)."""
        s = selector.strip().lower()
        return s in {
            self.account_id.lower(),
            self.address.lower(),
            self.label.lower(),
        } - {""}

    def default_sender(self) -> str:
        """The bare address mail goes out as unless a tool asks for another."""
        return self.from_address or self.address

    def sending_identities(self) -> list[str]:
        """Every address this mailbox may send as, default first."""
        out: list[str] = []
        for candidate in [self.default_sender(), self.address, *self.aliases]:
            cleaned = candidate.strip()
            if cleaned and cleaned.lower() not in {o.lower() for o in out}:
                out.append(cleaned)
        return out

    def resolve_sender(self, selector: str | None = None) -> str:
        """Check a requested From address against what this mailbox may use.

        Refusing an unknown address is the point: an agent acting on a message
        it just read must not be able to send as someone else.
        """
        identities = self.sending_identities()
        if not selector:
            return identities[0]
        wanted = selector.strip()
        bare = wanted.rpartition("<")[2].rstrip(">").strip() or wanted
        for identity in identities:
            if identity.lower() == bare.lower():
                return identity
        raise AccountConfigError(
            f"{selector!r} is not an address {self.address} may send as. "
            f"Allowed: {', '.join(identities)}. Add it to the mailbox's sending "
            "addresses in the web UI if it should be."
        )

    def sender(self, from_address: str | None = None) -> str:
        """The ``From`` header value, with a display name when one is set."""
        address = self.resolve_sender(from_address)
        if self.from_name:
            return f"{self.from_name} <{address}>"
        return address

    # --- serialisation (secrets handled by the store) ---

    def to_record(self) -> dict[str, Any]:
        record = {
            k: v
            for k, v in self.__dict__.items()
            # Both credentials are sealed by the store, never written as is.
            if not k.startswith("_") and k not in ("secret", "oauth_client_secret")
        }
        return record

    @classmethod
    def from_record(cls, record: dict[str, Any], secret: str = "") -> MailAccount:
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in record.items() if k in known}
        kwargs["secret"] = secret
        return cls(**kwargs)

    def public_dict(self) -> dict[str, Any]:
        """Non-secret view, safe to show in the UI or return from a tool."""
        return {
            "account_id": self.account_id,
            "address": self.address,
            "label": self.label,
            "from_name": self.from_name,
            "imap": f"{self.imap_host}:{self.imap_port} ({self.imap_security})",
            "smtp": f"{self.smtp_host}:{self.smtp_port} ({self.smtp_security})",
            "auth": self.auth,
            "sends_as": self.sending_identities(),
            "read_only": self.read_only,
            "settings_source": self.settings_source,
        }


@dataclass
class AccountSet:
    """The accounts served by one connection, with a default for bare calls."""

    accounts: list[MailAccount] = field(default_factory=list)
    default_account_id: str = ""

    def __len__(self) -> int:
        return len(self.accounts)

    def __iter__(self):
        return iter(self.accounts)

    def resolve(self, selector: str | None = None) -> MailAccount:
        """Find the account a tool call is about.

        No selector: the connection's default account (or the only one). A
        selector matches an account id, address or label, case-insensitively.
        """
        if not self.accounts:
            raise AccountConfigError(
                "This connection has no mailbox yet. Add one in the web UI first."
            )
        if selector:
            for account in self.accounts:
                if account.matches(selector):
                    return account
            known = ", ".join(a.address for a in self.accounts)
            raise AccountConfigError(
                f"No mailbox matches {selector!r}. Available: {known}."
            )
        if self.default_account_id:
            for account in self.accounts:
                if account.account_id == self.default_account_id:
                    return account
        return self.accounts[0]
