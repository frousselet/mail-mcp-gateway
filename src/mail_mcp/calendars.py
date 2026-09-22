"""Calendar account configuration.

A *calendar account* is one CalDAV login: a server, a username and a password.
Like mailboxes, calendars belong to a connection, so one MCP connector can
serve an agent both the mail and the calendars of the same person, or of
several people.

Apple iCloud is the case this was written against: the same Apple ID and
app-specific password that unlock iCloud Mail over IMAP unlock iCloud Calendar
over CalDAV. Any other CalDAV server (Fastmail, Nextcloud, Radicale, a company
Exchange with its CalDAV bridge) works the same way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_ADDRESS_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Servers that need no URL: discovery starts from this well-known host.
CALDAV_PRESETS: dict[str, str] = {
    "icloud.com": "https://caldav.icloud.com",
    "me.com": "https://caldav.icloud.com",
    "mac.com": "https://caldav.icloud.com",
    "fastmail.com": "https://caldav.fastmail.com",
    "gmail.com": "https://apidata.googleusercontent.com/caldav/v2",
}


class CalendarConfigError(ValueError):
    """Raised when a calendar account is incomplete or inconsistent."""


@dataclass
class CalendarAccount:
    """Everything needed to read and write one person's calendars."""

    address: str  # the account identity, usually an email address
    account_id: str = ""
    label: str = ""

    url: str = ""  # CalDAV entry point; discovered when left empty
    username: str = ""
    secret: str = ""

    verify_ssl: bool = True
    read_only: bool = False
    timeout: float = 30.0

    default_calendar: str = ""  # display name or href of the preferred calendar
    timezone: str = "UTC"  # how to read times given without an offset
    created_at: int = 0
    discovered_home: str = ""  # calendar-home-set, cached after discovery

    def __post_init__(self) -> None:
        self.address = self.address.strip()
        self.username = (self.username or self.address).strip()
        self.label = self.label.strip() or self.address
        self.url = self.url.strip().rstrip("/")

    def validate(self) -> None:
        """Raise :class:`CalendarConfigError` if the account cannot be used."""
        if not self.address:
            raise CalendarConfigError("An account identity (email address) is required.")
        if not _ADDRESS_RE.match(self.address) and not self.url:
            raise CalendarConfigError(
                f"{self.address!r} is not an email address, so a CalDAV URL is required."
            )
        if not self.secret:
            raise CalendarConfigError(
                "A password is required (an app-specific password on iCloud)."
            )
        url = self.entry_point()
        if not url:
            raise CalendarConfigError(
                "No CalDAV server known for this domain. Enter the server URL."
            )
        if not url.startswith(("http://", "https://")):
            raise CalendarConfigError("The CalDAV URL must start with https://.")
        try:
            ZoneInfo(self.timezone or "UTC")
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise CalendarConfigError(
                f"{self.timezone!r} is not a known timezone (use e.g. Europe/Paris)."
            ) from e

    def entry_point(self) -> str:
        """Where discovery starts: the given URL, or the provider's known host."""
        if self.url:
            return self.url
        domain = self.address.rpartition("@")[2].lower()
        return CALDAV_PRESETS.get(domain, "")

    def matches(self, selector: str) -> bool:
        wanted = selector.strip().lower()
        return wanted in {self.account_id.lower(), self.address.lower(), self.label.lower()} - {""}

    # --- serialisation (secrets handled by the store) ---

    def to_record(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in self.__dict__.items()
            if not key.startswith("_") and key != "secret"
        }

    @classmethod
    def from_record(cls, record: dict[str, Any], secret: str = "") -> CalendarAccount:
        known = set(cls.__dataclass_fields__)
        kwargs = {k: v for k, v in record.items() if k in known}
        kwargs["secret"] = secret
        return cls(**kwargs)

    def public_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "address": self.address,
            "label": self.label,
            "url": self.entry_point(),
            "read_only": self.read_only,
            "default_calendar": self.default_calendar,
            "timezone": self.timezone,
        }


@dataclass
class CalendarSet:
    """The calendar accounts served by one connection."""

    accounts: list[CalendarAccount] = field(default_factory=list)
    default_account_id: str = ""

    def __len__(self) -> int:
        return len(self.accounts)

    def __iter__(self):
        return iter(self.accounts)

    def resolve(self, selector: str | None = None) -> CalendarAccount:
        if not self.accounts:
            raise CalendarConfigError(
                "This connection has no calendar yet. Add one in the web UI first."
            )
        if selector:
            for account in self.accounts:
                if account.matches(selector):
                    return account
            known = ", ".join(a.address for a in self.accounts)
            raise CalendarConfigError(
                f"No calendar account matches {selector!r}. Available: {known}."
            )
        if self.default_account_id:
            for account in self.accounts:
                if account.account_id == self.default_account_id:
                    return account
        return self.accounts[0]
