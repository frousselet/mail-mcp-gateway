"""Encrypted store for users, MCP connections, mailboxes and OAuth state.

Vocabulary:

- a **user** signs in to the web UI with a passkey and owns connections;
- a **connection** is one MCP connector: an OAuth client (``client_id`` /
  ``client_secret``) that an agent uses against the shared ``/mcp`` endpoint;
- a connection serves one or more **mailboxes** (:class:`~mail_mcp.accounts.MailAccount`)
  and any number of **calendar accounts**
  (:class:`~mail_mcp.calendars.CalendarAccount`), so one connector can give an
  agent the mail and the calendars of one person, or of several.

Everything lives in one JSON file whose secrets (mailbox passwords, refresh
tokens, OAuth client secrets) are sealed field-by-field with Fernet. Bearer
secrets (access/refresh tokens, authorization codes) are stored as SHA-256
hashes only. A file plus an in-process lock is enough for a self-hosted,
single-process deployment; swap in a database to scale out.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from mail_mcp.accounts import AccountSet, MailAccount
from mail_mcp.calendars import CalendarAccount, CalendarSet

logger = logging.getLogger("mail-mcp.store")

DEFAULT_STORE_PATH = "/data/mail_connections.json"
MAX_CODES_PER_CLIENT = 20


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def _load_fernet(key_path: Path) -> Fernet:
    """Build the cipher used to encrypt secrets at rest.

    1. ``MAIL_SECRET_KEY`` env: a Fernet key, or any passphrase (hashed to one).
    2. Otherwise a key file next to the store, generated on first run so
       ``docker compose up`` needs no configuration yet survives restarts.
    """
    raw = os.environ.get("MAIL_SECRET_KEY", "")
    if raw:
        try:
            return Fernet(raw)
        except (ValueError, TypeError):
            digest = hashlib.sha256(raw.encode()).digest()
            return Fernet(base64.urlsafe_b64encode(digest))

    if key_path.exists():
        return Fernet(key_path.read_bytes().strip())
    key = Fernet.generate_key()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    logger.info(
        "Generated and persisted an encryption key at %s. Keep this file (and the "
        "data volume) safe; set MAIL_SECRET_KEY to override.",
        key_path,
    )
    return Fernet(key)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class Connection:
    """One MCP connector and the mailboxes it serves."""

    connection_id: str
    client_id: str
    client_secret: str  # decrypted in memory
    owner_id: str = ""
    label: str = ""
    default_account_id: str = ""
    accounts: list[MailAccount] = field(default_factory=list)
    calendars: list[CalendarAccount] = field(default_factory=list)
    default_calendar_id: str = ""
    created_at: int = 0
    revision: int = 0

    def account_set(self) -> AccountSet:
        return AccountSet(
            accounts=list(self.accounts), default_account_id=self.default_account_id
        )

    def calendar_set(self) -> CalendarSet:
        return CalendarSet(
            accounts=list(self.calendars), default_account_id=self.default_calendar_id
        )


@dataclass
class OAuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: list[str] = field(default_factory=list)
    expires_at: float = 0.0
    redirect_uri_provided_explicitly: bool = True


@dataclass
class OAuthTokenRecord:
    token: str
    client_id: str
    scopes: list[str] = field(default_factory=list)
    expires_at: float = 0.0


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class ConnectionStore:
    """Encrypted, file-backed store for everything the gateway persists."""

    def __init__(self, path: str | None = None):
        self._path = Path(
            path or os.environ.get("MAIL_STORE", "") or DEFAULT_STORE_PATH
        )
        self._fernet = _load_fernet(self._path.with_name("secret.key"))
        self._lock = asyncio.Lock()
        self._data: dict[str, Any] = {}
        self._load()
        for key in (
            "connections", "users", "credentials", "codes", "tokens", "refresh",
            "settings",
        ):
            self._data.setdefault(key, {})
        self._migrate()

    # --- persistence ---

    def _load(self) -> None:
        if not self._path.exists():
            self._data = {}
            return
        try:
            self._data = json.loads(self._path.read_text())
            return
        except (json.JSONDecodeError, OSError) as e:
            # Starting empty would be fine; the next write silently replacing
            # every stored credential would not. Keep the file that could not
            # be read, under a name nothing will overwrite.
            backup = self._path.with_name(f"{self._path.name}.unreadable-{int(time.time())}")
            try:
                self._path.replace(backup)
                kept = f"It has been kept as {backup.name}."
            except OSError:
                kept = "It could NOT be set aside, so do not restart before copying it."
            logger.error(
                "The store at %s could not be read (%s). Starting with an empty "
                "store; every connector and mailbox will have to be added again. %s",
                self._path,
                e,
                kept,
            )
            self._data = {}

    def _write(self, payload: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(payload)
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        tmp.replace(self._path)

    async def _save(self) -> None:
        """Write the store, off the event loop.

        Called with the lock held, so writes stay in order; the snapshot is
        taken before the thread starts, so a later change cannot tear it.
        """
        payload = json.dumps(self._data, indent=2)
        await asyncio.to_thread(self._write, payload)

    def _migrate(self) -> None:
        """Bring an older store file up to date, once, at start-up."""
        changed = False
        for connection in self._data.get("connections", {}).values():
            for account in connection.get("accounts", {}).values():
                plain = account.pop("oauth_client_secret", None)
                if plain:
                    account["oauth_client_secret_enc"] = self._enc(plain)
                    changed = True
                elif plain is not None:
                    changed = True
        if changed:
            self._write(json.dumps(self._data, indent=2))
            logger.info("Encrypted the OAuth client secrets left in clear in the store.")

    def _enc(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def _dec(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except InvalidToken:
            logger.error(
                "A stored secret could not be decrypted: the encryption key changed. "
                "Re-add the affected mailbox."
            )
            return ""

    def session_secret(self) -> str:
        """A cookie-signing key that survives a restart.

        Derived from the store's own encryption key, which is already generated
        once and persisted, so sessions no longer die on every restart while
        the mailbox passwords survive. It is a separate value, not the key
        itself: signing cookies and encrypting credentials are different jobs.
        """
        material = self._fernet._signing_key + self._fernet._encryption_key
        return hmac.new(material, b"mail-mcp session cookie", hashlib.sha256).hexdigest()

    @staticmethod
    def _hash(token: str) -> str:
        """Hash a bearer secret for storage.

        Tokens and authorization codes are high-entropy random strings, so a
        plain SHA-256 is enough (no salt needed) and the usable secret never
        touches the disk.
        """
        return hashlib.sha256(token.encode()).hexdigest()

    # --- deployment settings ---

    def pinned_origin(self) -> str:
        """The origin passkeys were first used on, when it was not configured."""
        return str(self._data["settings"].get("origin", ""))

    async def pin_origin(self, origin: str) -> None:
        async with self._lock:
            if self._data["settings"].get("origin"):
                return
            self._data["settings"]["origin"] = origin
            await self._save()

    # --- connections ---

    async def create_connection(self, *, owner_id: str, label: str = "") -> Connection:
        async with self._lock:
            connection_id = "con_" + secrets.token_hex(8)
            record = {
                "connection_id": connection_id,
                "client_id": "mail_" + secrets.token_hex(12),
                "client_secret_enc": self._enc(secrets.token_urlsafe(32)),
                "owner_id": owner_id,
                "label": label,
                "default_account_id": "",
                "accounts": {},
                "calendars": {},
                "default_calendar_id": "",
                "created_at": int(time.time()),
                "revision": 0,
            }
            self._data["connections"][connection_id] = record
            await self._save()
            return self._to_connection(record)

    def _to_connection(self, record: dict[str, Any]) -> Connection:
        accounts: list[MailAccount] = []
        for account_record in record.get("accounts", {}).values():
            secret = self._dec(account_record.get("secret_enc", ""))
            account = MailAccount.from_record(account_record, secret=secret)
            if account_record.get("oauth_client_secret_enc"):
                account.oauth_client_secret = self._dec(
                    account_record["oauth_client_secret_enc"]
                )
            accounts.append(account)
        accounts.sort(key=lambda a: a.created_at)
        calendars: list[CalendarAccount] = []
        for calendar_record in record.get("calendars", {}).values():
            secret = self._dec(calendar_record.get("secret_enc", ""))
            calendars.append(CalendarAccount.from_record(calendar_record, secret=secret))
        calendars.sort(key=lambda c: c.created_at)
        return Connection(
            connection_id=record["connection_id"],
            client_id=record["client_id"],
            client_secret=self._dec(record["client_secret_enc"]),
            owner_id=record.get("owner_id", ""),
            label=record.get("label", ""),
            default_account_id=record.get("default_account_id", ""),
            accounts=accounts,
            calendars=calendars,
            default_calendar_id=record.get("default_calendar_id", ""),
            created_at=record.get("created_at", 0),
            revision=record.get("revision", 0),
        )

    def get_connection(self, connection_id: str) -> Connection | None:
        record = self._data["connections"].get(connection_id)
        return self._to_connection(record) if record else None

    def get_connection_by_client_id(self, client_id: str) -> Connection | None:
        for record in self._data["connections"].values():
            if record["client_id"] == client_id:
                return self._to_connection(record)
        return None

    def list_connections(self, owner_id: str | None = None) -> list[Connection]:
        out = [
            self._to_connection(record)
            for record in self._data["connections"].values()
            if owner_id is None or record.get("owner_id", "") == owner_id
        ]
        out.sort(key=lambda c: c.created_at, reverse=True)
        return out

    async def delete_connection(
        self, connection_id: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            self._data["connections"].pop(connection_id, None)
            self._drop_client_tokens(record["client_id"])
            await self._save()
            return True

    async def rotate_client_secret(
        self, connection_id: str, owner_id: str | None = None
    ) -> str | None:
        """Issue a new client secret, invalidating tokens issued to the old one."""
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return None
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return None
            new_secret = secrets.token_urlsafe(32)
            record["client_secret_enc"] = self._enc(new_secret)
            self._drop_client_tokens(record["client_id"])
            await self._save()
            return new_secret

    def _drop_client_tokens(self, client_id: str) -> None:
        """Forget every token and code of one OAuth client (lock held)."""
        for bucket in ("tokens", "refresh", "codes"):
            for key, token_record in list(self._data[bucket].items()):
                if isinstance(token_record, dict) and token_record.get("client_id") == client_id:
                    self._data[bucket].pop(key, None)

    async def rename_connection(
        self, connection_id: str, label: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            record["label"] = label
            await self._save()
            return True

    # --- mailboxes inside a connection ---

    async def add_account(
        self, connection_id: str, account: MailAccount, owner_id: str | None = None
    ) -> MailAccount | None:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return None
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return None
            account.account_id = account.account_id or "box_" + secrets.token_hex(6)
            account.created_at = account.created_at or int(time.time())
            stored = account.to_record()
            stored["secret_enc"] = self._enc(account.secret)
            if account.oauth_client_secret:
                stored["oauth_client_secret_enc"] = self._enc(account.oauth_client_secret)
            record.setdefault("accounts", {})[account.account_id] = stored
            if not record.get("default_account_id"):
                record["default_account_id"] = account.account_id
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return account

    async def remove_account(
        self, connection_id: str, account_id: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            if record.get("accounts", {}).pop(account_id, None) is None:
                return False
            if record.get("default_account_id") == account_id:
                remaining = list(record.get("accounts", {}))
                record["default_account_id"] = remaining[0] if remaining else ""
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return True

    async def set_default_account(
        self, connection_id: str, account_id: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            if account_id not in record.get("accounts", {}):
                return False
            record["default_account_id"] = account_id
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return True

    # --- calendars inside a connection ---

    async def add_calendar(
        self, connection_id: str, calendar: CalendarAccount, owner_id: str | None = None
    ) -> CalendarAccount | None:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return None
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return None
            calendar.account_id = calendar.account_id or "cal_" + secrets.token_hex(6)
            calendar.created_at = calendar.created_at or int(time.time())
            stored = calendar.to_record()
            stored["secret_enc"] = self._enc(calendar.secret)
            record.setdefault("calendars", {})[calendar.account_id] = stored
            if not record.get("default_calendar_id"):
                record["default_calendar_id"] = calendar.account_id
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return calendar

    async def remove_calendar(
        self, connection_id: str, calendar_id: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            if record.get("calendars", {}).pop(calendar_id, None) is None:
                return False
            if record.get("default_calendar_id") == calendar_id:
                remaining = list(record.get("calendars", {}))
                record["default_calendar_id"] = remaining[0] if remaining else ""
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return True

    async def set_default_calendar(
        self, connection_id: str, calendar_id: str, owner_id: str | None = None
    ) -> bool:
        async with self._lock:
            record = self._data["connections"].get(connection_id)
            if record is None:
                return False
            if owner_id is not None and record.get("owner_id", "") != owner_id:
                return False
            if calendar_id not in record.get("calendars", {}):
                return False
            record["default_calendar_id"] = calendar_id
            record["revision"] = record.get("revision", 0) + 1
            await self._save()
            return True

    # --- users and passkeys ---

    def has_user(self) -> bool:
        return bool(self._data["users"])

    async def create_user(self, email: str) -> str:
        async with self._lock:
            user_id = "usr_" + secrets.token_hex(8)
            self._data["users"][user_id] = {
                "email": email,
                "created_at": int(time.time()),
            }
            await self._save()
            return user_id

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self._data["users"].get(user_id)

    async def bump_session_epoch(self, user_id: str) -> None:
        """Retire every session cookie issued to this user so far."""
        async with self._lock:
            user = self._data["users"].get(user_id)
            if user is not None:
                user["session_epoch"] = user.get("session_epoch", 0) + 1
                await self._save()

    def find_user_by_email(self, email: str) -> str | None:
        for user_id, record in self._data["users"].items():
            if record.get("email", "").lower() == email.lower():
                return user_id
        return None

    async def add_credential(
        self,
        user_id: str,
        credential_id: str,
        public_key: str,
        sign_count: int,
        transports: list[str] | None = None,
    ) -> None:
        """Store a passkey. Public keys are not secret, so they go in as-is."""
        async with self._lock:
            self._data["credentials"][credential_id] = {
                "user_id": user_id,
                "public_key": public_key,
                "sign_count": sign_count,
                "transports": transports or [],
                "created_at": int(time.time()),
                "last_used": 0,
            }
            await self._save()

    def get_credential(self, credential_id: str) -> dict[str, Any] | None:
        return self._data["credentials"].get(credential_id)

    def list_credentials(self, user_id: str) -> list[dict[str, Any]]:
        """The passkeys that can sign in as this user, oldest first."""
        out = [
            {"credential_id": credential_id, **record}
            for credential_id, record in self._data["credentials"].items()
            if record.get("user_id") == user_id
        ]
        out.sort(key=lambda record: record.get("created_at", 0))
        return out

    async def delete_credential(self, user_id: str, credential_id: str) -> bool:
        """Remove one passkey, never the last one: that would lock the user out."""
        async with self._lock:
            record = self._data["credentials"].get(credential_id)
            if record is None or record.get("user_id") != user_id:
                return False
            remaining = [
                other
                for other, value in self._data["credentials"].items()
                if value.get("user_id") == user_id and other != credential_id
            ]
            if not remaining:
                return False
            self._data["credentials"].pop(credential_id, None)
            await self._save()
            return True

    async def update_sign_count(self, credential_id: str, sign_count: int) -> None:
        async with self._lock:
            record = self._data["credentials"].get(credential_id)
            if record is not None:
                record["sign_count"] = sign_count
                record["last_used"] = int(time.time())
                await self._save()

    # --- OAuth codes (stored by hash) ---

    async def save_code(self, code: OAuthCode) -> None:
        """Keep a new authorization code.

        ``/authorize`` needs no session, only a client id, so anyone can make
        this run. Expired codes are dropped here and each client keeps at most
        ``MAX_CODES_PER_CLIENT`` pending ones, so the store cannot be grown
        without bound.
        """
        async with self._lock:
            codes = self._data["codes"]
            now = time.time()
            for key, record in list(codes.items()):
                if record.get("expires_at", 0) < now:
                    codes.pop(key, None)
            mine = sorted(
                (record.get("expires_at", 0), key)
                for key, record in codes.items()
                if record.get("client_id") == code.client_id
            )
            for _, key in mine[: max(0, len(mine) - MAX_CODES_PER_CLIENT + 1)]:
                codes.pop(key, None)
            codes[self._hash(code.code)] = {
                "client_id": code.client_id,
                "redirect_uri": code.redirect_uri,
                "redirect_uri_provided_explicitly": code.redirect_uri_provided_explicitly,
                "code_challenge": code.code_challenge,
                "scopes": code.scopes,
                "expires_at": code.expires_at,
            }
            await self._save()

    def get_code(self, code: str) -> OAuthCode | None:
        record = self._data["codes"].get(self._hash(code))
        if not record:
            return None
        known = OAuthCode.__dataclass_fields__
        return OAuthCode(code=code, **{k: v for k, v in record.items() if k in known})

    async def pop_code(self, code: str) -> None:
        async with self._lock:
            self._data["codes"].pop(self._hash(code), None)
            await self._save()

    # --- OAuth tokens (stored by hash) ---

    async def save_token(
        self,
        record: OAuthTokenRecord,
        refresh_token: str | None = None,
        refresh_expires_at: float = 0.0,
        family: str = "",
    ) -> None:
        """Keep an access token, and the refresh token issued with it.

        ``family`` ties together every token descended from one authorization,
        so that a replayed refresh token can revoke the whole line.
        """
        async with self._lock:
            self._data["tokens"][self._hash(record.token)] = {
                "client_id": record.client_id,
                "scopes": record.scopes,
                "expires_at": record.expires_at,
                "family": family,
            }
            if refresh_token:
                # The refresh token carries its own client and scopes. It used
                # to be a pointer to the access token, so the first call made
                # with an expired access token deleted the refresh token with
                # it and the connector had to be authorized again by hand.
                self._data["refresh"][self._hash(refresh_token)] = {
                    "client_id": record.client_id,
                    "scopes": record.scopes,
                    "expires_at": refresh_expires_at,
                    "access_hash": self._hash(record.token),
                    "family": family,
                }
            await self._save()

    def get_token(self, token: str) -> OAuthTokenRecord | None:
        record = self._data["tokens"].get(self._hash(token))
        if not record:
            return None
        return OAuthTokenRecord(
            token=token,
            client_id=record.get("client_id", ""),
            scopes=record.get("scopes", []),
            expires_at=record.get("expires_at", 0.0),
        )

    def get_token_by_hash(self, token_hash: str) -> OAuthTokenRecord | None:
        record = self._data["tokens"].get(token_hash)
        if not record:
            return None
        # Only the hash is stored, so the raw token is unknown here.
        return OAuthTokenRecord(
            token="",
            client_id=record.get("client_id", ""),
            scopes=record.get("scopes", []),
            expires_at=record.get("expires_at", 0.0),
        )

    def get_refresh(self, refresh_token: str) -> OAuthTokenRecord | None:
        """The connector and scopes behind a refresh token, if it is still live."""
        record = self._data["refresh"].get(self._hash(refresh_token))
        if not record:
            return None
        if isinstance(record, str):  # a pointer from an older store file
            pointed = self._data["tokens"].get(record)
            if not pointed:
                return None
            return self.get_token_by_hash(record)
        if record.get("consumed_at"):
            return None
        if record.get("expires_at") and record["expires_at"] < time.time():
            return None
        return OAuthTokenRecord(
            token="",
            client_id=record.get("client_id", ""),
            scopes=record.get("scopes", []),
            expires_at=record.get("expires_at", 0.0),
        )

    def get_refresh_access_hash(self, refresh_token: str) -> str | None:
        """The access token a refresh token was issued beside, when known."""
        record = self._data["refresh"].get(self._hash(refresh_token))
        if isinstance(record, str):
            return record
        return record.get("access_hash") if record else None

    def refresh_family(self, refresh_token: str) -> str:
        record = self._data["refresh"].get(self._hash(refresh_token))
        return record.get("family", "") if isinstance(record, dict) else ""

    def refresh_was_used(self, refresh_token: str) -> dict[str, Any] | None:
        """The record of a refresh token that was already exchanged, if it was."""
        record = self._data["refresh"].get(self._hash(refresh_token))
        if isinstance(record, dict) and record.get("consumed_at"):
            return record
        return None

    async def consume_refresh(self, refresh_token: str) -> None:
        """Retire a refresh token after use, but remember it was used.

        Deleting it would make a replay look like any unknown token. Kept as
        consumed, a second presentation is recognised as the theft it is.
        """
        async with self._lock:
            record = self._data["refresh"].get(self._hash(refresh_token))
            if isinstance(record, dict):
                self._data["tokens"].pop(record.get("access_hash", ""), None)
                record["consumed_at"] = time.time()
            else:
                self._data["refresh"].pop(self._hash(refresh_token), None)
            await self._save()

    async def revoke_family(self, family: str) -> int:
        """Revoke every token descended from one authorization."""
        if not family:
            return 0
        async with self._lock:
            removed = 0
            for bucket in ("tokens", "refresh"):
                for key, record in list(self._data[bucket].items()):
                    if isinstance(record, dict) and record.get("family") == family:
                        self._data[bucket].pop(key, None)
                        removed += 1
            await self._save()
            return removed

    async def expire_access(self, token: str) -> None:
        """Drop one access token that has timed out, and nothing else.

        Expiry is routine, so it must not cascade: the refresh token that came
        with it is exactly what the client is about to use.
        """
        async with self._lock:
            self._data["tokens"].pop(self._hash(token), None)
            await self._save()

    async def revoke(self, token: str) -> None:
        """Revoke a token the client asked to revoke, and what hangs off it."""
        await self.revoke_hash(self._hash(token))

    async def revoke_hash(self, token_hash: str) -> None:
        async with self._lock:
            self._data["tokens"].pop(token_hash, None)
            self._data["refresh"].pop(token_hash, None)
            for refresh_hash, record in list(self._data["refresh"].items()):
                pointed = record if isinstance(record, str) else record.get("access_hash")
                if pointed == token_hash:
                    self._data["refresh"].pop(refresh_hash, None)
            await self._save()

    async def purge_expired(self) -> int:
        """Drop expired codes and tokens; returns how many were removed.

        Consumed refresh tokens stay until they would have expired anyway: up
        to then, a replay of one must still be recognised.
        """
        async with self._lock:
            now = time.time()
            removed = 0
            for bucket in ("codes", "tokens", "refresh"):
                for key, record in list(self._data[bucket].items()):
                    if not isinstance(record, dict):
                        continue
                    expires = record.get("expires_at", 0)
                    if expires and expires < now:
                        self._data[bucket].pop(key, None)
                        removed += 1
            if removed:
                await self._save()
            return removed


# ---------------------------------------------------------------------------
# Mailbox registry (live IMAP clients, cached per connection)
# ---------------------------------------------------------------------------


@dataclass
class _RegistryEntry:
    revision: int
    accounts: AccountSet
    calendars: CalendarSet
    clients: dict[str, Any] = field(default_factory=dict)


IDLE_SECONDS = 15 * 60


class MailboxRegistry:
    """Keeps the live clients (IMAP and CalDAV) of one connection.

    Entries are rebuilt when the connection's ``revision`` changes, so editing
    a mailbox or a calendar in the web UI takes effect without a restart.
    """

    def __init__(self, store: ConnectionStore):
        self._store = store
        self._entries: dict[str, _RegistryEntry] = {}
        # Teardown tasks are kept until they finish so they are not garbage
        # collected mid-flight.
        self._closing: set[asyncio.Task[None]] = set()

    def _close_later(self, clients: dict[str, Any]) -> None:
        if not clients:
            return
        task = asyncio.get_event_loop().create_task(_close_clients(dict(clients)))
        clients.clear()
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    def forget(self, client_id: str) -> None:
        """Drop a connection's live clients now: it was deleted or re-keyed.

        Access is refused anyway once the connection is gone; this closes the
        authenticated IMAP sessions and CalDAV pools it still held open, and
        drops the decrypted credentials from memory.
        """
        entry = self._entries.pop(client_id, None)
        if entry is not None:
            self._close_later(entry.clients)

    async def reap_idle(self, idle_seconds: float = IDLE_SECONDS) -> int:
        """Close the connections nobody has used for a while.

        Also drops entries whose connection was deleted without going through
        :meth:`forget` (another process, a restored store file).
        """
        closed = 0
        now = time.time()
        for client_id, entry in list(self._entries.items()):
            if self._store.get_connection_by_client_id(client_id) is None:
                self.forget(client_id)
                continue
            for key, client in list(entry.clients.items()):
                last = getattr(client, "_last_used", 0.0) or 0.0
                if last and now - last > idle_seconds:
                    entry.clients.pop(key, None)
                    try:
                        await client.close()
                    except Exception:
                        pass
                    closed += 1
        return closed

    def _entry(self, client_id: str) -> _RegistryEntry | None:
        connection = self._store.get_connection_by_client_id(client_id)
        if connection is None:
            self.forget(client_id)
            return None
        cached = self._entries.get(client_id)
        if cached is not None and cached.revision == connection.revision:
            return cached
        if cached is not None:
            self._close_later(cached.clients)
        entry = _RegistryEntry(
            revision=connection.revision,
            accounts=connection.account_set(),
            calendars=connection.calendar_set(),
        )
        self._entries[client_id] = entry
        return entry

    def account_set_for_client_id(self, client_id: str) -> AccountSet | None:
        entry = self._entry(client_id)
        return entry.accounts if entry is not None else None

    def calendar_set_for_client_id(self, client_id: str) -> CalendarSet | None:
        entry = self._entry(client_id)
        return entry.calendars if entry is not None else None

    def imap_for(self, client_id: str, account: MailAccount):
        from mail_mcp.imap_client import ImapClient

        entry = self._entries.get(client_id)
        if entry is None:
            return ImapClient(account)
        client = entry.clients.get(account.account_id)
        if client is None:
            client = ImapClient(account)
            entry.clients[account.account_id] = client
        return client

    def caldav_for(self, client_id: str, calendar: CalendarAccount):
        from mail_mcp.caldav_client import CalDavClient

        entry = self._entries.get(client_id)
        if entry is None:
            return CalDavClient(calendar)
        client = entry.clients.get(calendar.account_id)
        if client is None:
            client = CalDavClient(calendar)
            entry.clients[calendar.account_id] = client
        return client

    async def aclose(self) -> None:
        for entry in self._entries.values():
            await _close_clients(entry.clients)
        self._entries.clear()


async def _close_clients(clients: dict[str, Any]) -> None:
    for client in list(clients.values()):
        try:
            await client.close()
        except Exception:
            pass
    clients.clear()
