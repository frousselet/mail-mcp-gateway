"""XOAUTH2 support for providers that no longer accept passwords.

Google and Microsoft both refuse plain IMAP/SMTP passwords on most accounts.
Their supported path is SASL XOAUTH2: the client presents a short-lived OAuth 2
access token instead of a password. The gateway stores the long-lived *refresh*
token and exchanges it for an access token when a connection is opened, caching
the result until shortly before it expires.

Obtaining the first refresh token is a one-off, out-of-band step (it needs a
browser consent screen); the README documents it.
"""

from __future__ import annotations

import base64
import logging
import time

import httpx

logger = logging.getLogger("mail-mcp.xoauth2")

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

# Scopes the refresh token must already carry; requested again on refresh so the
# access token keeps them.
GOOGLE_SCOPE = "https://mail.google.com/"
MICROSOFT_SCOPE = (
    "offline_access https://outlook.office.com/IMAP.AccessAsUser.All "
    "https://outlook.office.com/SMTP.Send"
)


class TokenError(RuntimeError):
    """Raised when a refresh token cannot be exchanged for an access token."""


def sasl_xoauth2_raw(username: str, access_token: str) -> bytes:
    """Build the raw SASL XOAUTH2 initial response.

    Format (Google and Microsoft alike):
    ``user=<address>^Aauth=Bearer <token>^A^A`` where ``^A`` is ``\\x01``.
    ``imaplib.IMAP4.authenticate`` base64-encodes what the callback returns, so
    it wants these raw bytes.
    """
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()


def sasl_xoauth2_b64(username: str, access_token: str) -> str:
    """The same initial response, base64-encoded for ``AUTH XOAUTH2 <arg>``."""
    return base64.b64encode(sasl_xoauth2_raw(username, access_token)).decode()


class TokenCache:
    """Process-wide cache of access tokens, keyed by refresh token."""

    def __init__(self) -> None:
        self._tokens: dict[str, tuple[str, float]] = {}

    def get(self, refresh_token: str) -> str | None:
        entry = self._tokens.get(refresh_token)
        if entry is None:
            return None
        token, expires_at = entry
        if expires_at - 60 <= time.time():
            self._tokens.pop(refresh_token, None)
            return None
        return token

    def put(self, refresh_token: str, access_token: str, expires_in: float) -> None:
        self._tokens[refresh_token] = (access_token, time.time() + expires_in)

    def clear(self) -> None:
        self._tokens.clear()


_CACHE = TokenCache()


async def access_token_for(
    *,
    provider: str,
    refresh_token: str,
    client_id: str,
    client_secret: str = "",
    tenant: str = "common",
    timeout: float = 20.0,
) -> str:
    """Return a valid access token, refreshing (and caching) as needed."""
    cached = _CACHE.get(refresh_token)
    if cached:
        return cached

    provider = provider.lower()
    if provider == "google":
        url = GOOGLE_TOKEN_URL
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": GOOGLE_SCOPE,
        }
    elif provider == "microsoft":
        url = MICROSOFT_TOKEN_URL.format(tenant=tenant or "common")
        data = {
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": MICROSOFT_SCOPE,
        }
        if client_secret:
            data["client_secret"] = client_secret
    else:
        raise TokenError(f"Unsupported XOAUTH2 provider {provider!r}.")

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, data=data)
    except httpx.HTTPError as e:
        raise TokenError(f"Token endpoint unreachable: {e}") from e

    if response.status_code != 200:
        detail = response.text.strip()[:400]
        raise TokenError(f"Token refresh failed ({response.status_code}): {detail}")

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise TokenError("Token endpoint returned no access_token.")
    _CACHE.put(refresh_token, access_token, float(payload.get("expires_in", 3600)))
    logger.info("Refreshed %s access token", provider)
    return access_token
