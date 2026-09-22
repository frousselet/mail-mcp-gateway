"""Multi-user onboarding web app plus the OAuth-protected MCP endpoint.

``mail-mcp-web`` serves everything on a single port, with no configuration
required:

- ``/register`` / ``/login``      passwordless accounts (WebAuthn passkeys)
- ``/``                           the signed-in user's connectors
- ``/connections/new``            create a connector (one MCP connection)
- ``/connections/{id}``           attach a mailbox to a connector
- ``/discover`` / ``/test``       look up provider settings, probe IMAP+SMTP
- ``/mcp``                        the shared, OAuth-protected MCP endpoint
- ``/authorize`` ``/token`` ``/.well-known/oauth-*``   the OAuth 2.1 server

Anyone can self-register (optionally gated by ``MAIL_ONBOARD_CODE``). Each user
owns as many connectors as they like, each connector serves as many mailboxes
as they like, and both can be revoked at any time. The public base URL is
derived from the request and the encryption key is generated on first run, so
``docker compose up`` works out of the box.
"""

from __future__ import annotations

import json as jsonlib
import logging
import os
import secrets
from typing import Any
from urllib.parse import urlparse

# The web app is inherently multi-user; the server module reads this at import.
os.environ.setdefault("MAIL_MULTITENANT", "1")

from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from mail_mcp import discovery, server, smtp_client, ui
from mail_mcp.accounts import AccountConfigError, MailAccount
from mail_mcp.imap_client import ImapClient, ImapError
from mail_mcp.oauth import SCOPE, _redirect_uris
from mail_mcp.smtp_client import SmtpError

logger = logging.getLogger("mail-mcp.web")

mcp = server.mcp

# Signing key for the browser session cookie (WebAuthn challenges, login state).
_SESSION_SECRET = os.environ.get("MAIL_SECRET_KEY") or secrets.token_urlsafe(32)


def _store():
    return server.STORE


def _base_url(request: Request) -> str:
    """The public base URL, derived from the request (honouring proxies).

    ``MAIL_PUBLIC_URL`` overrides the detection; setting it is recommended in
    production so the OAuth metadata matches exactly.
    """
    configured = os.environ.get("MAIL_PUBLIC_URL")
    if configured:
        return configured.rstrip("/")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
    )
    return f"{proto}://{host}"


def _rp_id(request: Request) -> str:
    return urlparse(_base_url(request)).hostname or "localhost"


def _uid(request: Request) -> str | None:
    return request.session.get("uid")


def _json_options(options) -> dict:
    return jsonlib.loads(options_to_json(options))


def _connection_view(connection, base_url: str) -> dict[str, Any]:
    return {
        "connection_id": connection.connection_id,
        "client_id": connection.client_id,
        "label": connection.label,
        "mcp_url": f"{base_url}/mcp",
        "redirect_uris": _redirect_uris(),
        "accounts": [
            {
                "account_id": account.account_id,
                "address": account.address,
                "imap": f"{account.imap_host}:{account.imap_port} "
                f"({account.imap_security})",
                "smtp": f"{account.smtp_host}:{account.smtp_port} "
                f"({account.smtp_security})",
                "auth": account.auth,
                "read_only": account.read_only,
                "is_default": account.account_id == connection.default_account_id,
            }
            for account in connection.accounts
        ],
    }


def _dashboard(request: Request, error: str = "", notice: str = "") -> HTMLResponse:
    store = _store()
    uid = _uid(request) or ""
    base_url = _base_url(request)
    connections = [
        _connection_view(connection, base_url)
        for connection in (store.list_connections(owner_id=uid) if store else [])
    ]
    return HTMLResponse(
        ui.dashboard_page(
            request.session.get("email", ""), connections, error=error, notice=notice
        ),
        status_code=400 if error else 200,
    )


# ---------------------------------------------------------------------------
# Accounts (passkeys)
# ---------------------------------------------------------------------------


@mcp.custom_route("/register", methods=["GET"])
async def register_get(request: Request) -> Response:
    if _uid(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(ui.register_page())


@mcp.custom_route("/webauthn/register/begin", methods=["POST"])
async def register_begin(request: Request) -> JSONResponse:
    store = _store()
    if store is None:
        return JSONResponse({"error": "server misconfigured"}, status_code=500)
    body = await request.json()

    gate = os.environ.get("MAIL_ONBOARD_CODE")
    if gate and str(body.get("code", "")) != gate:
        return JSONResponse({"error": "invalid invite code"}, status_code=403)

    email = str(body.get("email", "")).strip() or request.session.get("email", "")
    if not email:
        return JSONResponse({"error": "email required"}, status_code=400)

    options = generate_registration_options(
        rp_id=_rp_id(request),
        rp_name=os.environ.get("MAIL_RP_NAME", "Mail MCP Gateway"),
        user_name=email,
        user_id=secrets.token_bytes(16),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    request.session["wa_challenge"] = bytes_to_base64url(options.challenge)
    request.session["wa_reg_email"] = email
    return JSONResponse(_json_options(options))


@mcp.custom_route("/webauthn/register/complete", methods=["POST"])
async def register_complete(request: Request) -> JSONResponse:
    store = _store()
    if store is None:
        return JSONResponse({"error": "server misconfigured"}, status_code=500)
    challenge = request.session.pop("wa_challenge", None)
    email = request.session.pop("wa_reg_email", None)
    if not challenge or not email:
        return JSONResponse({"error": "no registration in progress"}, status_code=400)

    body = await request.json()
    try:
        verification = verify_registration_response(
            credential=body["credential"],
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=_rp_id(request),
            expected_origin=_base_url(request),
        )
    except Exception as e:
        logger.warning("Passkey registration failed: %s", e)
        return JSONResponse({"error": "verification failed"}, status_code=400)

    # A new passkey while signed in adds a credential; otherwise it creates an
    # account.
    uid = _uid(request) or await store.create_user(email)
    await store.add_credential(
        user_id=uid,
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
    )
    request.session["uid"] = uid
    request.session["email"] = email
    logger.info("Registered a passkey for %s", email)
    return JSONResponse({"ok": True})


@mcp.custom_route("/login", methods=["GET"])
async def login_get(request: Request) -> Response:
    if _uid(request):
        return RedirectResponse("/", status_code=303)
    store = _store()
    if store is None or not store.has_user():
        return RedirectResponse("/register", status_code=303)
    return HTMLResponse(ui.login_page())


@mcp.custom_route("/webauthn/login/begin", methods=["POST"])
async def login_begin(request: Request) -> JSONResponse:
    store = _store()
    if store is None or not store.has_user():
        return JSONResponse({"error": "no accounts yet"}, status_code=400)
    # Usernameless: let the authenticator offer any resident passkey for this RP.
    options = generate_authentication_options(
        rp_id=_rp_id(request),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    request.session["wa_challenge"] = bytes_to_base64url(options.challenge)
    return JSONResponse(_json_options(options))


@mcp.custom_route("/webauthn/login/complete", methods=["POST"])
async def login_complete(request: Request) -> JSONResponse:
    store = _store()
    if store is None:
        return JSONResponse({"error": "server misconfigured"}, status_code=500)
    challenge = request.session.pop("wa_challenge", None)
    if not challenge:
        return JSONResponse({"error": "no login in progress"}, status_code=400)

    credential = (await request.json())["credential"]
    record = store.get_credential(credential.get("id", ""))
    if record is None:
        return JSONResponse({"error": "unknown passkey"}, status_code=400)
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=_rp_id(request),
            expected_origin=_base_url(request),
            credential_public_key=base64url_to_bytes(record["public_key"]),
            credential_current_sign_count=record.get("sign_count", 0),
        )
    except Exception as e:
        logger.warning("Passkey login failed: %s", e)
        return JSONResponse({"error": "verification failed"}, status_code=400)

    await store.update_sign_count(credential["id"], verification.new_sign_count)
    user = store.get_user(record["user_id"])
    request.session["uid"] = record["user_id"]
    request.session["email"] = user["email"] if user else ""
    return JSONResponse({"ok": True})


@mcp.custom_route("/logout", methods=["GET"])
async def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------------


@mcp.custom_route("/", methods=["GET"])
async def home(request: Request) -> Response:
    if not _uid(request):
        return RedirectResponse("/login", status_code=303)
    return _dashboard(request)


@mcp.custom_route("/connections/new", methods=["POST"])
async def connection_new(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    if store is None:
        return HTMLResponse(ui.page("Server misconfigured."), status_code=500)

    form = await request.form()
    gate = os.environ.get("MAIL_ONBOARD_CODE")
    if gate and str(form.get("onboard_code", "")) != gate:
        return _dashboard(request, error="Invalid invite code.")
    label = str(form.get("label", "")).strip()
    if not label:
        return _dashboard(request, error="Give the connector a name.")

    connection = await store.create_connection(owner_id=uid, label=label)
    logger.info("User %s created connector %s (%r)", uid, connection.connection_id, label)
    return HTMLResponse(
        ui.credentials_page(
            _base_url(request),
            _connection_view(connection, _base_url(request)),
            connection.client_secret,
        )
    )


@mcp.custom_route("/connections/delete", methods=["POST"])
async def connection_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    connection_id = str(form.get("connection_id", ""))
    if store and connection_id:
        ok = await store.delete_connection(connection_id, owner_id=uid)
        logger.info("User %s deleted connector %s (ok=%s)", uid, connection_id, ok)
    return RedirectResponse("/", status_code=303)


@mcp.custom_route("/connections/rotate", methods=["POST"])
async def connection_rotate(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    connection_id = str(form.get("connection_id", ""))
    if store is None or not connection_id:
        return RedirectResponse("/", status_code=303)
    secret = await store.rotate_client_secret(connection_id, owner_id=uid)
    connection = store.get_connection(connection_id)
    if secret is None or connection is None:
        return _dashboard(request, error="That connector no longer exists.")
    base_url = _base_url(request)
    return HTMLResponse(
        ui.credentials_page(base_url, _connection_view(connection, base_url), secret)
    )


@mcp.custom_route("/connections/{connection_id}", methods=["GET"])
async def connection_detail(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.path_params["connection_id"]
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    return HTMLResponse(
        ui.mailbox_form_page(_connection_view(connection, _base_url(request)))
    )


# ---------------------------------------------------------------------------
# Mailboxes
# ---------------------------------------------------------------------------


def _account_from_form(form: Any) -> MailAccount:
    """Build a MailAccount from the add-mailbox form (without validating)."""

    def field(name: str, default: str = "") -> str:
        return str(form.get(name, default) or "").strip()

    def port(name: str, default: int) -> int:
        try:
            return int(field(name) or default)
        except ValueError:
            return default

    return MailAccount(
        address=field("address"),
        from_name=field("from_name"),
        imap_host=field("imap_host"),
        imap_port=port("imap_port", 993),
        imap_security=field("imap_security", "ssl").lower(),
        imap_username=field("imap_username"),
        smtp_host=field("smtp_host"),
        smtp_port=port("smtp_port", 587),
        smtp_security=field("smtp_security", "starttls").lower(),
        smtp_username=field("smtp_username"),
        auth=field("auth", "password").lower(),
        secret=str(form.get("secret", "") or ""),
        oauth_provider=field("oauth_provider").lower(),
        oauth_client_id=field("oauth_client_id"),
        oauth_client_secret=field("oauth_client_secret"),
        oauth_tenant=field("oauth_tenant", "common"),
        verify_ssl=bool(form.get("verify_ssl")),
        read_only=bool(form.get("read_only")),
    )


@mcp.custom_route("/connections/{connection_id}/mailboxes", methods=["POST"])
async def mailbox_add(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.path_params["connection_id"]
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")

    view = _connection_view(connection, _base_url(request))
    form = await request.form()
    account = _account_from_form(form)
    try:
        account.validate()
    except AccountConfigError as e:
        return HTMLResponse(ui.mailbox_form_page(view, error=str(e)), status_code=400)

    probe = await _probe(account)
    if not probe["ok"]:
        return HTMLResponse(
            ui.mailbox_form_page(
                view, error=f"{probe['message']} The mailbox was not saved."
            ),
            status_code=400,
        )

    account.settings_source = "manual"
    saved = await store.add_account(connection_id, account, owner_id=uid)
    if saved is None:
        return _dashboard(request, error="Could not attach that mailbox.")
    logger.info("User %s attached %s to %s", uid, account.address, connection_id)
    return _dashboard(
        request, notice=f"{account.address} is now available to this connector."
    )


@mcp.custom_route("/mailboxes/delete", methods=["POST"])
async def mailbox_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    connection_id = str(form.get("connection_id", ""))
    account_id = str(form.get("account_id", ""))
    if store and connection_id and account_id:
        await store.remove_account(connection_id, account_id, owner_id=uid)
    return RedirectResponse("/", status_code=303)


@mcp.custom_route("/mailboxes/default", methods=["POST"])
async def mailbox_default(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    connection_id = str(form.get("connection_id", ""))
    account_id = str(form.get("account_id", ""))
    if store and connection_id and account_id:
        await store.set_default_account(connection_id, account_id, owner_id=uid)
    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------------------------------
# Provider lookup and connection test (used by the add-mailbox form)
# ---------------------------------------------------------------------------


@mcp.custom_route("/discover", methods=["POST"])
async def discover_settings(request: Request) -> JSONResponse:
    if not _uid(request):
        return JSONResponse({"error": "sign in first"}, status_code=401)
    address = str((await request.json()).get("address", "")).strip()
    if "@" not in address:
        return JSONResponse({"error": "enter a full email address"}, status_code=400)
    settings = await discovery.discover(address)
    if settings is None:
        return JSONResponse({"found": False})
    return JSONResponse({"found": True, "settings": settings.as_dict()})


async def _probe(account: MailAccount) -> dict[str, Any]:
    """Try IMAP then SMTP with these settings; never raises."""
    client = ImapClient(account)
    try:
        report = await client.check()
    except ImapError as e:
        return {"ok": False, "message": f"IMAP: {e.message} {e.detail}".strip()}
    finally:
        await client.close()

    message = f"IMAP OK ({report['folders']} folders)."
    try:
        await smtp_client.check(account)
    except SmtpError as e:
        return {"ok": False, "message": f"{message} SMTP: {e.message} {e.detail}".strip()}
    return {"ok": True, "message": f"{message} SMTP OK. These settings work."}


@mcp.custom_route("/test", methods=["POST"])
async def test_settings(request: Request) -> JSONResponse:
    if not _uid(request):
        return JSONResponse({"error": "sign in first"}, status_code=401)
    payload = await request.json()
    try:
        account = _account_from_form(payload)
        account.validate()
    except AccountConfigError as e:
        return JSONResponse({"ok": False, "message": str(e)})
    return JSONResponse(await _probe(account))


# ---------------------------------------------------------------------------
# OAuth discovery metadata, derived from the request so the gateway works
# behind any host or proxy without configuration. Inserted ahead of the SDK's
# fixed-issuer routes.
# ---------------------------------------------------------------------------


async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [SCOPE],
        }
    )


async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
        }
    )


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------


def build_app():
    if server.STORE is None:  # pragma: no cover - import-order guard
        raise RuntimeError(
            "mail_mcp.server was imported without MAIL_MULTITENANT=1, so the MCP "
            "endpoint would be served without OAuth. Import mail_mcp.web first, "
            "or set MAIL_MULTITENANT=1 in the environment."
        )
    app = mcp.streamable_http_app(transport_security=server.transport_security())

    # Shadow the SDK's fixed-issuer metadata with request-derived versions
    # (matched first because they are inserted at the front of the route list).
    app.router.routes.insert(
        0,
        Route(
            "/.well-known/oauth-protected-resource",
            oauth_protected_resource_metadata,
            methods=["GET"],
        ),
    )
    app.router.routes.insert(
        0,
        Route(
            "/.well-known/oauth-authorization-server",
            oauth_authorization_server_metadata,
            methods=["GET"],
        ),
    )

    app.add_middleware(
        SessionMiddleware,
        secret_key=_SESSION_SECRET,
        session_cookie="mail_mcp_session",
        same_site="lax",
        https_only=os.environ.get("MAIL_PUBLIC_URL", "").startswith("https"),
    )
    return app


app = build_app()


def main() -> None:
    """Entry point: run the onboarding UI and the MCP endpoint together."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Mail MCP Gateway web server")
    parser.add_argument("--host", default=os.environ.get("MAIL_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("MAIL_PORT", "8000"))
    )
    args = parser.parse_args()

    logger.info("Starting the Mail MCP Gateway on %s:%s", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True)


if __name__ == "__main__":
    main()
