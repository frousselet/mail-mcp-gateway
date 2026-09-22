"""Multi-user onboarding web app plus the OAuth-protected MCP endpoint.

``mail-mcp-web`` serves everything on a single port, with no configuration
required:

- ``/register`` / ``/login``      passwordless accounts (WebAuthn passkeys)
- ``/``                           the signed-in user's connectors
- ``/connections/new``            create a connector (one MCP connection)
- ``/logs``                       every tool call the connectors served
- ``/connections/{id}``           attach a mailbox to a connector
- ``/connections/{id}/calendar``  attach a CalDAV calendar account
- ``/account``                    the signed-in user's passkeys
- ``/discover`` / ``/test``       look up provider settings, probe IMAP+SMTP
- ``/assets/app.css`` ``.js``     the stylesheet and script, so no HTML is inline
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
import time
from datetime import UTC, datetime
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
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from mail_mcp import activity, assets, discovery, server, smtp_client, ui
from mail_mcp.accounts import AccountConfigError, MailAccount
from mail_mcp.caldav_client import CalDavClient, CalDavError
from mail_mcp.calendars import CalendarAccount, CalendarConfigError
from mail_mcp.imap_client import ImapClient, ImapError
from mail_mcp.oauth import SCOPE, _redirect_uris
from mail_mcp.smtp_client import SmtpError

logger = logging.getLogger("mail-mcp.web")

mcp = server.mcp

def _session_secret() -> str:
    """The cookie-signing key, stable across restarts.

    A key regenerated on every boot signs everyone out whenever the container
    restarts, which reads as data loss. The store already persists an
    encryption key, so derive from that; a random per-process key is only the
    last resort when there is no store at all.
    """
    configured = os.environ.get("MAIL_SECRET_KEY")
    if configured:
        return configured
    if server.STORE is not None:
        return server.STORE.session_secret()
    return secrets.token_urlsafe(32)


def _secure_cookies() -> bool:
    """Whether to mark the session cookie Secure.

    On by default: the documented deployment terminates TLS at a reverse proxy
    and forwards plain HTTP, so keying this off MAIL_PUBLIC_URL left the
    cookie unprotected exactly where it mattered. Browsers treat localhost as
    a secure origin, so development still works; MAIL_INSECURE_COOKIE=1 is the
    escape hatch for a plain-HTTP LAN address.
    """
    return os.environ.get("MAIL_INSECURE_COOKIE", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    )


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


def _connection_view(
    connection, base_url: str, *, activity_summary: dict[str, Any] | None = None,
    email: str = "",
) -> dict[str, Any]:
    summary = (activity_summary or {}).get(connection.connection_id, {})
    return {
        "email": email,
        "activity": {
            "last_used": activity.humanise_age(summary.get("last_ts", 0), time.time()),
            "calls_7d": summary.get("calls_7d", 0),
            "errors_7d": summary.get("errors_7d", 0),
        },
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
                "sends_as": account.sending_identities(),
                "read_only": account.read_only,
                "is_default": account.account_id == connection.default_account_id,
            }
            for account in connection.accounts
        ],
        "calendars": [
            {
                "account_id": calendar.account_id,
                "address": calendar.address,
                "url": calendar.entry_point(),
                "timezone": calendar.timezone,
                "read_only": calendar.read_only,
                "is_default": calendar.account_id == connection.default_calendar_id,
            }
            for calendar in connection.calendars
        ],
    }


NOTICES = {
    "mailbox_added": "Mailbox added. The agent can use it right away.",
    "calendar_added": "Calendar added. The agent can use it right away.",
    "mailbox_removed": "Mailbox removed from that connector.",
    "calendar_removed": "Calendar removed from that connector.",
    "connector_deleted": "Connector deleted. Any agent using it has lost access.",
    "default_changed": "Default account changed.",
    "passkey_removed": "Passkey removed.",
}


def _dashboard(request: Request, error: str = "", notice: str = "") -> HTMLResponse:
    store = _store()
    uid = _uid(request) or ""
    base_url = _base_url(request)
    summary = activity.summarise_by_connection(server.ACTIVITY, uid) if uid else {}
    email = request.session.get("email", "")
    connections = [
        _connection_view(connection, base_url, activity_summary=summary, email=email)
        for connection in (store.list_connections(owner_id=uid) if store else [])
    ]
    if not notice:
        notice = NOTICES.get(request.query_params.get("notice", ""), "")
    return HTMLResponse(
        ui.dashboard_page(
            email,
            connections,
            error=error,
            notice=notice,
            open_registration=not os.environ.get("MAIL_ONBOARD_CODE"),
        ),
        status_code=400 if error else 200,
    )


def _redirect(path: str, notice: str = "") -> RedirectResponse:
    """POST then redirect: a refresh must not re-run what just happened."""
    target = f"{path}?notice={notice}" if notice else path
    return RedirectResponse(target, status_code=303)


# ---------------------------------------------------------------------------
# Accounts (passkeys)
# ---------------------------------------------------------------------------


@mcp.custom_route("/register", methods=["GET"])
async def register_get(request: Request) -> Response:
    """Create an account, or add a passkey to the one you are signed in to."""
    return HTMLResponse(
        ui.register_page(
            invite_required=bool(os.environ.get("MAIL_ONBOARD_CODE")),
            signed_in=bool(_uid(request)),
        )
    )


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

    uid = _uid(request)
    existing = store.find_user_by_email(email)
    if uid is None and existing is not None:
        # Registering the same email again used to mint a second, empty account
        # and leave the user staring at a dashboard with none of their work on
        # it. Adding a passkey to an existing account requires proving you hold
        # one already, so it happens while signed in, never here.
        return JSONResponse(
            {
                "error": "An account already exists for this email. Sign in with "
                "your passkey, then add another one from the Passkeys page."
            },
            status_code=409,
        )

    owner = uid or existing
    known = (
        [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(record["credential_id"]))
            for record in store.list_credentials(owner)
        ]
        if owner
        else []
    )
    options = generate_registration_options(
        rp_id=_rp_id(request),
        rp_name=os.environ.get("MAIL_RP_NAME", "Mail MCP Gateway"),
        user_name=email,
        user_id=(owner or secrets.token_hex(16)).encode(),
        exclude_credentials=known,
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


@mcp.custom_route("/account", methods=["GET"])
async def account(request: Request) -> Response:
    """Passkeys: see them, add one, remove one that is not the last."""
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    now = time.time()
    credentials = [
        {
            "credential_id": record["credential_id"],
            "short_id": record["credential_id"][:12] + "...",
            "created_at": record.get("created_at", 0),
            "added": datetime.fromtimestamp(
                record.get("created_at", 0) or now, tz=UTC
            ).strftime("%Y-%m-%d %H:%M UTC"),
            "last_used": activity.humanise_age(record.get("last_used", 0), now)
            or "never",
        }
        for record in (store.list_credentials(uid) if store else [])
    ]
    return HTMLResponse(
        ui.account_page(
            request.session.get("email", ""),
            credentials,
            open_registration=not os.environ.get("MAIL_ONBOARD_CODE"),
        )
    )


@mcp.custom_route("/account/passkeys/delete", methods=["POST"])
async def passkey_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    credential_id = str(form.get("credential_id", ""))
    if store and credential_id:
        await store.delete_credential(uid, credential_id)
    return _redirect("/account", "passkey_removed")


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
    return RedirectResponse(
        f"/connections/{connection.connection_id}/credentials?fresh=1", status_code=303
    )


@mcp.custom_route("/connections/{connection_id}/credentials", methods=["GET"])
async def connection_credentials(request: Request) -> Response:
    """What to paste into the agent.

    The secret is shown again on demand rather than once: it is stored
    encrypted, not hashed, so pretending it was unrecoverable only cost people
    a needless rotation and a reconnect.
    """
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection = store.get_connection(request.path_params["connection_id"]) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    base_url = _base_url(request)
    return HTMLResponse(
        ui.credentials_page(
            base_url,
            _connection_view(connection, base_url, email=request.session.get("email", "")),
            connection.client_secret,
            fresh=request.query_params.get("fresh") == "1",
        )
    )


@mcp.custom_route("/connections/remove", methods=["GET"])
async def connection_remove_confirm(request: Request) -> Response:
    """Ask before deleting, server-side, so the guard does not need scripting."""
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.query_params.get("connection_id", "")
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    return HTMLResponse(
        ui.confirm_page(
            title="Delete this connector",
            question=f"Delete the connector {connection.label!r}?",
            detail=(
                f"Any agent connected through it loses access immediately. Its "
                f"{len(connection.accounts)} mailbox(es) and "
                f"{len(connection.calendars)} calendar(s) are detached; the mail "
                "itself is untouched. This cannot be undone."
            ),
            action="/connections/delete",
            fields={"connection_id": connection_id},
            confirm_label="Delete connector",
            email=request.session.get("email", ""),
        )
    )


@mcp.custom_route("/connections/delete", methods=["POST"])
async def connection_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    if str(form.get("confirm", "")) != "yes":
        return _dashboard(request, error="That delete was not confirmed.")
    connection_id = str(form.get("connection_id", ""))
    if store and connection_id:
        ok = await store.delete_connection(connection_id, owner_id=uid)
        logger.info("User %s deleted connector %s (ok=%s)", uid, connection_id, ok)
    return _redirect("/", "connector_deleted")


@mcp.custom_route("/connections/rotate", methods=["GET"])
async def connection_rotate_confirm(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.query_params.get("connection_id", "")
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    return HTMLResponse(
        ui.confirm_page(
            title="Issue a new secret",
            question=f"Issue a new client secret for {connection.label!r}?",
            detail=(
                "The current secret stops working at once, and the agent will "
                "refuse to connect until you paste the new one into it."
            ),
            action="/connections/rotate",
            fields={"connection_id": connection_id},
            confirm_label="Issue a new secret",
            email=request.session.get("email", ""),
        )
    )


@mcp.custom_route("/connections/rotate", methods=["POST"])
async def connection_rotate(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    if str(form.get("confirm", "")) != "yes":
        return _dashboard(request, error="That rotation was not confirmed.")
    connection_id = str(form.get("connection_id", ""))
    if store is None or not connection_id:
        return RedirectResponse("/", status_code=303)
    secret = await store.rotate_client_secret(connection_id, owner_id=uid)
    if secret is None:
        return _dashboard(request, error="That connector no longer exists.")
    return RedirectResponse(
        f"/connections/{connection_id}/credentials", status_code=303
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
        ui.mailbox_form_page(
            _connection_view(
                connection, _base_url(request), email=request.session.get("email", "")
            )
        )
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
        from_address=field("from_address"),
        aliases=field("aliases"),
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

    view = _connection_view(
        connection, _base_url(request), email=request.session.get("email", "")
    )
    form = await request.form()
    # Everything but the password is handed back, so a wrong app password costs
    # one field, not the whole form (WCAG 3.3.7).
    typed = {key: value for key, value in form.items() if key != "secret"}
    account = _account_from_form(form)
    try:
        account.validate()
    except AccountConfigError as e:
        return HTMLResponse(
            ui.mailbox_form_page(view, error=str(e), values=typed), status_code=400
        )

    probe = await _probe(account)
    if not probe["ok"]:
        return HTMLResponse(
            ui.mailbox_form_page(
                view,
                error=f"{probe['message']} The mailbox was not saved.",
                values=typed,
            ),
            status_code=400,
        )

    account.settings_source = "manual"
    saved = await store.add_account(connection_id, account, owner_id=uid)
    if saved is None:
        return _dashboard(request, error="Could not attach that mailbox.")
    logger.info("User %s attached %s to %s", uid, account.address, connection_id)
    return _redirect("/", "mailbox_added")


@mcp.custom_route("/mailboxes/remove", methods=["GET"])
async def mailbox_remove_confirm(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.query_params.get("connection_id", "")
    account_id = request.query_params.get("account_id", "")
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    box = next((a for a in connection.accounts if a.account_id == account_id), None)
    if box is None:
        return _dashboard(request, error="That mailbox is already gone.")
    return HTMLResponse(
        ui.confirm_page(
            title="Remove this mailbox",
            question=f"Remove {box.address} from {connection.label!r}?",
            detail=(
                "The agent loses access to it. Nothing in the mailbox itself is "
                "touched, and you can attach it again later."
            ),
            action="/mailboxes/delete",
            fields={"connection_id": connection_id, "account_id": account_id},
            confirm_label="Remove mailbox",
            email=request.session.get("email", ""),
        )
    )


@mcp.custom_route("/mailboxes/delete", methods=["POST"])
async def mailbox_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    if str(form.get("confirm", "")) != "yes":
        return _dashboard(request, error="That removal was not confirmed.")
    connection_id = str(form.get("connection_id", ""))
    account_id = str(form.get("account_id", ""))
    if store and connection_id and account_id:
        await store.remove_account(connection_id, account_id, owner_id=uid)
    return _redirect("/", "mailbox_removed")


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
    return _redirect("/", "default_changed")


@mcp.custom_route("/calendars/default", methods=["POST"])
async def calendar_default(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    connection_id = str(form.get("connection_id", ""))
    calendar_id = str(form.get("calendar_id", ""))
    if store and connection_id and calendar_id:
        await store.set_default_calendar(connection_id, calendar_id, owner_id=uid)
    return _redirect("/", "default_changed")


# ---------------------------------------------------------------------------
# Calendars
# ---------------------------------------------------------------------------


def _calendar_from_form(form: Any) -> CalendarAccount:
    """Build a CalendarAccount from the add-calendar form (without validating)."""

    def field(name: str, default: str = "") -> str:
        return str(form.get(name, default) or "").strip()

    return CalendarAccount(
        address=field("address"),
        url=field("url"),
        username=field("username"),
        secret=str(form.get("secret", "") or ""),
        timezone=field("timezone", "UTC") or "UTC",
        default_calendar=field("default_calendar"),
        read_only=bool(form.get("read_only")),
    )


async def _probe_calendar(account: CalendarAccount) -> dict[str, Any]:
    """Try the CalDAV server with these settings; never raises."""
    try:
        client = CalDavClient(account)
    except CalDavError as e:
        return {"ok": False, "message": e.message}
    try:
        report = await client.check()
    except CalDavError as e:
        return {"ok": False, "message": f"{e.message} {e.detail}".strip()}
    finally:
        await client.close()

    names = ", ".join(c["name"] for c in report["calendars"]) or "none"
    return {
        "ok": True,
        "message": f"Connected. Calendars found: {names}.",
        "calendars": report["calendars"],
    }


@mcp.custom_route("/connections/{connection_id}/calendar", methods=["GET"])
async def calendar_form(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.path_params["connection_id"]
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    return HTMLResponse(
        ui.calendar_form_page(
            _connection_view(
                connection, _base_url(request), email=request.session.get("email", "")
            )
        )
    )


@mcp.custom_route("/connections/{connection_id}/calendars", methods=["POST"])
async def calendar_add(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.path_params["connection_id"]
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")

    view = _connection_view(
        connection, _base_url(request), email=request.session.get("email", "")
    )
    form = await request.form()
    typed = {key: value for key, value in form.items() if key != "secret"}
    calendar = _calendar_from_form(form)
    try:
        calendar.validate()
    except CalendarConfigError as e:
        return HTMLResponse(
            ui.calendar_form_page(view, error=str(e), values=typed), status_code=400
        )

    probe = await _probe_calendar(calendar)
    if not probe["ok"]:
        return HTMLResponse(
            ui.calendar_form_page(
                view,
                error=f"{probe['message']} The calendar was not saved.",
                values=typed,
            ),
            status_code=400,
        )

    saved = await store.add_calendar(connection_id, calendar, owner_id=uid)
    if saved is None:
        return _dashboard(request, error="Could not attach that calendar.")
    logger.info("User %s attached calendar %s to %s", uid, calendar.address, connection_id)
    return _redirect("/", "calendar_added")


@mcp.custom_route("/calendars/remove", methods=["GET"])
async def calendar_remove_confirm(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    connection_id = request.query_params.get("connection_id", "")
    calendar_id = request.query_params.get("calendar_id", "")
    connection = store.get_connection(connection_id) if store else None
    if connection is None or connection.owner_id != uid:
        return _dashboard(request, error="That connector no longer exists.")
    calendar = next(
        (c for c in connection.calendars if c.account_id == calendar_id), None
    )
    if calendar is None:
        return _dashboard(request, error="That calendar is already gone.")
    return HTMLResponse(
        ui.confirm_page(
            title="Remove this calendar",
            question=f"Remove {calendar.address} from {connection.label!r}?",
            detail=(
                "The agent loses access to those calendars. No event is changed, "
                "and you can attach the account again later."
            ),
            action="/calendars/delete",
            fields={"connection_id": connection_id, "calendar_id": calendar_id},
            confirm_label="Remove calendar",
            email=request.session.get("email", ""),
        )
    )


@mcp.custom_route("/calendars/delete", methods=["POST"])
async def calendar_delete(request: Request) -> Response:
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    store = _store()
    form = await request.form()
    if str(form.get("confirm", "")) != "yes":
        return _dashboard(request, error="That removal was not confirmed.")
    connection_id = str(form.get("connection_id", ""))
    calendar_id = str(form.get("calendar_id", ""))
    if store and connection_id and calendar_id:
        await store.remove_calendar(connection_id, calendar_id, owner_id=uid)
    return _redirect("/", "calendar_removed")


@mcp.custom_route("/test-calendar", methods=["POST"])
async def test_calendar(request: Request) -> JSONResponse:
    if not _uid(request):
        return JSONResponse({"error": "sign in first"}, status_code=401)
    payload = await request.json()
    try:
        calendar = _calendar_from_form(payload)
        calendar.validate()
    except CalendarConfigError as e:
        return JSONResponse({"ok": False, "message": str(e)})
    return JSONResponse(await _probe_calendar(calendar))


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------


def _entry_view(entry) -> dict[str, Any]:
    when = datetime.fromtimestamp(entry.ts, tz=UTC)
    return {
        "ts": entry.ts,
        "when": when.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool": entry.tool,
        "status": entry.status if entry.status in ("ok", "error", "denied") else "error",
        "account": entry.account,
        "connection_id": entry.connection_id,
        "connection_label": entry.connection_label,
        "arguments": entry.arguments,
        "detail": entry.detail,
        "duration_ms": entry.duration_ms,
    }


@mcp.custom_route("/logs", methods=["GET"])
async def logs(request: Request) -> Response:
    """Everything the agents did, scoped to the signed-in user's connectors."""
    uid = _uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)

    params = request.query_params
    try:
        limit = max(1, min(1000, int(params.get("limit", "100"))))
    except ValueError:
        limit = 100
    filters = {
        key: params.get(key, "").strip()
        for key in ("connection_id", "account", "tool", "status")
    }

    log = server.ACTIVITY
    entries = log.read(
        owner_id=uid,
        connection_id=filters["connection_id"] or None,
        account=filters["account"] or None,
        tool=filters["tool"] or None,
        status=filters["status"] or None,
        limit=limit,
    )
    stats = log.stats(owner_id=uid)
    store = _store()
    connections = [
        (connection.connection_id, connection.label or connection.connection_id)
        for connection in (store.list_connections(owner_id=uid) if store else [])
    ]
    return HTMLResponse(
        ui.logs_page(
            request.session.get("email", ""),
            [_entry_view(entry) for entry in entries],
            connections=connections,
            stats=stats,
            filters=filters,
            limit=limit,
            truncated=len(entries) >= limit and stats["total"] > len(entries),
            filtered=any(filters.values()),
        )
    )


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
# Static assets
# ---------------------------------------------------------------------------


def _asset(content: str, media_type: str, version: str, request: Request) -> Response:
    """Serve an asset with a long cache, keyed by the hash in its URL."""
    if request.headers.get("if-none-match") == f'"{version}"':
        return Response(status_code=304)
    return Response(
        content,
        media_type=media_type,
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "ETag": f'"{version}"',
        },
    )


@mcp.custom_route("/assets/app.css", methods=["GET"])
async def app_css(request: Request) -> Response:
    return _asset(assets.APP_CSS, "text/css; charset=utf-8", assets.CSS_VERSION, request)


@mcp.custom_route("/assets/app.js", methods=["GET"])
async def app_js(request: Request) -> Response:
    return _asset(
        assets.APP_JS, "text/javascript; charset=utf-8", assets.JS_VERSION, request
    )


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


class SecurityHeaders:
    """Headers for the browser-facing half only.

    The pages carry no inline script or style, so the policy can forbid both
    outright. It is applied to HTML responses alone: /mcp is a JSON and SSE
    endpoint that no browser renders, and a stray policy there would only
    confuse a future reader.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                content_type = next(
                    (
                        value.decode()
                        for key, value in headers
                        if key.decode().lower() == "content-type"
                    ),
                    "",
                )
                if content_type.startswith("text/html"):
                    headers.extend(
                        [
                            (b"content-security-policy", CSP.encode()),
                            (b"x-content-type-options", b"nosniff"),
                            (b"referrer-policy", b"same-origin"),
                            (b"x-frame-options", b"DENY"),
                        ]
                    )
            await send(message)

        await self.app(scope, receive, send_with_headers)


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
        secret_key=_session_secret(),
        session_cookie="mail_mcp_session",
        same_site="lax",
        https_only=_secure_cookies(),
        max_age=14 * 24 * 3600,
    )
    app.add_middleware(SecurityHeaders)
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
