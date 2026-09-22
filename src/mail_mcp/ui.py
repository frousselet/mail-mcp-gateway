"""The pages, rendered server-side.

Every page is a function returning a string. The stylesheet and the script live
in :mod:`mail_mcp.assets` and are linked, never inlined, so the HTML carries no
``style`` or ``on*`` attribute and a strict Content-Security-Policy can forbid
both. Behaviour is attached by ``data-action`` hooks that the script binds on a
delegated listener.

Two rules hold throughout:

- every interpolated value goes through :func:`esc`, and no value is ever
  placed in a JavaScript context, because HTML escaping is not JavaScript
  escaping and an attribute is decoded before its script is parsed;
- anything destructive is confirmed by a server-rendered page, not by a
  ``confirm()`` dialog, so the guard survives scripting being off.
"""

from __future__ import annotations

import contextvars
import html
import re
from typing import Any

from mail_mcp import charts
from mail_mcp.assets import CSS_VERSION, JS_VERSION

PRODUCT = "Mail MCP Gateway"

# The anti-forgery token of the request being rendered, set by the web app.
CSRF_TOKEN: contextvars.ContextVar[str] = contextvars.ContextVar("csrf_token", default="")
_POST_FORM_RE = re.compile(r'(<form\b[^>]*\bmethod="post"[^>]*>)', re.IGNORECASE)


def _with_csrf(markup: str) -> str:
    """Give every POST form on the page the session's anti-forgery token.

    Done once, here, so no form can be written without it. The pattern only
    ever meets markup this module wrote: interpolated values are escaped, so
    they cannot contain a literal ``<form``.
    """
    token = CSRF_TOKEN.get()
    if not token:
        return markup
    field = f'<input type="hidden" name="csrf" value="{esc(token)}">'
    return _POST_FORM_RE.sub(lambda match: match.group(1) + field, markup)


def esc(value: Any) -> str:
    """HTML-escape a value for either element or attribute position."""
    return html.escape(str(value if value is not None else ""), quote=True)


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------


def page(
    body: str,
    *,
    title: str,
    nav: str = "",
    after: str = "",
) -> str:
    """Wrap a body in the document shell.

    ``title`` names the page: seven tabs called "Mail MCP Gateway" are no help
    to anyone halfway through setup.
    """
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} - {PRODUCT}</title>
<link rel="stylesheet" href="/assets/app.css?v={CSS_VERSION}">
<script src="/assets/app.js?v={JS_VERSION}" defer></script>
</head>
<body{f' data-after="{esc(after)}"' if after else ""}>
<a class="skip" href="#main">Skip to content</a>
<div class="shell">
{_with_csrf(nav)}
<main id="main">
{_with_csrf(body)}
</main>
</div>
</body></html>"""


def _header(title: str, email: str = "", current: str = "") -> str:
    """The page heading, plus the signed-in navigation when there is a session."""
    if not email:
        return f'<header class="top"><h1>{esc(title)}</h1></header>'

    def link(href: str, text: str, key: str) -> str:
        mark = ' aria-current="page"' if key == current else ""
        return f'<a href="{esc(href)}"{mark}>{esc(text)}</a>'

    return f"""<header class="top">
  <h1>{esc(title)}</h1>
  <div class="who">
    <nav class="main" aria-label="Main">
      {link("/", "Connectors", "connectors")}
      {link("/logs", "Activity", "logs")}
      {link("/account", "Passkeys", "account")}
      <form method="post" action="/logout" class="inline">
        <button type="submit" class="linklike">Sign out</button>
      </form>
    </nav>
    {esc(email)}
  </div>
</header>"""


def _notice(message: str, kind: str = "info") -> str:
    if not message:
        return ""
    role = ' role="alert"' if kind == "error" else ' role="status"'
    return f'<p class="notice notice-{esc(kind)}"{role}>{esc(message)}</p>'


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{esc(kind)}">{esc(text)}</span>'


def access_badge(read_only: bool) -> str:
    """Say in words what the agent may do; never colour alone."""
    if read_only:
        return _badge("Read only", "read")
    return _badge("Can send and delete", "write")


def _option_list(options: list[tuple[str, str]], selected: str) -> str:
    return "".join(
        f'<option value="{esc(value)}"{" selected" if value == selected else ""}>'
        f"{esc(text)}</option>"
        for value, text in options
    )


def _hidden(fields: dict[str, str]) -> str:
    return "".join(
        f'<input type="hidden" name="{esc(name)}" value="{esc(value)}">'
        for name, value in fields.items()
    )


SECURITY_CHOICES = [("ssl", "SSL/TLS"), ("starttls", "STARTTLS"), ("none", "None (plain)")]


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def register_page(*, invite_required: bool = False, signed_in: bool = False) -> str:
    """Create the first account, or add a passkey to the one you have."""
    code_field = (
        '<label for="code">Invite code<span class="hint">This gateway asks for one '
        'before it will create an account.</span>'
        '<input id="code" name="code" autocomplete="off" required></label>'
        if invite_required
        else ""
    )
    if signed_in:
        intro = (
            "<p>Add a second passkey so losing one device does not lock you out of "
            "your own gateway.</p>"
        )
        button = "Add a passkey"
        email_field = (
            '<label for="email">Email<span class="hint">The account this passkey '
            "signs in to.</span>"
            '<input id="email" name="email" type="email" autocomplete="username webauthn" '
            'required></label>'
        )
    else:
        intro = (
            "<p>Your account is secured by a passkey: Touch ID, Windows Hello, a "
            "security key, or your phone. There is no password to choose or lose.</p>"
        )
        button = "Create my passkey"
        email_field = (
            '<label for="email">Email<span class="hint">Only used to tell your '
            "accounts apart. It is never contacted.</span>"
            '<input id="email" type="email" name="email" required '
            'autocomplete="username webauthn" placeholder="you@example.com"></label>'
        )

    body = f"""
{_header("Add a passkey" if signed_in else "Create your account")}
{intro}
<p id="err" class="status" role="alert"></p>
<div class="card">
  {email_field}
  {code_field}
  <p><button type="button" data-action="register">{esc(button)}</button></p>
</div>
{"" if signed_in else '<p class="muted">Already set up? <a href="/login">Sign in</a>.</p>'}
"""
    return page(
        body,
        title="Add a passkey" if signed_in else "Create your account",
        after="/account" if signed_in else "/",
    )


def login_page() -> str:
    body = f"""
{_header("Sign in")}
<p class="muted">Use the passkey you created when you set this gateway up.</p>
<p id="err" class="status" role="alert"></p>
<div class="card">
  <p><button type="button" data-action="login">Sign in with a passkey</button></p>
</div>
<p class="muted">No account yet? <a href="/register">Create one</a>.</p>
"""
    return page(body, title="Sign in")


def account_page(
    email: str, credentials: list[dict[str, Any]], *, open_registration: bool = False
) -> str:
    """Passkeys: the page that keeps a lost device from being a lost gateway."""
    if credentials:
        rows = "".join(
            f"<tr>"
            f'<td><span class="label">Added</span>'
            f'<span data-ts="{esc(credential["created_at"])}">{esc(credential["added"])}</span></td>'
            f'<td><span class="label">Identifier</span><code>{esc(credential["short_id"])}</code></td>'
            f'<td><span class="label">Last used</span>{esc(credential["last_used"])}</td>'
            f"<td>"
            + (
                '<span class="muted small-text">Your only passkey</span>'
                if len(credentials) == 1
                else (
                    '<form method="post" action="/account/passkeys/delete">'
                    f'<input type="hidden" name="credential_id" value="{esc(credential["credential_id"])}">'
                    '<button class="small danger" data-busy="Removing">Remove</button>'
                    "</form>"
                )
            )
            + "</td></tr>"
            for credential in credentials
        )
        table = (
            '<div class="table-wrap"><table class="stack">'
            '<caption class="sr-only">Passkeys that can sign in to this account</caption>'
            "<thead><tr><th scope=\"col\">Added</th><th scope=\"col\">Identifier</th>"
            '<th scope="col">Last used</th><th scope="col"><span class="sr-only">Actions</span></th>'
            f"</tr></thead><tbody>{rows}</tbody></table></div>"
        )
    else:
        table = '<p class="muted">No passkey on this account yet.</p>'

    warning = (
        _notice(
            "This is your only passkey. If you lose that device you lose access to "
            "this gateway, and the only way back is deleting its data. Add a second "
            "one now, on another device.",
            "warn",
        )
        if len(credentials) == 1
        else ""
    )
    registration = (
        _notice(
            "Anyone who can reach this address can create their own account here. "
            "Set MAIL_ONBOARD_CODE to require an invite code.",
            "warn",
        )
        if open_registration
        else ""
    )

    body = f"""
{_header("Passkeys", email, "account")}
{warning}
<div class="card">
  <div class="card-head"><h2>Your passkeys</h2>
    <a class="btn small" href="/register">Add a passkey</a></div>
  {table}
</div>
<h2>This account</h2>
<div class="card">
  <dl class="kv">
    <dt>Email</dt><dd>{esc(email)}</dd>
  </dl>
  {registration}
  <p class="muted">Signing out does not revoke anything: your connectors keep
  working, because they hold their own OAuth credentials.</p>
</div>
"""
    return page(body, title="Passkeys", nav="")


# ---------------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------------


def _mailbox_rows(connection: dict[str, Any]) -> str:
    rows = []
    for box in connection["accounts"]:
        sends_as = box.get("sends_as") or [box["address"]]
        identity = (
            f'<div class="muted small-text">Sends as {esc(", ".join(sends_as))}</div>'
            if len(sends_as) > 1 or sends_as[0] != box["address"]
            else ""
        )
        default = (
            _badge("Default", "default")
            if box["is_default"]
            else (
                '<form method="post" action="/mailboxes/default">'
                f'{_hidden({"connection_id": connection["connection_id"], "account_id": box["account_id"]})}'
                '<button class="small secondary" data-busy="Setting">Set as default</button></form>'
            )
        )
        rows.append(
            "<tr>"
            f'<td><span class="label">Mailbox</span><strong>{esc(box["address"])}</strong>'
            f"{identity}"
            f'<div class="muted small-text">{esc(box["imap"])} &middot; {esc(box["smtp"])}'
            f' &middot; {esc(box["auth"])}</div></td>'
            f'<td><span class="label">Access</span>{access_badge(box["read_only"])}</td>'
            f'<td><span class="label">Default</span>{default}</td>'
            f'<td><form method="get" action="/mailboxes/remove">'
            f'{_hidden({"connection_id": connection["connection_id"], "account_id": box["account_id"]})}'
            '<button class="small danger">Remove</button></form></td>'
            "</tr>"
        )
    if not rows:
        return (
            '<p class="muted">No mailbox yet. This connector cannot do anything '
            "until it has one.</p>"
        )
    return (
        '<div class="table-wrap"><table class="stack">'
        '<caption class="sr-only">Mailboxes this connector serves</caption>'
        '<thead><tr><th scope="col">Mailbox</th><th scope="col">Access</th>'
        '<th scope="col">Default</th><th scope="col"><span class="sr-only">Actions</span></th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _calendar_rows(connection: dict[str, Any]) -> str:
    calendars = connection.get("calendars", [])
    if not calendars:
        return ""
    rows = "".join(
        "<tr>"
        f'<td><span class="label">Calendar account</span><strong>{esc(calendar["address"])}</strong>'
        f'<div class="muted small-text">{esc(calendar["url"])} &middot; '
        f'{esc(calendar["timezone"])}</div></td>'
        f'<td><span class="label">Access</span>{access_badge(calendar["read_only"])}</td>'
        f'<td><form method="get" action="/calendars/remove">'
        f'{_hidden({"connection_id": connection["connection_id"], "calendar_id": calendar["account_id"]})}'
        '<button class="small danger">Remove</button></form></td>'
        "</tr>"
        for calendar in calendars
    )
    return (
        '<div class="table-wrap"><table class="stack">'
        '<caption class="sr-only">Calendar accounts this connector serves</caption>'
        '<thead><tr><th scope="col">Calendar account</th><th scope="col">Access</th>'
        '<th scope="col"><span class="sr-only">Actions</span></th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _connector_card(connection: dict[str, Any]) -> str:
    activity = connection.get("activity") or {}
    if activity.get("last_used"):
        used = f'<span class="muted small-text">Last used {esc(activity["last_used"])}</span>'
    else:
        used = _badge("Never used", "idle")
    series = activity.get("series") or []
    spark = charts.sparkline(
        series,
        label=(
            f"{sum(series)} calls over the last {len(series)} days, "
            f"{activity.get('errors_7d', 0)} of them failed or refused this week"
        ),
    )

    counts = []
    mailboxes = len(connection["accounts"])
    calendars = len(connection.get("calendars", []))
    if mailboxes:
        counts.append(f"{mailboxes} mailbox" + ("es" if mailboxes > 1 else ""))
    if calendars:
        counts.append(f"{calendars} calendar" + ("s" if calendars > 1 else ""))
    summary = ", ".join(counts) or "nothing attached yet"

    unfinished = (
        _notice(
            "This connector has no mailbox and no calendar, so an agent connected "
            "to it can do nothing. Add one below.",
            "warn",
        )
        if not connection["accounts"] and not connection.get("calendars")
        else ""
    )

    return f"""
<section class="card" aria-labelledby="c-{esc(connection['connection_id'])}">
  <div class="card-head">
    <h2 id="c-{esc(connection['connection_id'])}">{esc(connection['label'] or 'Connector')}</h2>
    <span class="muted small-text">{spark} {esc(summary)} &middot; {used}</span>
  </div>
  {unfinished}
  {_mailbox_rows(connection)}
  {_calendar_rows(connection)}
  <div class="actions">
    <a class="btn small" href="/connections/{esc(connection['connection_id'])}">Add a mailbox</a>
    <a class="btn small secondary" href="/connections/{esc(connection['connection_id'])}/calendar">Add a calendar</a>
    <a class="btn small secondary" href="/connections/{esc(connection['connection_id'])}/credentials">Connection details</a>
    <form method="get" action="/connections/remove">
      {_hidden({"connection_id": connection["connection_id"]})}
      <button class="small danger">Delete connector</button>
    </form>
  </div>
</section>"""


def dashboard_page(
    email: str,
    connections: list[dict[str, Any]],
    error: str = "",
    notice: str = "",
    *,
    open_registration: bool = False,
) -> str:
    cards = (
        "".join(_connector_card(connection) for connection in connections)
        if connections
        else """
<div class="card">
  <p><strong>No connector yet.</strong></p>
  <p class="muted">A connector is one connection for one agent. It carries the
  mailboxes and calendars that agent may use, and its own credentials, so you
  can revoke it on its own. Create one below, then attach a mailbox to it.</p>
</div>"""
    )

    gate = (
        '<label for="onboard_code">Invite code<input id="onboard_code" '
        'name="onboard_code" required autocomplete="off"></label>'
        if open_registration is False and _invite_required()
        else ""
    )

    body = f"""
{_header("Your MCP connectors", email, "connectors")}
{_notice(error, "error")}{_notice(notice, "ok")}
{cards}

<h2>New connector</h2>
<div class="card">
  <p class="muted">Give it a name you will recognise later. One connector per
  agent, or per purpose, keeps revoking simple.</p>
  <form method="post" action="/connections/new">
    {gate}
    <label for="label">Name<input id="label" name="label" required
      autocomplete="off" placeholder="Claude on my laptop"></label>
    <p><button type="submit" data-busy="Creating">Create connector</button></p>
  </form>
</div>
"""
    return page(body, title="Your connectors")


def _invite_required() -> bool:
    import os

    return bool(os.environ.get("MAIL_ONBOARD_CODE"))


def credentials_page(
    base_url: str,
    connection: dict[str, Any],
    client_secret: str,
    *,
    fresh: bool = False,
) -> str:
    """What to paste into the agent. Not one-shot: the secret is recoverable."""
    redirects = ", ".join(esc(uri) for uri in connection.get("redirect_uris", []))
    intro = (
        "<p>Your connector is ready. In Claude, open <strong>Settings &rarr; "
        "Connectors &rarr; Add custom connector</strong> and paste these three "
        "values.</p>"
        if fresh
        else "<p>Paste these into the agent's custom-connector dialog.</p>"
    )
    body = f"""
{_header(connection['label'] or 'Connector', connection.get('email', ''), 'connectors')}
{intro}
<div class="card">
  <dl class="kv">
    <dt><label for="mcp-url">MCP server URL</label></dt>
    <dd><div class="secret"><code id="mcp-url">{esc(base_url)}/mcp</code>
      <button class="small secondary" type="button" data-action="copy" data-copy="mcp-url">Copy</button></div></dd>
    <dt><label for="client-id">OAuth client ID</label></dt>
    <dd><div class="secret"><code id="client-id">{esc(connection['client_id'])}</code>
      <button class="small secondary" type="button" data-action="copy" data-copy="client-id">Copy</button></div></dd>
    <dt><label for="client-secret">OAuth client secret</label></dt>
    <dd><div class="secret"><code id="client-secret">{esc(client_secret)}</code>
      <button class="small secondary" type="button" data-action="copy" data-copy="client-secret">Copy</button></div></dd>
  </dl>
  <p id="copy-status" class="status" role="status" aria-live="polite"></p>
  <p class="muted">You can come back to this page whenever you need it. If the
  secret has leaked, issue a new one below: the agent will have to reconnect.</p>
  <div class="actions">
    <a class="btn secondary" href="/">Back to connectors</a>
    <a class="btn small" href="/connections/{esc(connection['connection_id'])}">Add a mailbox</a>
    <form method="get" action="/connections/rotate">
      {_hidden({"connection_id": connection["connection_id"]})}
      <button class="small danger">Issue a new secret</button>
    </form>
  </div>
</div>
<p class="muted">Authorized redirect URLs: {redirects or "(none configured)"}.</p>
"""
    return page(body, title=f"{connection['label'] or 'Connector'} details")


def confirm_page(
    *,
    title: str,
    question: str,
    detail: str,
    action: str,
    fields: dict[str, str],
    confirm_label: str,
    email: str = "",
    cancel: str = "/",
) -> str:
    """Server-rendered confirmation for anything destructive.

    A ``confirm()`` dialog is not a guard: it needs scripting, and putting the
    name of the thing inside a JavaScript string in an attribute is how
    escaping bugs happen. This page works with scripting off and puts no data
    in a script context.
    """
    body = f"""
{_header(title, email)}
<div class="card">
  <p><strong>{esc(question)}</strong></p>
  <p class="muted">{esc(detail)}</p>
  <form method="post" action="{esc(action)}">
    {_hidden({**fields, "confirm": "yes"})}
    <div class="actions">
      <button class="danger" type="submit" data-busy="Working">{esc(confirm_label)}</button>
      <a class="btn secondary" href="{esc(cancel)}">Cancel, keep it</a>
    </div>
  </form>
</div>
"""
    return page(body, title=title)


def logout_page(email: str) -> str:
    """Signing out is a POST: this is where a plain link to it lands."""
    body = f"""
{_header("Sign out", email)}
<div class="card">
  <p>Sign out of {esc(email) or "this browser"}? Every other browser signed in to
  this account is signed out too.</p>
  <form method="post" action="/logout">
    <div class="actions">
      <button type="submit">Sign out</button>
      <a class="btn secondary" href="/">Stay signed in</a>
    </div>
  </form>
</div>
"""
    return page(body, title="Sign out")


def expired_page(reason: str) -> str:
    """A refused form post, with the way back."""
    body = f"""
{_header("That did not go through")}
<div class="card">
  <p><strong>Nothing was changed.</strong> The request was refused because
  {esc(reason)}.</p>
  <p class="muted">This happens when a page stayed open across a sign-in, or when
  another site tried to act on your behalf. Go back, reload the page and try
  again.</p>
  <div class="actions"><a class="btn" href="/">Back to the dashboard</a></div>
</div>
"""
    return page(body, title="Request refused")


# ---------------------------------------------------------------------------
# Mailbox and calendar forms
# ---------------------------------------------------------------------------


def _value(values: dict[str, Any] | None, name: str, default: str = "") -> str:
    if not values:
        return esc(default)
    raw = values.get(name)
    if raw is None or raw == "":
        return esc(default)
    return esc(raw)


def _checked(values: dict[str, Any] | None, name: str, default: bool = False) -> str:
    if values is None:
        return " checked" if default else ""
    return " checked" if values.get(name) else ""


def mailbox_form_page(
    connection: dict[str, Any], error: str = "", values: dict[str, Any] | None = None
) -> str:
    """Attach a mailbox. Everything typed survives a failed attempt but the password."""
    lost_password = (
        '<p class="muted">Your password was not kept, so type it again. Everything '
        "else is as you left it.</p>"
        if error and values
        else ""
    )
    body = f"""
{_header("Add a mailbox", connection.get("email", ""), "connectors")}
<p class="muted">Connector: <strong>{esc(connection['label'])}</strong></p>
{_notice(error, "error")}{lost_password}
<form method="post" action="/connections/{esc(connection['connection_id'])}/mailboxes">
  <div class="card">
    <label for="address">Email address<span class="hint">The mailbox the agent
      will read and send from.</span></label>
    <div class="row">
      <input id="address" name="address" type="email" required autocomplete="email"
        placeholder="you@example.com" value="{_value(values, 'address')}">
      <button type="button" class="secondary" data-action="detect">Detect settings</button>
    </div>

    <label for="secret" id="secret_label"><span id="secret_label_text">Password or app
      password</span></label>
    <input id="secret" name="secret" type="password" required autocomplete="off">
    <p id="provider_note" class="status" role="status"{"" if values and values.get("provider_note") else " hidden"}>
      {_value(values, "provider_note")}</p>
    <p class="muted">Most providers refuse your normal password here and want an
      app password: Gmail, iCloud, Fastmail and Yahoo all do.</p>
    <p id="probe" class="status" role="status" aria-live="polite"></p>
  </div>

  <div class="card">
    <h2>Servers</h2>
    <div class="grid">
      <label for="imap_host">IMAP server<input id="imap_host" name="imap_host" required
        placeholder="imap.example.com" value="{_value(values, 'imap_host')}"></label>
      <label for="imap_port">IMAP port<input id="imap_port" name="imap_port" type="number"
        min="1" max="65535" value="{_value(values, 'imap_port', '993')}"></label>
      <label for="imap_security">IMAP security<select id="imap_security" name="imap_security">
        {_option_list(SECURITY_CHOICES, (values or {}).get("imap_security", "ssl"))}</select></label>
      <label for="smtp_host">SMTP server<input id="smtp_host" name="smtp_host" required
        placeholder="smtp.example.com" value="{_value(values, 'smtp_host')}"></label>
      <label for="smtp_port">SMTP port<input id="smtp_port" name="smtp_port" type="number"
        min="1" max="65535" value="{_value(values, 'smtp_port', '587')}"></label>
      <label for="smtp_security">SMTP security<select id="smtp_security" name="smtp_security">
        {_option_list(SECURITY_CHOICES, (values or {}).get("smtp_security", "starttls"))}</select></label>
    </div>
  </div>

  <div class="card">
    <h2>Identity</h2>
    <label for="from_name">Display name<span class="hint">Optional, shown in the
      From header.</span><input id="from_name" name="from_name" autocomplete="off"
      placeholder="Ada Lovelace" value="{_value(values, 'from_name')}"></label>
    <label for="from_address">Send from<span class="hint">Optional. Set this when mail
      should go out as another address, such as an iCloud+ custom domain.</span>
      <input id="from_address" name="from_address" type="email" autocomplete="off"
      placeholder="you@your-domain.com" value="{_value(values, 'from_address')}"></label>
    <label for="aliases">Other sending addresses<span class="hint">Optional,
      comma-separated. The agent may only send as one of these.</span>
      <input id="aliases" name="aliases" autocomplete="off"
      placeholder="contact@your-domain.com, billing@your-domain.com"
      value="{_value(values, 'aliases')}"></label>
  </div>

  <fieldset class="scope">
    <legend>What the agent may do with this mailbox</legend>
    <label class="check" for="read_only">
      <input type="checkbox" id="read_only" name="read_only" value="1"{_checked(values, "read_only")}>
      <span><strong>Read only.</strong> The agent can read and search this mailbox,
      but never send, move or delete. Leave this off and it can do all of that.</span>
    </label>
  </fieldset>

  <details id="advanced">
    <summary>Advanced</summary>
    <div class="grid">
      <label for="imap_username">IMAP username<span class="hint">Defaults to the
        address.</span><input id="imap_username" name="imap_username" autocomplete="off"
        value="{_value(values, 'imap_username')}"></label>
      <label for="smtp_username">SMTP username<span class="hint">Defaults to the
        address.</span><input id="smtp_username" name="smtp_username" autocomplete="off"
        value="{_value(values, 'smtp_username')}"></label>
    </div>
    <label for="auth">Authentication<select id="auth" name="auth">
      <option value="password"{" selected" if (values or {}).get("auth") != "xoauth2" else ""}>
        Password or app password</option>
      <option value="xoauth2"{" selected" if (values or {}).get("auth") == "xoauth2" else ""}>
        OAuth 2 (XOAUTH2)</option>
    </select></label>
    <div id="oauth_fields" data-js-hidden="1">
      <label for="oauth_provider">OAuth provider<select id="oauth_provider" name="oauth_provider">
        {_option_list([("google", "Google"), ("microsoft", "Microsoft")],
                      (values or {}).get("oauth_provider", "google"))}</select></label>
      <div class="grid">
        <label for="oauth_client_id">OAuth client ID<input id="oauth_client_id"
          name="oauth_client_id" autocomplete="off"
          value="{_value(values, 'oauth_client_id')}"></label>
        <label for="oauth_client_secret">OAuth client secret<input id="oauth_client_secret"
          name="oauth_client_secret" type="password" autocomplete="off"></label>
      </div>
      <label for="oauth_tenant">Microsoft tenant<span class="hint">Defaults to
        common.</span><input id="oauth_tenant" name="oauth_tenant"
        value="{_value(values, 'oauth_tenant', 'common')}"></label>
    </div>
    <label class="check" for="verify_ssl">
      <input type="checkbox" id="verify_ssl" name="verify_ssl" value="1"{_checked(values, "verify_ssl", True)}>
      <span>Verify TLS certificates. Turn this off only for a local bridge such as
      Proton Mail Bridge.</span>
    </label>
  </details>

  <div class="actions">
    <button type="button" class="secondary" data-action="test-mailbox">Test connection</button>
    <button type="submit" data-busy="Checking and saving">Add mailbox</button>
  </div>
  <p class="muted">The mailbox is saved only once IMAP and SMTP have both
  answered, so a wrong password cannot be stored silently.</p>
</form>
"""
    return page(body, title="Add a mailbox")


def calendar_form_page(
    connection: dict[str, Any], error: str = "", values: dict[str, Any] | None = None
) -> str:
    lost_password = (
        '<p class="muted">Your password was not kept, so type it again. Everything '
        "else is as you left it.</p>"
        if error and values
        else ""
    )
    body = f"""
{_header("Add a calendar", connection.get("email", ""), "connectors")}
<p class="muted">Connector: <strong>{esc(connection['label'])}</strong></p>
{_notice(error, "error")}{lost_password}
<form method="post" action="/connections/{esc(connection['connection_id'])}/calendars">
  <div class="card">
    <label for="address">Account address<span class="hint">The account the
      calendars belong to.</span>
      <input id="address" name="address" type="email" required autocomplete="email"
        placeholder="you@icloud.com" value="{_value(values, 'address')}"></label>
    <label for="secret">Password<input id="secret" name="secret" type="password"
      required autocomplete="off"></label>
    <p class="muted">Apple iCloud needs an <strong>app-specific password</strong>
      (appleid.apple.com &rarr; Sign-In and Security), not your Apple ID password.
      The server address is known for iCloud, Fastmail and Google.</p>
    <p id="probe" class="status" role="status" aria-live="polite"></p>
  </div>

  <div class="card">
    <h2>Server</h2>
    <div class="grid">
      <label for="url">CalDAV URL<span class="hint">Optional for known
        providers.</span><input id="url" name="url" autocomplete="off"
        placeholder="https://caldav.example.com" value="{_value(values, 'url')}"></label>
      <label for="username">Username<span class="hint">Defaults to the
        address.</span><input id="username" name="username" autocomplete="off"
        value="{_value(values, 'username')}"></label>
      <label for="timezone">Timezone<span class="hint">How times written without an
        offset are read. Use your own, e.g. Europe/Paris or America/Chicago.</span>
        <input id="timezone" name="timezone" required placeholder="Europe/Paris"
        value="{_value(values, 'timezone')}"></label>
      <label for="default_calendar">Default calendar<span class="hint">Optional; the
        first one is used otherwise.</span>
        <input id="default_calendar" name="default_calendar" autocomplete="off"
        placeholder="Personal" value="{_value(values, 'default_calendar')}"></label>
    </div>
    <label for="default_calendar_pick" id="default_calendar_pick_label" data-js-hidden="1">
      Calendars found<span class="hint">Pick one to use as the default.</span>
      <select id="default_calendar_pick"></select></label>
  </div>

  <fieldset class="scope">
    <legend>What the agent may do with these calendars</legend>
    <label class="check" for="read_only">
      <input type="checkbox" id="read_only" name="read_only" value="1"{_checked(values, "read_only")}>
      <span><strong>Read only.</strong> The agent can read events and find free time,
      but never create, change, delete or answer invitations.</span>
    </label>
  </fieldset>

  <div class="actions">
    <button type="button" class="secondary" data-action="test-calendar">Test connection</button>
    <button type="submit" data-busy="Checking and saving">Add calendar</button>
  </div>
  <p class="muted">The calendar is saved only once the server has answered.</p>
</form>
"""
    return page(body, title="Add a calendar")


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------


def logs_page(
    email: str,
    entries: list[dict[str, Any]],
    *,
    connections: list[tuple[str, str]],
    stats: dict[str, Any],
    filters: dict[str, str],
    limit: int,
    truncated: bool = False,
    filtered: bool = False,
    overview: Any = None,
) -> str:
    """Every tool call the agents made, scoped to this user's connectors."""
    tool_options = [("", "All tools")] + [(t, t) for t in stats.get("tools", [])]
    account_options = [("", "All accounts")] + [(a, a) for a in stats.get("accounts", [])]
    connection_options = [("", "All connectors"), *connections]
    status_options = [
        ("", "Any outcome"),
        ("ok", "Succeeded"),
        ("error", "Failed"),
        ("denied", "Refused (read-only)"),
    ]

    if entries:
        rows = []
        for entry in entries:
            arguments = ", ".join(
                f"{key}={value}" for key, value in (entry["arguments"] or {}).items()
            )
            detail = (
                f'<div class="muted small-text">{esc(entry["detail"])}</div>'
                if entry["detail"]
                else ""
            )
            outcome = {
                "ok": ("Succeeded", "read"),
                "error": ("Failed", "write"),
                "denied": ("Refused", "idle"),
            }.get(entry["status"], ("Failed", "write"))
            rows.append(
                "<tr>"
                f'<td><span class="label">When</span>'
                f'<span data-ts="{esc(entry["ts"])}">{esc(entry["when"])}</span></td>'
                f'<td><span class="label">Action</span><code>{esc(entry["tool"])}</code>'
                + (
                    f'<div class="muted small-text">{esc(arguments)}</div>'
                    if arguments
                    else ""
                )
                + detail
                + "</td>"
                f'<td><span class="label">Account</span>{esc(entry["account"] or "-")}'
                f'<div class="muted small-text">'
                f'{esc(entry["connection_label"] or entry["connection_id"])}</div></td>'
                f'<td><span class="label">Outcome</span>{_badge(outcome[0], outcome[1])}</td>'
                f'<td><span class="label">Took</span>{esc(entry["duration_ms"])} ms</td>'
                "</tr>"
            )
        table = (
            '<div class="table-wrap"><table class="logs stack">'
            '<caption class="sr-only">Tool calls, most recent first</caption>'
            '<thead><tr><th scope="col">When</th><th scope="col">Action</th>'
            '<th scope="col">Account</th><th scope="col">Outcome</th>'
            '<th scope="col">Took</th></tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
        note = (
            f'<p class="muted">Showing the {len(entries)} most recent of '
            f"{stats.get('total', 0)} recorded calls. Raise the limit to see more.</p>"
            if truncated
            else f'<p class="muted">{len(entries)} call(s).</p>'
        )
    elif filtered:
        table = (
            '<p><strong>No call matches these filters.</strong></p>'
            '<p class="muted">There are still '
            f"{esc(stats.get('total', 0))} recorded calls.</p>"
            '<p><a class="btn secondary" href="/logs">Clear filters</a></p>'
        )
        note = ""
    else:
        table = (
            "<p><strong>Nothing recorded yet.</strong></p>"
            '<p class="muted">Every tool call an agent makes through your connectors '
            "shows up here: what it ran, on which mailbox, and how it went.</p>"
        )
        note = ""

    if overview is not None and overview.total:
        days = [
            charts.DayPoint(
                label=day["label"], full=day["full"], ok=day["ok"], failed=day["failed"]
            )
            for day in overview.days
        ]
        plots = f"""
<div class="card charts">
  {charts.daily_activity_chart(days, title=f"Calls per day, last {len(days)} days")}
  {charts.tool_usage_chart(overview.tools[:6], title="Most used tools")}
</div>"""
    else:
        plots = ""

    body = f"""
{_header("Activity", email, "logs")}
<div class="card">
  <div class="stats">
    <div><b>{esc(stats.get('total', 0))}</b><span>recorded calls</span></div>
    <div><b>{esc(stats.get('last_24h', 0))}</b><span>in the last 24 hours</span></div>
    <div><b>{esc(stats.get('errors', 0))}</b><span>failed or refused</span></div>
  </div>
</div>
{plots}

<form method="get" action="/logs" class="card filters">
  <label for="f_connection">Connector<select id="f_connection" name="connection_id">
    {_option_list(connection_options, filters.get("connection_id", ""))}</select></label>
  <label for="f_account">Account<select id="f_account" name="account">
    {_option_list(account_options, filters.get("account", ""))}</select></label>
  <label for="f_tool">Tool<select id="f_tool" name="tool">
    {_option_list(tool_options, filters.get("tool", ""))}</select></label>
  <label for="f_status">Outcome<select id="f_status" name="status">
    {_option_list(status_options, filters.get("status", ""))}</select></label>
  <label for="f_limit">Limit<input id="f_limit" type="number" name="limit"
    value="{esc(limit)}" min="1" max="1000"></label>
  <button type="submit">Apply</button>
  <a class="btn secondary" href="/logs">Reset</a>
</form>

{note}
<div class="card">{table}</div>
<p class="muted">Subjects, recipients, folders and UIDs are recorded, so this can
answer what was sent and to whom. Message bodies, attachments and credentials
never are.</p>
"""
    return page(body, title="Activity")
