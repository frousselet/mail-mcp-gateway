"""HTML for the onboarding web UI.

Deliberately dependency-free: a handful of server-rendered pages, one small
stylesheet and the WebAuthn glue the browser needs. Nothing here talks to the
store; :mod:`mail_mcp.web` passes in plain data.
"""

from __future__ import annotations

import html
import os
from typing import Any

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail MCP Gateway</title>
<style>
  :root { color-scheme: light dark; --accent: #2d6cdf; --danger: #c0392b; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 820px;
         margin: 2.5rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.5rem; } h2 { font-size: 1.15rem; margin-top: 2rem; }
  h3 { font-size: 1rem; margin: 1.2rem 0 .3rem; }
  label { display: block; margin-top: .9rem; font-weight: 600; }
  input, select { width: 100%; padding: .55rem; margin-top: .3rem;
         border: 1px solid #8888; border-radius: 6px; font-size: 1rem;
         background: transparent; color: inherit; }
  input[type=checkbox] { width: auto; margin-right: .4rem; }
  small { color: #888; font-weight: 400; }
  button { margin-top: 1rem; padding: .6rem 1.1rem; font-size: 1rem;
           border-radius: 6px; border: 0; background: var(--accent); color: #fff;
           cursor: pointer; }
  button.secondary { background: #666; }
  button.danger { background: var(--danger); }
  button.small { padding: .3rem .6rem; font-size: .85rem; margin: 0; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.2rem;
          margin-top: 1rem; }
  code { background: #8882; padding: .15rem .4rem; border-radius: 4px;
         word-break: break-all; }
  .muted { color: #888; font-size: .9rem; }
  .err { color: var(--danger); white-space: pre-wrap; }
  .ok { color: #1e8449; }
  .top { display: flex; justify-content: space-between; align-items: center;
         flex-wrap: wrap; gap: .5rem; }
  .row { margin: .6rem 0; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1rem; }
  .inline { display: flex; gap: .5rem; align-items: flex-end; flex-wrap: wrap; }
  table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  th, td { text-align: left; padding: .45rem .3rem; border-bottom: 1px solid #8883;
           vertical-align: top; }
  details summary { cursor: pointer; margin-top: 1rem; font-weight: 600; }
  .filters { display: flex; gap: .6rem; flex-wrap: wrap; align-items: flex-end; }
  .filters label { margin-top: 0; font-size: .85rem; }
  .filters select, .filters input { min-width: 9rem; }
  .filters button { margin-top: 0; }
  .pill { display: inline-block; padding: .1rem .45rem; border-radius: 999px;
          font-size: .75rem; font-weight: 600; }
  .pill.ok { background: #1e844933; color: #1e8449; }
  .pill.error { background: #c0392b33; color: var(--danger); }
  .pill.denied { background: #b9770e33; color: #b9770e; }
  .logs td { font-size: .9rem; }
  .logs .args { color: #888; font-size: .8rem; word-break: break-word; }
  .stats { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: .5rem 0 0; }
  .stats b { font-size: 1.2rem; display: block; }
  @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
</style></head><body>
{{body}}
</body></html>"""

COMMON_JS = """
<script>
function b64urlToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const p=s.length%4;
 if(p)s+='='.repeat(4-p);const b=atob(s);const u=new Uint8Array(b.length);
 for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer;}
function bufToB64url(buf){const u=new Uint8Array(buf);let s='';
 for(const b of u)s+=String.fromCharCode(b);
 return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
async function postJSON(url,body){const r=await fetch(url,{method:'POST',
 headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
 const j=await r.json().catch(()=>({}));
 if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j;}
function setErr(m){const e=document.getElementById('err');if(e)e.textContent=m||'';}
</script>
"""

WEBAUTHN_JS = """
<script>
async function doRegister(email,code){
 setErr('');
 const opts=await postJSON('/webauthn/register/begin',{email:email,code:code});
 opts.challenge=b64urlToBuf(opts.challenge);opts.user.id=b64urlToBuf(opts.user.id);
 if(opts.excludeCredentials)for(const c of opts.excludeCredentials)c.id=b64urlToBuf(c.id);
 const cred=await navigator.credentials.create({publicKey:opts});
 await postJSON('/webauthn/register/complete',{credential:{
   id:cred.id,rawId:bufToB64url(cred.rawId),type:cred.type,
   clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},
   response:{clientDataJSON:bufToB64url(cred.response.clientDataJSON),
    attestationObject:bufToB64url(cred.response.attestationObject),
    transports:cred.response.getTransports?cred.response.getTransports():[]}}});
 location.href='/';
}
async function doLogin(){
 setErr('');
 const opts=await postJSON('/webauthn/login/begin',{});
 opts.challenge=b64urlToBuf(opts.challenge);
 if(opts.allowCredentials)for(const c of opts.allowCredentials)c.id=b64urlToBuf(c.id);
 const cred=await navigator.credentials.get({publicKey:opts});const r=cred.response;
 await postJSON('/webauthn/login/complete',{credential:{
   id:cred.id,rawId:bufToB64url(cred.rawId),type:cred.type,
   clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},
   response:{clientDataJSON:bufToB64url(r.clientDataJSON),
    authenticatorData:bufToB64url(r.authenticatorData),
    signature:bufToB64url(r.signature),
    userHandle:r.userHandle?bufToB64url(r.userHandle):null}}});
 location.href='/';
}
</script>
"""

MAILBOX_JS = """
<script>
function val(id){const e=document.getElementById(id);return e?e.value.trim():'';}
function setVal(id,v){const e=document.getElementById(id);if(e&&v!==undefined&&v!==null)e.value=v;}
function status(msg,cls){const e=document.getElementById('probe');
 if(e){e.textContent=msg;e.className=cls||'muted';}}
function settingsPayload(){
 return {address:val('address'),imap_host:val('imap_host'),imap_port:val('imap_port'),
  imap_security:val('imap_security'),imap_username:val('imap_username'),
  smtp_host:val('smtp_host'),smtp_port:val('smtp_port'),
  smtp_security:val('smtp_security'),smtp_username:val('smtp_username'),
  auth:val('auth'),secret:val('secret'),oauth_provider:val('oauth_provider'),
  oauth_client_id:val('oauth_client_id'),oauth_client_secret:val('oauth_client_secret'),
  oauth_tenant:val('oauth_tenant'),
  verify_ssl:document.getElementById('verify_ssl').checked};
}
async function detect(){
 const address=val('address');
 if(!address){status('Enter an address first.','err');return;}
 status('Looking up the provider settings...');
 try{
  const j=await postJSON('/discover',{address:address});
  if(!j.found){status('No published settings for this domain: fill the servers in by hand.','err');return;}
  setVal('imap_host',j.settings.imap_host);setVal('imap_port',j.settings.imap_port);
  setVal('imap_security',j.settings.imap_security);
  setVal('smtp_host',j.settings.smtp_host);setVal('smtp_port',j.settings.smtp_port);
  setVal('smtp_security',j.settings.smtp_security);
  const notes=(j.settings.notes||[]).join(' ');
  status('Found via '+j.settings.source+(j.settings.provider_name?(' ('+j.settings.provider_name+')'):'')+'. '+notes,'ok');
  document.getElementById('advanced').open=true;
 }catch(e){status(e.message,'err');}
}
async function testConn(){
 status('Connecting to IMAP and SMTP...');
 try{
  const j=await postJSON('/test',settingsPayload());
  status(j.message,j.ok?'ok':'err');
 }catch(e){status(e.message,'err');}
}
function onAuthChange(){
 const oauth=val('auth')==='xoauth2';
 document.getElementById('oauth_fields').style.display=oauth?'block':'none';
 document.getElementById('secret_label').textContent=oauth?'OAuth refresh token':'Password or app password';
}
</script>
"""


def page(body: str) -> str:
    return _PAGE.replace("{{body}}", body)


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def register_page() -> str:
    code_field = ""
    if os.environ.get("MAIL_ONBOARD_CODE"):
        code_field = (
            '<label>Invite code<input id="code" autocomplete="off" required></label>'
        )
    return page(f"""
<h1>Create your account</h1>
<p class="muted">Passwordless: your account is secured with a passkey (Touch ID,
Windows Hello, a security key or your phone).</p>
<p id="err" class="err"></p>
<div class="card">
  <label>Email<input id="email" type="email" required placeholder="you@example.com"></label>
  {code_field}
  <button onclick="const e=document.getElementById('email').value.trim();
    const c=document.getElementById('code')?document.getElementById('code').value.trim():'';
    if(!e){{setErr('Enter an email.');return;}}
    doRegister(e,c).catch(x=>setErr(x.message))">Create passkey</button>
</div>
<p class="muted">Already have an account? <a href="/login">Sign in</a></p>
{COMMON_JS}{WEBAUTHN_JS}
""")


def login_page() -> str:
    return page(f"""
<h1>Sign in</h1>
<p id="err" class="err"></p>
<div class="card">
  <button onclick="doLogin().catch(x=>setErr(x.message))">Sign in with passkey</button>
</div>
<p class="muted">No account yet? <a href="/register">Create one</a></p>
{COMMON_JS}{WEBAUTHN_JS}
""")


def dashboard_page(
    email: str, connections: list[dict[str, Any]], error: str = "", notice: str = ""
) -> str:
    error_html = f'<p class="err">{esc(error)}</p>' if error else ""
    notice_html = f'<p class="ok">{esc(notice)}</p>' if notice else ""

    if connections:
        cards = []
        for connection in connections:
            mailboxes = connection["accounts"]
            if mailboxes:
                rows = "".join(
                    f"<tr><td>{esc(box['address'])}"
                    + (" <small>(default)</small>" if box["is_default"] else "")
                    + f"<br><small class='muted'>{esc(box['imap'])} | "
                    f"{esc(box['smtp'])} | {esc(box['auth'])}"
                    + (" | read-only" if box["read_only"] else "")
                    + "</small></td>"
                    f"<td style='width:1%;white-space:nowrap'>"
                    f'<form method="post" action="/mailboxes/delete" style="display:inline">'
                    f'<input type="hidden" name="connection_id" value="{esc(connection["connection_id"])}">'
                    f'<input type="hidden" name="account_id" value="{esc(box["account_id"])}">'
                    f'<button class="small danger" '
                    f"onclick=\"return confirm('Remove {esc(box['address'])} from this connector?')\">"
                    f"Remove</button></form></td></tr>"
                    for box in mailboxes
                )
                table = f"<table><tr><th>Mailbox</th><th></th></tr>{rows}</table>"
            else:
                table = (
                    "<p class='muted'>No mailbox yet. Add one to make this "
                    "connector useful.</p>"
                )
            cards.append(f"""
<div class="card">
  <div class="top">
    <h3 style="margin:0">{esc(connection['label'] or 'Connector')}</h3>
    <span class="muted">{len(mailboxes)} mailbox(es)</span>
  </div>
  <div class="row muted">MCP URL: <code>{esc(connection['mcp_url'])}</code><br>
    OAuth client ID: <code>{esc(connection['client_id'])}</code></div>
  {table}
  <div class="inline">
    <a href="/connections/{esc(connection['connection_id'])}"><button class="small">Add a mailbox</button></a>
    <form method="post" action="/connections/rotate" style="margin:0">
      <input type="hidden" name="connection_id" value="{esc(connection['connection_id'])}">
      <button class="small secondary"
        onclick="return confirm('Issue a new client secret? The agent will have to reconnect.')">
        New secret</button>
    </form>
    <form method="post" action="/connections/delete" style="margin:0">
      <input type="hidden" name="connection_id" value="{esc(connection['connection_id'])}">
      <button class="small danger"
        onclick="return confirm('Delete this connector? The agent loses access immediately.')">
        Delete</button>
    </form>
  </div>
</div>""")
        connections_html = "".join(cards)
    else:
        connections_html = (
            "<p class='muted'>No connector yet. Create one below, then attach "
            "the mailboxes it should serve.</p>"
        )

    gate = ""
    if os.environ.get("MAIL_ONBOARD_CODE"):
        gate = ('<label>Invite code<input name="onboard_code" required '
                'autocomplete="off"></label>')

    return page(f"""
<div class="top"><h1>Your MCP connectors</h1>
  <span class="muted">{esc(email)} &middot; <a href="/logs">Activity log</a>
    &middot; <a href="/logout">Sign out</a></span></div>
{error_html}{notice_html}
{connections_html}

<h2>New connector</h2>
<p class="muted">One connector is one MCP connection for an agent. Give it a
single mailbox for a dedicated connector, or several to let the agent work
across addresses.</p>
<form method="post" action="/connections/new" class="card">
  {gate}
  <label>Name <small>(what you will recognise it by)</small>
    <input name="label" required autocomplete="off" placeholder="Work inbox"></label>
  <button type="submit">Create connector</button>
</form>
""")


def _option_list(options: list[tuple[str, str]], selected: str) -> str:
    return "".join(
        f'<option value="{esc(value)}"{" selected" if value == selected else ""}>'
        f"{esc(text)}</option>"
        for value, text in options
    )


def mailbox_form_page(connection: dict[str, Any], error: str = "") -> str:
    error_html = f'<p class="err">{esc(error)}</p>' if error else ""
    security = [("ssl", "SSL/TLS"), ("starttls", "STARTTLS"), ("none", "None (plain)")]
    return page(f"""
<div class="top"><h1>Add a mailbox</h1>
  <span class="muted"><a href="/">Back to connectors</a></span></div>
<p class="muted">Connector: <b>{esc(connection['label'])}</b></p>
{error_html}
<form method="post" action="/connections/{esc(connection['connection_id'])}/mailboxes"
      class="card">
  <label>Email address
    <div class="inline">
      <input id="address" name="address" type="email" required style="flex:1"
             placeholder="you@example.com">
      <button type="button" class="secondary" onclick="detect()">Detect settings</button>
    </div></label>
  <label id="secret_label">Password or app password
    <input id="secret" name="secret" type="password" required autocomplete="off"></label>
  <p id="probe" class="muted">Most providers require an app password rather than
    your normal one.</p>

  <label>Display name <small>(optional, used in the From header)</small>
    <input id="from_name" name="from_name" autocomplete="off" placeholder="Ada Lovelace"></label>

  <div class="grid">
    <label>IMAP server<input id="imap_host" name="imap_host" required
      placeholder="imap.example.com"></label>
    <label>IMAP port<input id="imap_port" name="imap_port" type="number" value="993"></label>
    <label>IMAP security<select id="imap_security" name="imap_security">
      {_option_list(security, "ssl")}</select></label>
    <label>SMTP server<input id="smtp_host" name="smtp_host" required
      placeholder="smtp.example.com"></label>
    <label>SMTP port<input id="smtp_port" name="smtp_port" type="number" value="587"></label>
    <label>SMTP security<select id="smtp_security" name="smtp_security">
      {_option_list(security, "starttls")}</select></label>
  </div>

  <details id="advanced"><summary>Advanced</summary>
    <div class="grid">
      <label>IMAP username <small>(defaults to the address)</small>
        <input id="imap_username" name="imap_username" autocomplete="off"></label>
      <label>SMTP username <small>(defaults to the address)</small>
        <input id="smtp_username" name="smtp_username" autocomplete="off"></label>
    </div>
    <label>Authentication<select id="auth" name="auth" onchange="onAuthChange()">
      <option value="password">Password / app password</option>
      <option value="xoauth2">OAuth 2 (XOAUTH2)</option></select></label>
    <div id="oauth_fields" style="display:none">
      <label>OAuth provider<select id="oauth_provider" name="oauth_provider">
        <option value="google">Google</option>
        <option value="microsoft">Microsoft</option></select></label>
      <div class="grid">
        <label>OAuth client ID<input id="oauth_client_id" name="oauth_client_id"
          autocomplete="off"></label>
        <label>OAuth client secret<input id="oauth_client_secret" type="password"
          name="oauth_client_secret" autocomplete="off"></label>
      </div>
      <label>Microsoft tenant <small>(default: common)</small>
        <input id="oauth_tenant" name="oauth_tenant" value="common"></label>
    </div>
    <label><input type="checkbox" id="verify_ssl" name="verify_ssl" value="1" checked>
      Verify TLS certificates <small>(uncheck only for a local bridge)</small></label>
    <label><input type="checkbox" name="read_only" value="1">
      Read-only <small>(the agent can read but never send, move or delete)</small></label>
  </details>

  <div class="inline">
    <button type="button" class="secondary" onclick="testConn()">Test connection</button>
    <button type="submit">Add mailbox</button>
  </div>
</form>
{COMMON_JS}
{MAILBOX_JS}
""")


def credentials_page(
    base_url: str, connection: dict[str, Any], client_secret: str
) -> str:
    redirects = ", ".join(esc(uri) for uri in connection.get("redirect_uris", []))
    return page(f"""
<h1>Connector ready</h1>
<p>In Claude, open <b>Settings &rarr; Connectors &rarr; Add custom connector</b>
and enter:</p>
<div class="card">
  <div class="row"><b>MCP server URL</b><br><code>{esc(base_url)}/mcp</code></div>
  <div class="row"><b>OAuth client ID</b><br><code>{esc(connection['client_id'])}</code></div>
  <div class="row"><b>OAuth client secret</b><br><code>{esc(client_secret)}</code></div>
</div>
<p class="muted">Copy the secret now: it is not shown again (you can issue a new
one from the dashboard). Authorized redirects: {redirects}.</p>
<p><a href="/connections/{esc(connection['connection_id'])}">Add a mailbox to this
connector</a> &middot; <a href="/">Back to your connectors</a></p>
""")


LOGS_JS = """
<script>
// Timestamps are rendered in UTC; show them in the reader's own timezone.
for (const cell of document.querySelectorAll('[data-ts]')) {
  const ms = Number(cell.getAttribute('data-ts')) * 1000;
  if (!Number.isNaN(ms)) cell.textContent = new Date(ms).toLocaleString();
}
</script>
"""


def _select(name: str, options: list[tuple[str, str]], selected: str) -> str:
    return (
        f'<select name="{esc(name)}" onchange="this.form.submit()">'
        + _option_list(options, selected)
        + "</select>"
    )


def logs_page(
    email: str,
    entries: list[dict[str, Any]],
    *,
    connections: list[tuple[str, str]],
    stats: dict[str, Any],
    filters: dict[str, str],
    limit: int,
    truncated: bool = False,
) -> str:
    """The activity view: every MCP tool call this user's connectors served."""
    tool_options = [("", "All tools")] + [(t, t) for t in stats.get("tools", [])]
    account_options = [("", "All mailboxes")] + [
        (a, a) for a in stats.get("accounts", [])
    ]
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
                f'<div class="args">{esc(entry["detail"])}</div>'
                if entry["detail"]
                else ""
            )
            rows.append(
                f"<tr>"
                f'<td style="white-space:nowrap" data-ts="{esc(entry["ts"])}">'
                f'{esc(entry["when"])}</td>'
                f'<td><code>{esc(entry["tool"])}</code>'
                + (f'<div class="args">{esc(arguments)}</div>' if arguments else "")
                + detail
                + "</td>"
                f'<td>{esc(entry["account"] or "-")}<div class="args">'
                f'{esc(entry["connection_label"] or entry["connection_id"])}</div></td>'
                f'<td><span class="pill {esc(entry["status"])}">'
                f'{esc(entry["status"])}</span></td>'
                f'<td style="white-space:nowrap">{esc(entry["duration_ms"])} ms</td>'
                f"</tr>"
            )
        table = (
            '<table class="logs"><tr><th>When</th><th>Action</th>'
            "<th>Mailbox</th><th>Outcome</th><th>Took</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        note = (
            f'<p class="muted">Showing the {len(entries)} most recent of the last '
            f"{stats.get('total', 0)} recorded calls. Raise the limit to see more.</p>"
            if truncated
            else f'<p class="muted">{len(entries)} call(s).</p>'
        )
    else:
        table = (
            "<p class='muted'>Nothing recorded yet. Every tool call an agent makes "
            "through your connectors shows up here.</p>"
        )
        note = ""

    return page(f"""
<div class="top"><h1>Activity log</h1>
  <span class="muted">{esc(email)} &middot; <a href="/">Connectors</a>
    &middot; <a href="/logout">Sign out</a></span></div>

<div class="card">
  <div class="stats">
    <span><b>{esc(stats.get('total', 0))}</b> recorded calls</span>
    <span><b>{esc(stats.get('last_24h', 0))}</b> in the last 24h</span>
    <span><b>{esc(stats.get('errors', 0))}</b> failed or refused</span>
  </div>
</div>

<form method="get" action="/logs" class="card filters">
  <label>Connector<br>{_select("connection_id", connection_options,
                               filters.get("connection_id", ""))}</label>
  <label>Mailbox<br>{_select("account", account_options, filters.get("account", ""))}</label>
  <label>Tool<br>{_select("tool", tool_options, filters.get("tool", ""))}</label>
  <label>Outcome<br>{_select("status", status_options, filters.get("status", ""))}</label>
  <label>Limit<br><input type="number" name="limit" value="{esc(limit)}" min="1"
    max="1000" style="min-width:6rem"></label>
  <button type="submit">Apply</button>
  <a href="/logs"><button type="button" class="secondary">Reset</button></a>
</form>

{note}
<div class="card">{table}</div>
<p class="muted">Message bodies, attachments and credentials are never recorded.
Subjects, recipients, folders and UIDs are, so the log can answer what was sent
and to whom.</p>
{LOGS_JS}
""")
