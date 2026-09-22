"""The stylesheet and the script, served as real assets rather than inlined.

Keeping them out of the HTML buys three things: the pages carry no inline
``style`` or ``on*`` attribute, so a strict Content-Security-Policy can forbid
both; the browser caches them; and the design tokens live in one place instead
of being sprinkled through f-strings.

No build step, no dependency: these are Python strings served by Python routes.
Their version is the hash of their content, so a changed asset busts the cache
by itself.
"""

from __future__ import annotations

import hashlib

APP_CSS = """
/* ---------------------------------------------------------------- tokens */
:root {
  color-scheme: light dark;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

  --fs-xs: .75rem; --fs-sm: .8125rem; --fs-md: .9375rem; --fs-base: 1rem;
  --fs-lg: 1.125rem; --fs-xl: 1.375rem; --fs-2xl: 1.75rem;
  --lh: 1.55; --lh-tight: 1.25;

  --s1: .25rem; --s2: .5rem; --s3: .75rem; --s4: 1rem;
  --s5: 1.5rem; --s6: 2rem; --s7: 3rem;
  --r-sm: 6px; --r-md: 10px; --r-lg: 14px;

  --bg: #fbfbfc; --surface: #ffffff; --surface-2: #f2f4f7;
  --text: #16181d; --muted: #565c66;
  --border: #d5d9e0; --border-strong: #767d8a;
  --accent: #1f5fd0; --accent-hover: #18499f; --accent-ink: #ffffff;
  --danger: #b32218; --danger-hover: #8e1b13;
  --ok: #136b3a; --warn: #8a5300;
  --tint-ok: #136b3a1a; --tint-danger: #b322181a; --tint-warn: #8a53001a;
  --tint-accent: #1f5fd014;
  --focus: #1f5fd0; --shadow: 0 1px 2px rgb(16 24 40 / .06);
  /* Chart marks, validated against the light surface: CVD separation 28.4,
     both inside the lightness band, both over 3:1. */
  --chart-1: #1f5fd0; --chart-alert: #b32218;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1116; --surface: #181b21; --surface-2: #212530;
    --text: #e8eaef; --muted: #a6adb9;
    --border: #333a46; --border-strong: #7b8390;
    --accent: #6fa0f5; --accent-hover: #8ab4f8; --accent-ink: #0b0e14;
    --danger: #ff8d80; --danger-hover: #ffa89d;
    --ok: #5cd08c; --warn: #e6ab48;
    --tint-ok: #5cd08c26; --tint-danger: #ff8d8026; --tint-warn: #e6ab4826;
    --tint-accent: #6fa0f526;
    --focus: #8ab4f8; --shadow: none;
    /* Dark is selected, not flipped: these are the steps that pass the same
       six checks against #181b21 (separation 20.7, band, contrast). */
    --chart-1: #5590ea; --chart-alert: #e06a5e;
  }
}

/* ----------------------------------------------------------------- base */
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: var(--font); font-size: var(--fs-base); line-height: var(--lh);
}
.shell { max-width: 60rem; margin: 0 auto; padding: var(--s5) var(--s4) var(--s7); }
.shell-wide { max-width: 76rem; }
h1 { font-size: var(--fs-2xl); line-height: var(--lh-tight); margin: 0 0 var(--s2); }
h2 { font-size: var(--fs-xl); line-height: var(--lh-tight); margin: var(--s6) 0 var(--s3); }
h3 { font-size: var(--fs-lg); line-height: var(--lh-tight); margin: 0; }
p { margin: 0 0 var(--s3); }
a { color: var(--accent); }
a:hover { color: var(--accent-hover); }
code, .mono { font-family: var(--mono); font-size: var(--fs-sm); overflow-wrap: anywhere; }
code {
  background: var(--surface-2); border: 1px solid var(--border);
  padding: .1rem .35rem; border-radius: var(--r-sm);
}
.muted { color: var(--muted); font-size: var(--fs-md); }
.small-text { font-size: var(--fs-sm); }
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.skip {
  position: absolute; left: -9999px; top: var(--s2);
  background: var(--surface); color: var(--text); padding: var(--s2) var(--s3);
  border: 1px solid var(--border-strong); border-radius: var(--r-sm); z-index: 10;
}
.skip:focus { left: var(--s4); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: var(--r-sm); }
.danger:focus-visible { outline-color: var(--danger); }
hr { border: 0; border-top: 1px solid var(--border); margin: var(--s5) 0; }

/* --------------------------------------------------------------- header */
.top {
  display: flex; flex-wrap: wrap; gap: var(--s2) var(--s4);
  align-items: baseline; justify-content: space-between;
  padding-bottom: var(--s3); border-bottom: 1px solid var(--border);
  margin-bottom: var(--s5);
}
.top .who { color: var(--muted); font-size: var(--fs-md); }
nav.main { display: flex; gap: var(--s3); flex-wrap: wrap; align-items: baseline; }
nav.main a[aria-current="page"] { font-weight: 600; color: var(--text); text-decoration: none; }
form.inline { display: inline; margin: 0; }
button.linklike {
  background: none; border: 0; padding: 0; min-height: 0; font: inherit;
  color: var(--accent); text-decoration: underline; cursor: pointer;
}
button.linklike:hover { background: none; color: var(--accent-hover); }

/* -------------------------------------------------------------- buttons */
button, .btn {
  display: inline-flex; align-items: center; justify-content: center; gap: .45rem;
  min-height: 44px; padding: .6rem 1.05rem; margin: 0;
  font: inherit; font-size: var(--fs-base); font-weight: 600; line-height: 1.2;
  text-decoration: none; cursor: pointer;
  border: 1px solid transparent; border-radius: var(--r-sm);
  background: var(--accent); color: var(--accent-ink);
}
button:hover, .btn:hover { background: var(--accent-hover); color: var(--accent-ink); }
.secondary { background: var(--surface); color: var(--text); border-color: var(--border-strong); }
.secondary:hover { background: var(--surface-2); color: var(--text); }
.danger { background: var(--surface); color: var(--danger); border-color: var(--danger); }
.danger:hover { background: var(--tint-danger); color: var(--danger); }
button:disabled, .btn[aria-disabled="true"] { opacity: .55; cursor: not-allowed; }
.small { min-height: 36px; padding: .4rem .7rem; font-size: var(--fs-sm); white-space: nowrap; }
@media (pointer: coarse) { button.small, .btn.small { min-height: 44px; padding-inline: .9rem; } }
.actions { display: flex; flex-wrap: wrap; gap: var(--s2); align-items: center; }
.actions form { margin: 0; }

/* ---------------------------------------------------------------- cards */
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r-md); padding: var(--s4) var(--s4);
  margin-bottom: var(--s4); box-shadow: var(--shadow);
}
.card > :last-child { margin-bottom: 0; }
.card-head {
  display: flex; flex-wrap: wrap; gap: var(--s2) var(--s3);
  align-items: baseline; justify-content: space-between; margin-bottom: var(--s3);
}
.card-head h2 { margin: 0; font-size: var(--fs-lg); }
.kv { margin: var(--s2) 0; font-size: var(--fs-md); }
.kv dt { color: var(--muted); font-size: var(--fs-sm); margin-top: var(--s2); }
.kv dd { margin: 0 0 var(--s2); }

/* --------------------------------------------------------------- badges */
.badge {
  display: inline-flex; align-items: center; gap: .3rem;
  font-size: var(--fs-xs); font-weight: 600; letter-spacing: .01em;
  padding: .15rem .5rem; border-radius: 999px;
  border: 1px solid currentColor; white-space: nowrap;
}
.badge-read { color: var(--ok); background: var(--tint-ok); }
.badge-write { color: var(--warn); background: var(--tint-warn); }
.badge-default { color: var(--accent); background: var(--tint-accent); }
.badge-idle { color: var(--muted); background: var(--surface-2); }
.badge-good { color: var(--ok); background: var(--tint-ok); }
.badge-attn { color: var(--warn); background: var(--tint-warn); }
.badge-bad { color: var(--danger); background: var(--tint-danger); }

/* ---------------------------------------------------------------- forms */
form { margin: 0; }
label { display: block; margin-top: var(--s4); font-weight: 600; }
label .hint { display: block; font-weight: 400; color: var(--muted); font-size: var(--fs-sm); }
input, select, textarea {
  width: 100%; padding: .55rem .6rem; margin-top: var(--s1);
  font: inherit; font-size: var(--fs-base);
  color: var(--text); background: var(--surface);
  border: 1px solid var(--border-strong); border-radius: var(--r-sm);
}
input:disabled { background: var(--surface-2); }
.check { display: flex; gap: var(--s2); align-items: flex-start; margin-top: var(--s3); font-weight: 400; }
.check input { width: auto; margin: .2rem 0 0; min-width: 1.1rem; min-height: 1.1rem; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 var(--s4); }
@media (max-width: 40rem) { .grid { grid-template-columns: 1fr; } }
.row { display: flex; gap: var(--s2); align-items: flex-end; flex-wrap: wrap; }
.row > * { flex: 1 1 12rem; }
.row > button, .row > .btn { flex: 0 0 auto; }
fieldset { border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s3) var(--s4) var(--s4); margin: var(--s4) 0; }
legend { font-weight: 600; padding: 0 var(--s2); }
details { border: 1px solid var(--border); border-radius: var(--r-md); padding: var(--s3); margin-top: var(--s4); }
details > summary { cursor: pointer; font-weight: 600; }
.scope { border-color: var(--border-strong); background: var(--surface-2); }

/* -------------------------------------------------------------- notices */
.notice {
  padding: var(--s3) var(--s4); border-radius: var(--r-md);
  border: 1px solid; margin-bottom: var(--s4); font-size: var(--fs-md);
}
.notice-error { color: var(--danger); border-color: var(--danger); background: var(--tint-danger); }
.notice-ok { color: var(--ok); border-color: var(--ok); background: var(--tint-ok); }
.notice-warn { color: var(--warn); border-color: var(--warn); background: var(--tint-warn); }
.notice-info { color: var(--text); border-color: var(--border); background: var(--surface-2); }
.status { font-size: var(--fs-md); margin-top: var(--s2); }
.status-error { color: var(--danger); }
.status-ok { color: var(--ok); }
.status-busy { color: var(--muted); }

/* --------------------------------------------------------------- tables */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: var(--fs-md); }
caption { text-align: left; }
th, td { text-align: left; padding: var(--s2) var(--s2); border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: var(--fs-sm); color: var(--muted); font-weight: 600; }
tbody tr:last-child td { border-bottom: 0; }
.stack tbody td .label { display: none; }
@media (max-width: 40rem) {
  .stack thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  .stack tbody tr { display: block; border-bottom: 1px solid var(--border); padding: var(--s2) 0; }
  .stack tbody td { display: block; border: 0; padding: var(--s1) 0; }
  .stack tbody td .label { display: inline; color: var(--muted); font-size: var(--fs-sm); margin-right: var(--s2); }
}

/* --------------------------------------------------------------- charts */
.chart { margin: 0 0 var(--s5); }
.chart:last-child { margin-bottom: 0; }
.chart figcaption { font-weight: 600; margin-bottom: var(--s1); }
.legend { display: flex; flex-wrap: wrap; gap: var(--s4); align-items: center;
          color: var(--muted); font-size: var(--fs-sm); margin: 0 0 var(--s3); }
.key { width: 10px; height: 10px; border-radius: 2px; display: inline-block;
       margin-right: .4rem; vertical-align: -1px; }
.key-ok { background: var(--chart-1); }
.key-alert { background: var(--chart-alert); }

/* Columns: a stack per day, magnitudes carried by the vN classes below. */
.plot { display: grid; grid-template-columns: auto 1fr; grid-template-rows: 160px auto;
         column-gap: var(--s2); }
.scale { grid-row: 1; display: flex; flex-direction: column; justify-content: space-between;
         color: var(--muted); font-size: var(--fs-xs); text-align: right;
         font-variant-numeric: tabular-nums; }
.cols { grid-row: 1; grid-column: 2; display: flex; align-items: flex-end; gap: 2px;
        border-bottom: 1px solid var(--border-strong);
        background-image: linear-gradient(var(--border), var(--border));
        background-size: 100% 1px; background-position: 0 50%;
        background-repeat: no-repeat; }
.slot { position: relative; flex: 1; height: 100%; display: flex;
        align-items: flex-end; justify-content: center; }
.col { position: relative; display: flex; flex-direction: column; justify-content: flex-end;
       width: 100%; max-width: 22px; }  /* height comes from its own vN class */
.seg { display: block; width: 100%; }
.seg-ok { background: var(--chart-1); }
.seg-alert { background: var(--chart-alert); border-radius: 4px 4px 0 0; }
.seg.capped { border-radius: 4px 4px 0 0; }
.seg.gapped { margin-bottom: 2px; }  /* surface, not a stroke, does the separating */
.col-value { position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
             margin-bottom: var(--s1); color: var(--muted);
             font-size: var(--fs-xs); font-weight: 600; }
.axis { grid-row: 2; grid-column: 2; display: flex; gap: 2px; margin-top: var(--s1);
        color: var(--muted); font-size: var(--fs-xs); }
.axis .tick { flex: 1; text-align: center; font-variant-numeric: tabular-nums; }

/* Horizontal bars: label, track, value. */
.bars { display: grid; gap: var(--s2); }
.bar-row { display: grid; grid-template-columns: minmax(6rem, 11rem) 1fr 3ch;
           gap: var(--s3); align-items: center; }
.bar-label { color: var(--text); font-size: var(--fs-sm); text-align: right;
             overflow-wrap: anywhere; }
.bar-track { display: block; height: 18px; }
.bar { display: block; height: 100%; background: var(--chart-1);
       border-radius: 0 4px 4px 0; }
.bar-value { color: var(--muted); font-size: var(--fs-sm); font-weight: 600;
             font-variant-numeric: tabular-nums; }
@media (max-width: 34rem) {
  .bar-row { grid-template-columns: 1fr 3ch; }
  .bar-label { grid-column: 1 / -1; text-align: left; }
}

.c-ok { fill: var(--chart-1); }
.c-spark { width: 110px; height: 22px; vertical-align: middle; margin-right: var(--s2); }
.chart-data { border: 0; padding: 0; margin-top: var(--s3); }
.chart-data summary { font-weight: 400; font-size: var(--fs-sm); color: var(--muted); }
.charts { display: grid; gap: var(--s6); }
@media (forced-colors: active) {
  .seg-ok, .bar, .c-ok { background: CanvasText; fill: CanvasText; }
  .seg-alert { background: Highlight; }
}

/* ------------------------------------------------------------ dashboard */
.kpis {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(min(9.5rem, 100%), 1fr));
  gap: var(--s3); margin-bottom: var(--s4);
}
.kpi {
  display: flex; flex-direction: column; gap: var(--s1);
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r-md); padding: var(--s3) var(--s4); box-shadow: var(--shadow);
}
.kpi-label { color: var(--muted); font-size: var(--fs-sm); font-weight: 600; }
.kpi-value { font-size: var(--fs-2xl); font-weight: 700; line-height: 1.1;
             font-variant-numeric: tabular-nums; }
.kpi-note { color: var(--muted); font-size: var(--fs-sm); }
.dash-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0 var(--s4); }
@media (min-width: 56rem) {
  .dash-grid { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); }
  .dash-grid.even { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
}
.card-title { font-size: var(--fs-lg); margin: 0 0 var(--s3); }
.card h3 { margin: var(--s5) 0 0; }
.block { display: block; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
th.num { text-align: right; }
.health th[scope="row"] { color: var(--text); font-size: var(--fs-md); font-weight: 600; }
.health th .block { font-weight: 400; }
tbody tr:last-child th { border-bottom: 0; }
.dash-grid { align-items: start; }
.health td { vertical-align: middle; }
.spark-cell { white-space: nowrap; }
.spark-cell .c-spark { margin-right: 0; }
.feed { list-style: none; margin: 0; padding: 0; }
.feed li { padding: var(--s2) 0; border-bottom: 1px solid var(--border); font-size: var(--fs-md); }
.feed li:last-child { border-bottom: 0; }
.feed .badge { margin-right: var(--s1); }
.feed-main { display: flex; flex-wrap: wrap; gap: var(--s2); align-items: center; }
.steps { padding-left: 1.25rem; margin: var(--s3) 0 var(--s4); }
.steps li { margin-bottom: var(--s2); }
@media (max-width: 40rem) {
  .health thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  .health tr { display: grid; grid-template-columns: 1fr auto; gap: var(--s1) var(--s3);
               padding: var(--s3) 0; border-bottom: 1px solid var(--border); }
  .health th, .health td { border: 0; padding: 0; }
  .health td.num { display: none; }
}

/* ----------------------------------------------------------------- misc */
.stats { display: flex; flex-wrap: wrap; gap: var(--s5); margin: 0; }
.stats div { margin: 0; }
.stats b { display: block; font-size: var(--fs-xl); line-height: 1.2; }
.stats span { color: var(--muted); font-size: var(--fs-sm); }
.filters { display: flex; flex-wrap: wrap; gap: var(--s3); align-items: flex-end; }
.filters label { margin-top: 0; font-size: var(--fs-sm); }
.filters select, .filters input { min-width: 9rem; }
.secret {
  display: flex; gap: var(--s2); align-items: center; flex-wrap: wrap;
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: var(--r-sm); padding: var(--s2) var(--s3);
}
.secret code { background: transparent; border: 0; padding: 0; }
.spin {
  width: 1em; height: 1em; border: 2px solid currentColor; border-right-color: transparent;
  border-radius: 50%; display: inline-block; animation: spin .7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; } }
[hidden] { display: none !important; }
"""

APP_JS = """
'use strict';

// --- helpers ---------------------------------------------------------------
function $(id) { return document.getElementById(id); }

function setStatus(id, message, kind) {
  const node = $(id);
  if (!node) return;
  node.textContent = message || '';
  node.className = 'status' + (kind ? ' status-' + kind : '');
}

function busy(button, label) {
  if (!button) return function () {};
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = '<span class="spin" aria-hidden="true"></span>' + label;
  return function restore() { button.disabled = false; button.innerHTML = original; };
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const payload = await response.json().catch(function () { return {}; });
  if (!response.ok) throw new Error(payload.error || ('HTTP ' + response.status));
  return payload;
}

function b64urlToBuf(value) {
  value = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = value.length % 4;
  if (pad) value += '='.repeat(4 - pad);
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
}

function bufToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

function fields(names) {
  const out = {};
  for (const name of names) {
    const node = $(name);
    if (!node) continue;
    out[name] = node.type === 'checkbox' ? node.checked : node.value.trim();
  }
  return out;
}

// --- passkeys --------------------------------------------------------------
function passkeySupport() {
  if (!window.isSecureContext) {
    return 'Passkeys need a secure page. Open this over https, or on ' +
           'http://localhost while you are setting it up.';
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    return 'This browser has no passkey support. Try Safari, Chrome, Edge or Firefox.';
  }
  return '';
}

function passkeyError(error) {
  const name = error && error.name;
  if (name === 'NotAllowedError') return 'That was cancelled, or it timed out. Try again.';
  if (name === 'InvalidStateError') return 'This device already has a passkey for this account. Sign in instead.';
  if (name === 'SecurityError') return 'The page address does not match the passkey. Open the gateway on its usual https address.';
  return (error && error.message) || 'Something went wrong.';
}

async function doRegister(button) {
  const unsupported = passkeySupport();
  if (unsupported) { setStatus('err', unsupported, 'error'); return; }
  const email = ($('email') || {}).value;
  const code = ($('code') || {}).value;
  if (!email || !email.trim()) { setStatus('err', 'Enter your email address.', 'error'); return; }
  setStatus('err', '');
  const restore = busy(button, 'Waiting for your passkey');
  try {
    const options = await postJSON('/webauthn/register/begin',
      { email: email.trim(), code: code ? code.trim() : '' });
    options.challenge = b64urlToBuf(options.challenge);
    options.user.id = b64urlToBuf(options.user.id);
    for (const credential of options.excludeCredentials || []) credential.id = b64urlToBuf(credential.id);
    const created = await navigator.credentials.create({ publicKey: options });
    await postJSON('/webauthn/register/complete', {
      credential: {
        id: created.id, rawId: bufToB64url(created.rawId), type: created.type,
        clientExtensionResults: created.getClientExtensionResults ? created.getClientExtensionResults() : {},
        response: {
          clientDataJSON: bufToB64url(created.response.clientDataJSON),
          attestationObject: bufToB64url(created.response.attestationObject),
          transports: created.response.getTransports ? created.response.getTransports() : [],
        },
      },
    });
    location.href = document.body.dataset.after || '/';
  } catch (error) {
    restore();
    setStatus('err', passkeyError(error), 'error');
  }
}

async function doLogin(button) {
  const unsupported = passkeySupport();
  if (unsupported) { setStatus('err', unsupported, 'error'); return; }
  setStatus('err', '');
  const restore = busy(button, 'Waiting for your passkey');
  try {
    const options = await postJSON('/webauthn/login/begin', {});
    options.challenge = b64urlToBuf(options.challenge);
    for (const credential of options.allowCredentials || []) credential.id = b64urlToBuf(credential.id);
    const assertion = await navigator.credentials.get({ publicKey: options });
    const response = assertion.response;
    await postJSON('/webauthn/login/complete', {
      credential: {
        id: assertion.id, rawId: bufToB64url(assertion.rawId), type: assertion.type,
        clientExtensionResults: assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {},
        response: {
          clientDataJSON: bufToB64url(response.clientDataJSON),
          authenticatorData: bufToB64url(response.authenticatorData),
          signature: bufToB64url(response.signature),
          userHandle: response.userHandle ? bufToB64url(response.userHandle) : null,
        },
      },
    });
    location.href = '/';
  } catch (error) {
    restore();
    setStatus('err', passkeyError(error), 'error');
  }
}

// --- mailbox form ----------------------------------------------------------
const MAILBOX_FIELDS = ['address', 'secret', 'imap_host', 'imap_port', 'imap_security',
  'imap_username', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_username',
  'auth', 'oauth_provider', 'oauth_client_id', 'oauth_client_secret', 'oauth_tenant',
  'verify_ssl'];

async function detectSettings(button) {
  const address = ($('address') || {}).value;
  if (!address || !address.trim()) {
    setStatus('probe', 'Enter the address first.', 'error');
    return;
  }
  const restore = busy(button, 'Looking up');
  setStatus('probe', 'Looking up this provider...', 'busy');
  try {
    const found = await postJSON('/discover', { address: address.trim() });
    if (!found.found) {
      setStatus('probe', 'No published settings for this domain. Fill the servers in by hand.', 'error');
      return;
    }
    const settings = found.settings;
    const assign = { imap_host: settings.imap_host, imap_port: settings.imap_port,
      imap_security: settings.imap_security, smtp_host: settings.smtp_host,
      smtp_port: settings.smtp_port, smtp_security: settings.smtp_security };
    for (const key in assign) { const node = $(key); if (node && assign[key] != null) node.value = assign[key]; }
    const where = settings.provider_name ? (settings.provider_name + ' settings') : 'Settings';
    setStatus('probe', where + ' filled in (source: ' + settings.source + '). Now enter the password.', 'ok');
    const note = $('provider_note');
    if (note) {
      const notes = (settings.notes || []).join(' ');
      note.textContent = notes;
      note.hidden = !notes;
    }
  } catch (error) {
    setStatus('probe', error.message, 'error');
  } finally {
    restore();
  }
}

async function testMailbox(button) {
  const restore = busy(button, 'Testing');
  setStatus('probe', 'Connecting to IMAP and SMTP. This can take up to a minute.', 'busy');
  try {
    const result = await postJSON('/test', fields(MAILBOX_FIELDS));
    setStatus('probe', result.message, result.ok ? 'ok' : 'error');
  } catch (error) {
    setStatus('probe', error.message, 'error');
  } finally {
    restore();
  }
}

function onAuthChange() {
  const select = $('auth');
  if (!select) return;
  const oauth = select.value === 'xoauth2';
  const panel = $('oauth_fields');
  if (panel) panel.hidden = !oauth;
  const label = $('secret_label_text');
  if (label) label.textContent = oauth ? 'OAuth refresh token' : 'Password or app password';
}

// --- calendar form ---------------------------------------------------------
const CALENDAR_FIELDS = ['address', 'secret', 'url', 'username', 'timezone', 'default_calendar'];

async function testCalendar(button) {
  const restore = busy(button, 'Testing');
  setStatus('probe', 'Connecting to the CalDAV server...', 'busy');
  try {
    const result = await postJSON('/test-calendar', fields(CALENDAR_FIELDS));
    setStatus('probe', result.message, result.ok ? 'ok' : 'error');
    const picker = $('default_calendar_pick');
    if (result.ok && picker && (result.calendars || []).length) {
      picker.innerHTML = '';
      const blank = document.createElement('option');
      blank.value = ''; blank.textContent = '(first calendar)';
      picker.appendChild(blank);
      for (const calendar of result.calendars) {
        const option = document.createElement('option');
        option.value = calendar.name;
        option.textContent = calendar.name + (calendar.read_only ? ' (read-only on the server)' : '');
        picker.appendChild(option);
      }
      picker.hidden = false;
      const wrapper = $('default_calendar_pick_label');
      if (wrapper) wrapper.hidden = false;
    }
  } catch (error) {
    setStatus('probe', error.message, 'error');
  } finally {
    restore();
  }
}

// --- copy ------------------------------------------------------------------
async function copyValue(button) {
  const source = $(button.dataset.copy);
  if (!source) return;
  const text = source.textContent.trim();
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text; area.setAttribute('readonly', '');
      area.style.position = 'absolute'; area.style.left = '-9999px';
      document.body.appendChild(area); area.select();
      document.execCommand('copy'); document.body.removeChild(area);
    }
    setStatus('copy-status', 'Copied.', 'ok');
  } catch (error) {
    setStatus('copy-status', 'Could not copy. Select the text and copy it by hand.', 'error');
  }
}

// --- timestamps ------------------------------------------------------------
function localiseTimestamps() {
  for (const cell of document.querySelectorAll('[data-ts]')) {
    const ms = Number(cell.getAttribute('data-ts')) * 1000;
    if (!Number.isNaN(ms)) cell.textContent = new Date(ms).toLocaleString();
  }
}

// --- wiring ----------------------------------------------------------------
const ACTIONS = {
  register: doRegister,
  login: doLogin,
  detect: detectSettings,
  'test-mailbox': testMailbox,
  'test-calendar': testCalendar,
  copy: copyValue,
};

document.addEventListener('click', function (event) {
  const trigger = event.target.closest('[data-action]');
  if (!trigger) return;
  const handler = ACTIONS[trigger.dataset.action];
  if (!handler) return;
  event.preventDefault();
  handler(trigger);
});

document.addEventListener('change', function (event) {
  if (event.target.id === 'auth') onAuthChange();
  if (event.target.id === 'default_calendar_pick') {
    const target = $('default_calendar');
    if (target) target.value = event.target.value;
  }
});

document.addEventListener('submit', function (event) {
  const form = event.target;
  const submit = form.querySelector('[data-busy]');
  if (submit && !submit.disabled) busy(submit, submit.dataset.busy);
});

document.addEventListener('DOMContentLoaded', function () {
  localiseTimestamps();
  onAuthChange();
  // These panels render visible so the form still works without scripting;
  // hide them only once we know scripting is available to bring them back.
  for (const id of ['oauth_fields', 'default_calendar_pick_label']) {
    const node = $(id);
    if (node && node.dataset.jsHidden === '1') node.hidden = true;
  }
});
"""


def _size_classes() -> str:
    """``v0``-``v100`` and ``w0``-``w100``: height and width in whole percent.

    Generated rather than written out: a chart has to express a magnitude, and
    with `style-src 'self'` an inline ``style`` attribute is not available.
    """
    heights = "".join(f".v{n}{{height:{n}%}}" for n in range(101))
    widths = "".join(f".w{n}{{width:{n}%}}" for n in range(101))
    return f"\n/* generated magnitude classes */\n{heights}\n{widths}\n"


APP_CSS += _size_classes()


def _fingerprint(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


CSS_VERSION = _fingerprint(APP_CSS)
JS_VERSION = _fingerprint(APP_JS)
