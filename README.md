# Mail MCP Gateway

An [MCP](https://modelcontextprotocol.io) gateway that connects **any mailbox**
to an AI agent. Point it at an IMAP/SMTP account and the agent can read, search,
sort and send mail through **17 tools**.

It is built to be run once and shared:

- **many users** self-register with passkeys and only ever see their own things;
- **many connectors**, so you can hand an agent one MCP connection per address;
- **many mail servers**, because a connector can serve several mailboxes at
  once (work, personal, a shared box) and every tool takes an `account`
  argument to pick one.

Any IMAP + SMTP server works: Gmail, Microsoft 365, iCloud, Fastmail, a company
Exchange, a self-hosted Dovecot, or Proton through its local Bridge.

## Features

### Reading

| Tool               | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| `list_accounts`    | List the mailboxes this connector serves                        |
| `check_account`    | Test IMAP login, folders and SMTP login for one mailbox         |
| `list_folders`     | List folders with their role (sent, drafts, trash, junk...)     |
| `folder_status`    | Message counts for a folder, plus quota when the server reports it |
| `list_messages`    | The most recent messages in a folder, newest first              |
| `search_messages`  | Search by sender, recipient, subject, body, date, flags, size   |
| `get_message`      | Read one message in full, with its attachment list              |
| `get_thread`       | The other messages of a conversation, here and in Sent          |
| `get_attachment`   | Download one attachment (text inline, anything else base64)     |

### Writing

| Tool               | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| `send_message`     | Send a new message, with HTML and attachments                   |
| `reply_message`    | Reply (or reply-all), threaded and quoted like a mail client    |
| `forward_message`  | Forward, carrying the original as a `.eml` attachment           |
| `save_draft`       | Write to Drafts without sending, for the user to finish         |
| `mark_messages`    | Mark read, unread, flagged, unflagged, answered                 |
| `move_messages`    | Move messages to another folder                                 |
| `delete_messages`  | Move to Trash, or expunge permanently when asked                |
| `create_folder`    | Create a folder                                                 |

Outgoing mail is copied to the Sent folder, replies keep `In-Reply-To` and
`References` so threads hold together, and a mailbox can be attached
**read-only** so an agent can read it but never send, move or delete.

## Activity log

Every tool call an agent makes is recorded and shown at `/logs`: when it ran,
which connector and mailbox it went through, which tool, the arguments worth
auditing, whether it succeeded, was refused or failed, and how long it took.
The view filters by connector, mailbox, tool and outcome, and each user only
ever sees their own connectors.

| Recorded                                              | Never recorded                      |
| ----------------------------------------------------- | ----------------------------------- |
| Subjects, recipients, folders, UIDs, flags, durations | Message bodies and HTML             |
| Tool name, connector, mailbox, outcome, error text    | Attachment contents                 |
| Timestamps                                            | Passwords, tokens, client secrets   |

The log is a JSONL file next to the store, trimmed to the most recent 5000
entries (`MAIL_ACTIVITY_MAX_ENTRIES`, `0` turns it off). The recording point is
a server middleware, so a tool added later is covered without touching it.

## Quick start

```bash
git clone https://github.com/frousselet/mail-mcp-gateway
cd mail-mcp-gateway
docker compose up -d
```

Open `http://localhost:8000/`, create your account with a passkey, then:

1. **Create a connector** and give it a name. You get an MCP URL, an OAuth
   client ID and a client secret (shown once).
2. **Add a mailbox**: type the address, hit *Detect settings*, enter the
   password, hit *Test connection*. The mailbox is only saved once IMAP **and**
   SMTP actually answered.
3. In Claude, **Settings → Connectors → Add custom connector** and paste the
   three values. Repeat step 1 for a second connector, or add more mailboxes to
   the same one.

For anything public, put an HTTPS reverse proxy in front and set
`MAIL_PUBLIC_URL`: passkeys require HTTPS outside localhost.

## Setting up a mailbox

*Detect settings* looks the domain up the way mail clients do: a short local
table of well-known providers first, then the
[Mozilla ISPDB](https://wiki.mozilla.org/Thunderbird:Autoconfiguration)
(`autoconfig.thunderbird.net`), then the domain's own
`autoconfig`/`.well-known` endpoints. Whatever comes back is editable, and
nothing is trusted until the connection test passes.

Most large providers refuse your normal password over IMAP:

| Provider            | What to use                                                          |
| ------------------- | --------------------------------------------------------------------- |
| Gmail               | An App Password (needs 2-Step Verification), or XOAUTH2               |
| Microsoft 365       | XOAUTH2 on most tenants; basic auth is disabled                       |
| iCloud              | An app-specific password from appleid.apple.com                       |
| Fastmail, Yahoo     | An app password                                                       |
| Proton Mail         | Proton Mail Bridge on the same host, its generated password, TLS verification off |
| Dovecot, Exchange   | The normal account password, or whatever your admin set up            |

### XOAUTH2

For Google and Microsoft the gateway stores a **refresh token** and exchanges it
for an access token when it connects. Obtain the refresh token once, out of
band, with the scopes:

- Google: `https://mail.google.com/`
- Microsoft: `offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send`

then choose *OAuth 2 (XOAUTH2)* in the mailbox form and paste the token, the
client ID and, where the app is confidential, the client secret.

## Architecture

```
                 ┌──────────────────────────────────────────┐
   passkey ─────▶│  web UI        users, connectors,        │
   login         │  (/, /login)   mailboxes                 │
                 ├──────────────────────────────────────────┤
   agent ───────▶│  OAuth 2.1     /authorize  /token        │
   (OAuth)       │                                          │
                 ├──────────────────────────────────────────┤
                 │  /mcp          17 tools, per-request     │───▶ IMAP
                 │                mailbox resolution        │───▶ SMTP
                 └──────────────────────────────────────────┘
                          encrypted store (Fernet)
```

One process serves everything on one port. A tool call arrives with an OAuth
access token, the token names a connector, the connector names its mailboxes,
and the `account` argument (or the connector's default) picks the one to act on.

| Module              | Role                                                       |
| ------------------- | ---------------------------------------------------------- |
| `server.py`         | The MCP tools and how a request resolves to a mailbox      |
| `activity.py`       | The activity log behind `/logs`, and what it redacts       |
| `web.py`            | Onboarding UI, connector management, the ASGI app          |
| `store.py`          | Encrypted store: users, connectors, mailboxes, OAuth state |
| `oauth.py`          | OAuth 2.1 authorization server (PKCE, rotating refresh)    |
| `imap_client.py`    | One long-lived IMAP connection per mailbox, async-friendly |
| `smtp_client.py`    | SMTP submission                                            |
| `message.py`        | Parsing: encoded headers, multipart, HTML, attachments     |
| `composer.py`       | Building new mail, replies and forwards                    |
| `search.py`         | IMAP SEARCH criteria from named filters                    |
| `discovery.py`      | Provider settings lookup                                   |
| `mutf7.py`          | Modified UTF-7 for non-ASCII folder names                  |

## Security

- Mailbox passwords, OAuth refresh tokens and connector client secrets are
  encrypted at rest with Fernet; the key is generated on first run and kept on
  the data volume (`MAIL_SECRET_KEY` overrides it).
- Access tokens, refresh tokens and authorization codes are stored as SHA-256
  hashes, never in usable form.
- Each user only sees and can only delete their own connectors and mailboxes;
  every write checks ownership.
- Deleting a connector, or issuing it a new secret, immediately revokes the
  tokens already handed out.
- `MAIL_ONBOARD_CODE` gates self-registration when the gateway is reachable
  from the internet.
- A mailbox can be attached read-only, which is enforced before anything is
  composed, sent or written.

## Single-mailbox mode

For a local agent that spawns the server itself, skip the web UI entirely:

```bash
export MAIL_ADDRESS=you@example.com MAIL_PASSWORD=app-password
export MAIL_IMAP_HOST=imap.example.com MAIL_SMTP_HOST=smtp.example.com
uvx --from . mail-mcp                 # stdio
```

```json
{
  "mcpServers": {
    "mail": {
      "command": "mail-mcp",
      "env": {
        "MAIL_ADDRESS": "you@example.com",
        "MAIL_PASSWORD": "app-password",
        "MAIL_IMAP_HOST": "imap.example.com",
        "MAIL_SMTP_HOST": "smtp.example.com"
      }
    }
  }
}
```

Several mailboxes in this mode: point `MAIL_ACCOUNTS_FILE` at a JSON list of
account objects (same field names, plus `password`). See `.env.example` for
every variable.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest        # 135 tests, including a fake IMAP server
uv run ruff check src tests
```

The test suite drives the real IMAP code path against an in-process IMAP server
(`tests/fake_imap.py`) and exercises the whole OAuth flow through the ASGI app,
so tool calls are tested end to end rather than mocked.

## License

MIT
