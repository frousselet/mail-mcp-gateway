"""IMAP client: one long-lived connection per mailbox, driven from asyncio.

``imaplib`` is synchronous and a single IMAP connection can only run one
command at a time, so every call is serialised behind a lock and executed in a
worker thread. A dropped connection is transparently re-established once.

Only UID commands are used: sequence numbers shift under concurrent expunges,
UIDs do not, so the identifiers handed to an agent stay valid.

A worker thread cannot be cancelled once started. When the task waiting on it
is (a client that disconnects, an agent that stops), the lock is kept until the
thread has finished, and the connection it was using is thrown away: a later
command must never share a socket that still has someone else's reply on it.
"""

from __future__ import annotations

import asyncio
import imaplib
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mail_mcp import mutf7
from mail_mcp.accounts import AUTH_XOAUTH2, SECURITY_NONE, SECURITY_SSL, MailAccount
from mail_mcp.xoauth2 import TokenError, access_token_for, sasl_xoauth2_raw

logger = logging.getLogger("mail-mcp.imap")

# Servers with thousands of folders, or very long FETCH preambles, can emit a
# single line longer than imaplib's 1 MiB default, which would abort the read.
imaplib._MAXLINE = max(imaplib._MAXLINE, 10_000_000)  # type: ignore[attr-defined]

SUMMARY_HEADERS = (
    "FROM TO CC SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES LIST-UNSUBSCRIBE"
)

_LIST_HEAD_RE = re.compile(rb'^\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s*')
_UID_RE = re.compile(rb"UID\s+(\d+)")
_FLAGS_RE = re.compile(rb"FLAGS\s+\(([^)]*)\)")
_SIZE_RE = re.compile(rb"RFC822\.SIZE\s+(\d+)")
_INTERNALDATE_RE = re.compile(rb'INTERNALDATE\s+"([^"]+)"')
_APPENDUID_RE = re.compile(rb"APPENDUID\s+\d+\s+(\d+)")

# Special-use attributes (RFC 6154) mapped to the role the gateway needs.
_SPECIAL_USE = {
    rb"\\Sent": "sent",
    rb"\\Drafts": "drafts",
    rb"\\Trash": "trash",
    rb"\\Junk": "junk",
    rb"\\Archive": "archive",
    rb"\\All": "all",
    rb"\\Flagged": "flagged",
}

# Fallback names, by role, when the server advertises no special-use flags.
_FALLBACK_NAMES = {
    "sent": ("Sent", "Sent Items", "Sent Messages", "INBOX.Sent", "Éléments envoyés",
             "Messages envoyés", "Gesendet", "Enviados"),
    "drafts": ("Drafts", "INBOX.Drafts", "Brouillons", "Entwürfe", "Borradores"),
    "trash": ("Trash", "Deleted Items", "Deleted Messages", "INBOX.Trash", "Corbeille",
              "Papierkorb", "Papelera"),
    "junk": ("Junk", "Spam", "Junk E-mail", "INBOX.Junk", "Indésirables", "Pourriel"),
    "archive": ("Archive", "Archives", "INBOX.Archive"),
}


# A connection idle this long is checked with NOOP before a command that must
# not be run twice (APPEND, COPY): the reconnect-and-retry path cannot tell a
# command that never reached the server from one whose reply was lost.
_IDLE_CHECK_SECONDS = 60


@dataclass
class Outcome:
    """What a mutation really touched, as opposed to what it was asked to."""

    done: list[int] = field(default_factory=list)
    missing: list[int] = field(default_factory=list)
    # For moves: "moved", "uids" (copied, originals expunged one by one) or
    # "flagged" (copied, originals only flagged deleted: no MOVE, no UIDPLUS).
    how: str = ""

    @property
    def count(self) -> int:
        return len(self.done)


async def _in_thread(fn, on_abandon=None) -> Any:
    """Run ``fn`` in a worker thread without letting cancellation outrun it.

    ``asyncio.to_thread`` returns as soon as the awaiting task is cancelled,
    while the thread carries on. Here the caller keeps waiting (so whatever lock
    it holds stays held), then ``on_abandon`` gets the finished future to clean
    up after it, and only then is the cancellation passed on.
    """
    future = asyncio.ensure_future(asyncio.to_thread(fn))
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if not future.cancelled():
            future.exception()  # retrieved, so asyncio does not log it
        if on_abandon is not None:
            await on_abandon(future)
        raise


def _uid_set(uids: list[int]) -> str:
    return ",".join(str(u) for u in uids)


def _present(conn: imaplib.IMAP4, uids: list[int]) -> list[int]:
    """The subset of ``uids`` that exists in the selected folder."""
    status, data = conn.uid("SEARCH", "UID", _uid_set(uids))
    if status != "OK":
        return list(uids)  # cannot tell: assume all, as before
    found = {int(u) for u in (data[0] or b"").split()}
    return [u for u in uids if u in found]


class ImapError(RuntimeError):
    """Raised for any IMAP-level failure, with a message fit for an agent."""

    def __init__(self, message: str, *, detail: str = ""):
        self.message = message
        self.detail = detail
        super().__init__(f"{message} {detail}".strip())


@dataclass
class FolderInfo:
    name: str  # decoded, human readable
    raw_name: str  # modified UTF-7, as the server wants it
    delimiter: str = "/"
    flags: list[str] = field(default_factory=list)
    role: str = ""  # sent/drafts/trash/junk/archive/all when known
    selectable: bool = True


def ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def quote(value: str) -> str:
    """Quote a string for an IMAP command argument.

    Control characters are refused rather than escaped: a CR or LF ends the
    command line early and turns the rest of the argument into a command of its
    own, which quoting cannot prevent.
    """
    for character in value:
        if character in "\r\n\x00" or (ord(character) < 0x20 and character != "\t"):
            raise ImapError(
                "That name contains a control character, which IMAP does not allow."
            )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


class ImapClient:
    """Async facade over one authenticated IMAP connection."""

    def __init__(self, account: MailAccount):
        self.account = account
        self._conn: imaplib.IMAP4 | None = None
        self._lock = asyncio.Lock()
        self._selected: tuple[str, bool] | None = None
        self._capabilities: set[str] = set()
        self._folders: list[FolderInfo] | None = None
        self._last_used = 0.0

    # --- connection handling -------------------------------------------------

    def _connect_sync(self) -> imaplib.IMAP4:
        account = self.account
        context = ssl_context(account.verify_ssl)
        try:
            if account.imap_security == SECURITY_SSL:
                conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                    account.imap_host,
                    account.imap_port,
                    ssl_context=context,
                    timeout=account.timeout,
                )
            else:
                conn = imaplib.IMAP4(
                    account.imap_host, account.imap_port, timeout=account.timeout
                )
                if account.imap_security != SECURITY_NONE:
                    conn.starttls(context)
        except (OSError, imaplib.IMAP4.error, ssl.SSLError) as e:
            raise ImapError(
                f"Cannot reach the IMAP server {account.imap_host}:{account.imap_port}.",
                detail=str(e),
            ) from e
        return conn

    def _login_sync(self, conn: imaplib.IMAP4, access_token: str | None) -> None:
        account = self.account
        try:
            if account.auth == AUTH_XOAUTH2:
                conn.authenticate(
                    "XOAUTH2",
                    lambda _challenge: sasl_xoauth2_raw(
                        account.imap_username, access_token or ""
                    ),
                )
            else:
                conn.login(account.imap_username, account.secret)
        except imaplib.IMAP4.error as e:
            raise ImapError(
                f"IMAP login rejected for {account.address}.",
                detail=_readable(e)
                + " Check the password (many providers require an app password).",
            ) from e

    async def _ensure_conn(self) -> imaplib.IMAP4:
        if self._conn is not None and self._conn.state in ("AUTH", "SELECTED"):
            return self._conn
        access_token = None
        if self.account.auth == AUTH_XOAUTH2:
            try:
                access_token = await access_token_for(
                    provider=self.account.oauth_provider,
                    refresh_token=self.account.secret,
                    client_id=self.account.oauth_client_id,
                    client_secret=self.account.oauth_client_secret,
                    tenant=self.account.oauth_tenant,
                )
            except TokenError as e:
                raise ImapError("OAuth token refresh failed.", detail=str(e)) from e

        def _open() -> imaplib.IMAP4:
            conn = self._connect_sync()
            self._login_sync(conn, access_token)
            return conn

        async def _close_orphan(future) -> None:
            # Cancelled while logging in: the socket exists but nobody owns it.
            if future.cancelled() or future.exception() is not None:
                return
            orphan = future.result()
            await asyncio.to_thread(_quiet_logout, orphan)

        conn = await _in_thread(_open, _close_orphan)
        self._conn = conn
        self._selected = None
        self._capabilities = {
            (c.decode() if isinstance(c, bytes) else c).upper()
            for c in (conn.capabilities or ())
        }
        logger.info(
            "IMAP connected: %s (%s)", self.account.address, self.account.imap_host
        )
        return conn

    async def _run(self, conn: imaplib.IMAP4, fn, *args, **kwargs) -> Any:
        async def _poisoned(_future) -> None:
            # The thread finished after its caller gave up. Whatever state it
            # left the connection in, nobody is reading it: start afresh.
            if self._conn is conn:
                await self._drop()

        return await _in_thread(lambda: fn(conn, *args, **kwargs), _poisoned)

    async def _alive(self) -> None:
        """Replace a connection that has gone quiet and may be dead."""
        conn = self._conn
        if conn is None or time.time() - self._last_used < _IDLE_CHECK_SECONDS:
            return
        try:
            await self._run(conn, lambda c: c.noop())
        except (imaplib.IMAP4.error, OSError, ssl.SSLError):
            await self._drop()

    async def _call(self, fn, *args, retry: bool = True, **kwargs) -> Any:
        """Run one IMAP command, reconnecting once if the link went away.

        ``retry=False`` is for commands that must not run twice (APPEND, COPY):
        if the link breaks mid-command, the server may already have done it.
        Those check an idle connection first instead, which covers the common
        case of a server that closed it while nothing was happening.
        """
        async with self._lock:
            if not retry:
                await self._alive()
            conn = await self._ensure_conn()
            try:
                result = await self._run(conn, fn, *args, **kwargs)
            except (imaplib.IMAP4.abort, OSError, ssl.SSLError) as e:
                logger.warning("IMAP connection lost (%s); reconnecting", e)
                await self._drop()
                if not retry:
                    raise ImapError(
                        "IMAP connection lost in the middle of a change; it may or "
                        "may not have been applied. Check before trying again.",
                        detail=str(e),
                    ) from e
                conn = await self._ensure_conn()
                try:
                    result = await self._run(conn, fn, *args, **kwargs)
                except (imaplib.IMAP4.error, OSError, ssl.SSLError) as e2:
                    raise ImapError("IMAP command failed.", detail=_readable(e2)) from e2
            except imaplib.IMAP4.error as e:
                raise ImapError("IMAP command failed.", detail=_readable(e)) from e
            self._last_used = time.time()
            return result

    async def _drop(self) -> None:
        conn, self._conn, self._selected = self._conn, None, None
        if conn is None:
            return

        await asyncio.to_thread(_quiet_logout, conn)

    async def close(self) -> None:
        async with self._lock:
            await self._drop()

    def has_capability(self, name: str) -> bool:
        """Whether the server advertises a capability.

        Only meaningful once connected: before that the set is empty, which is
        why the decisions that depend on it are taken inside the command, with
        the live connection in hand, rather than ahead of it.
        """
        return name.upper() in self._capabilities

    @staticmethod
    def _advertises(conn: imaplib.IMAP4, name: str) -> bool:
        """Read a capability off the live connection."""
        return name.upper() in {
            (capability.decode() if isinstance(capability, bytes) else capability).upper()
            for capability in (conn.capabilities or ())
        }

    async def check(self) -> dict[str, Any]:
        """Open a connection and report what the server supports."""
        await self._ensure_conn()
        folders = await self.list_folders()
        return {
            "ok": True,
            "host": f"{self.account.imap_host}:{self.account.imap_port}",
            "capabilities": sorted(self._capabilities),
            "folders": len(folders),
        }

    # --- folders -------------------------------------------------------------

    async def list_folders(self, refresh: bool = False) -> list[FolderInfo]:
        if self._folders is not None and not refresh:
            return self._folders

        def _list(conn: imaplib.IMAP4):
            return conn.list()

        status, data = await self._call(_list)
        if status != "OK":
            raise ImapError("Could not list folders.", detail=str(data))

        folders: list[FolderInfo] = []
        for line in data:
            if not line:
                continue
            if isinstance(line, tuple):
                # Literal form: (b'(\\Sent) "/" {5}', b'Sent')
                head, name_bytes = line[0] or b"", line[1] or b""
            else:
                head, name_bytes = line.strip(), b""
            match = _LIST_HEAD_RE.match(head)
            if not match:
                continue
            flags = match.group("flags")
            delim = match.group("delim")
            if not name_bytes:
                name_bytes = head[match.end():].strip()
                if name_bytes.startswith(b'"') and name_bytes.endswith(b'"'):
                    name_bytes = name_bytes[1:-1]
            flag_list = [f.decode(errors="replace") for f in flags.split()]
            raw = name_bytes.decode("ascii", errors="replace").replace('\\"', '"')
            role = ""
            for attr, value in _SPECIAL_USE.items():
                if re.search(attr, flags, re.IGNORECASE):
                    role = value
                    break
            folders.append(
                FolderInfo(
                    name=mutf7.decode(raw),
                    raw_name=raw,
                    delimiter=delim.decode().strip('"') if delim != b"NIL" else "/",
                    flags=flag_list,
                    role=role,
                    selectable=not any(f.lower() == "\\noselect" for f in flag_list),
                )
            )

        # Fill roles the server did not advertise, by well-known name.
        by_name = {f.name.lower(): f for f in folders}
        for role, names in _FALLBACK_NAMES.items():
            if any(f.role == role for f in folders):
                continue
            for candidate in names:
                folder = by_name.get(candidate.lower())
                if folder is not None and not folder.role:
                    folder.role = role
                    break

        self._folders = folders
        return folders

    async def folder_for_role(self, role: str) -> str | None:
        """Return the raw folder name playing ``role``, if the mailbox has one."""
        override = getattr(self.account, f"{role}_folder", "")
        if override:
            return mutf7.encode(override)
        for folder in await self.list_folders():
            if folder.role == role:
                return folder.raw_name
        return None

    async def resolve_folder(self, name: str | None) -> str:
        """Map a user-supplied folder name to the raw name the server expects.

        Accepts the decoded display name, the raw name, a role such as ``sent``
        or ``trash``, and defaults to ``INBOX``.
        """
        if not name or name.strip().lower() == "inbox":
            return "INBOX"
        wanted = name.strip()
        if wanted.lower() in _FALLBACK_NAMES or wanted.lower() in ("all", "archive"):
            raw = await self.folder_for_role(wanted.lower())
            if raw:
                return raw
        folders = await self.list_folders()
        for folder in folders:
            if folder.name.lower() == wanted.lower() or folder.raw_name == wanted:
                return folder.raw_name
        # Unknown: let the server decide (it may exist but not be listed).
        return mutf7.encode(wanted)

    async def create_folder(self, name: str) -> str:
        raw = mutf7.encode(name.strip())

        def _create(conn: imaplib.IMAP4):
            return conn.create(quote(raw))

        status, data = await self._call(_create)
        if status != "OK":
            raise ImapError(f"Could not create folder {name!r}.", detail=str(data))
        self._folders = None
        return name

    async def status(self, folder: str | None = None) -> dict[str, Any]:
        raw = await self.resolve_folder(folder)

        def _status(conn: imaplib.IMAP4):
            return conn.status(quote(raw), "(MESSAGES UNSEEN RECENT UIDNEXT UIDVALIDITY)")

        status, data = await self._call(_status)
        if status != "OK" or not data or not data[0]:
            raise ImapError(f"Could not read the status of {folder or 'INBOX'}.")
        payload = data[0].decode(errors="replace")
        counts: dict[str, Any] = {"folder": mutf7.decode(raw)}
        for key in ("MESSAGES", "UNSEEN", "RECENT", "UIDNEXT", "UIDVALIDITY"):
            match = re.search(rf"{key}\s+(\d+)", payload)
            if match:
                counts[key.lower()] = int(match.group(1))
        return counts

    async def quota(self) -> dict[str, Any] | None:
        if not self.has_capability("QUOTA"):
            return None

        def _quota(conn: imaplib.IMAP4):
            return conn.getquotaroot("INBOX")

        try:
            status, data = await self._call(_quota)
        except ImapError:
            return None
        if status != "OK":
            return None
        for line in data[1] if len(data) > 1 else []:
            match = re.search(rb"STORAGE\s+(\d+)\s+(\d+)", line or b"")
            if match:
                used, limit = int(match.group(1)), int(match.group(2))
                return {
                    "used_kb": used,
                    "limit_kb": limit,
                    "used_percent": round(used * 100 / limit, 1) if limit else None,
                }
        return None

    # --- search --------------------------------------------------------------

    async def search(
        self,
        folder: str | None,
        criteria: list[bytes],
        *,
        limit: int = 25,
        newest_first: bool = True,
    ) -> tuple[list[int], int]:
        """Return ``(uids, total_matches)`` for a search in one folder."""
        raw = await self.resolve_folder(folder)
        args = criteria or [b"ALL"]
        use_sort = self.has_capability("SORT") and newest_first

        def _search(conn: imaplib.IMAP4):
            status, data = conn.select(quote(raw), readonly=True)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(raw)!r}.", detail=_first(data)
                )
            self._selected = (raw, True)
            if use_sort:
                result = conn.uid("SORT", "(REVERSE DATE)", "UTF-8", *args)
                if result[0] == "OK":
                    return result
            return conn.uid("SEARCH", "CHARSET", "UTF-8", *args)

        status, data = await self._call(_search)
        if status != "OK":
            # Some servers reject CHARSET UTF-8; retry in US-ASCII.
            def _retry(conn: imaplib.IMAP4):
                return conn.uid("SEARCH", *args)

            status, data = await self._call(_retry)
            if status != "OK":
                raise ImapError("Search failed.", detail=_first(data))

        uids = [int(u) for u in (data[0] or b"").split()]
        total = len(uids)
        if not use_sort and newest_first:
            uids.reverse()
        return uids[: max(0, limit)], total

    # --- fetch ---------------------------------------------------------------

    async def fetch_summaries(
        self, folder: str | None, uids: list[int]
    ) -> list[dict[str, Any]]:
        """Fetch flags, size, internal date and the headers used for listings."""
        if not uids:
            return []
        raw = await self.resolve_folder(folder)
        uid_set = ",".join(str(u) for u in uids)
        spec = (
            f"(UID FLAGS INTERNALDATE RFC822.SIZE "
            f"BODY.PEEK[HEADER.FIELDS ({SUMMARY_HEADERS})])"
        )

        def _fetch(conn: imaplib.IMAP4):
            status, data = conn.select(quote(raw), readonly=True)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(raw)!r}.", detail=_first(data)
                )
            self._selected = (raw, True)
            return conn.uid("FETCH", uid_set, spec)

        status, data = await self._call(_fetch)
        if status != "OK":
            raise ImapError("Could not fetch messages.", detail=_first(data))

        order = {uid: i for i, uid in enumerate(uids)}
        parsed = [p for p in (_parse_fetch_item(item) for item in data) if p]
        parsed.sort(key=lambda p: order.get(p["uid"], 1_000_000))
        return parsed

    async def fetch_raw(self, folder: str | None, uid: int) -> bytes:
        """Fetch one full message, without marking it read."""
        raw = await self.resolve_folder(folder)

        def _fetch(conn: imaplib.IMAP4):
            status, data = conn.select(quote(raw), readonly=True)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(raw)!r}.", detail=_first(data)
                )
            self._selected = (raw, True)
            return conn.uid("FETCH", str(uid), "(BODY.PEEK[])")

        status, data = await self._call(_fetch)
        if status != "OK":
            raise ImapError(f"Could not fetch message {uid}.", detail=_first(data))
        for item in data:
            if isinstance(item, tuple) and len(item) > 1 and item[1]:
                return item[1]
        raise ImapError(
            f"Message {uid} was not found in {mutf7.decode(raw)!r}. "
            "It may have been moved or deleted."
        )

    # --- mutations -----------------------------------------------------------

    def _guard_read_only(self, action: str) -> None:
        if self.account.read_only:
            raise ImapError(
                f"This mailbox is connected read-only, so {action} is not allowed."
            )

    async def store_flags(
        self, folder: str | None, uids: list[int], flags: list[str], *, add: bool = True
    ) -> Outcome:
        """Add or remove flags; reports which UIDs were really there.

        A server answers OK to a STORE on UIDs that do not exist, so the count
        comes from a search in the same selection, not from the request.
        """
        self._guard_read_only("changing flags")
        if not uids:
            return Outcome()
        raw = await self.resolve_folder(folder)
        command = "+FLAGS.SILENT" if add else "-FLAGS.SILENT"
        flag_arg = "(" + " ".join(flags) + ")"
        present: list[int] = []

        def _store(conn: imaplib.IMAP4):
            nonlocal present
            status, data = conn.select(quote(raw), readonly=False)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(raw)!r} for writing.",
                    detail=_first(data),
                )
            self._selected = (raw, False)
            present = _present(conn, uids)
            if not present:
                return "OK", [b""]
            return conn.uid("STORE", _uid_set(present), command, flag_arg)

        status, data = await self._call(_store)
        if status != "OK":
            raise ImapError("Could not update message flags.", detail=_first(data))
        return Outcome(done=present, missing=[u for u in uids if u not in present])

    async def move(
        self, folder: str | None, uids: list[int], destination: str
    ) -> Outcome:
        """Move messages; reports which UIDs moved and how.

        Without MOVE the gateway copies, then flags the originals deleted. With
        UIDPLUS it expunges exactly those; without it, it stops there, because
        the only expunge left would also destroy every other message someone
        flagged deleted in that folder.
        """
        self._guard_read_only("moving messages")
        if not uids:
            return Outcome()
        source = await self.resolve_folder(folder)
        target = await self.resolve_folder(destination)
        present: list[int] = []
        how = "moved"

        def _move(conn: imaplib.IMAP4):
            nonlocal present, how
            # Decided here, not above: before the first command the capability
            # set is empty, and guessing wrong means the destructive fallback.
            can_move = self._advertises(conn, "MOVE")
            status, data = conn.select(quote(source), readonly=False)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(source)!r} for writing.",
                    detail=_first(data),
                )
            self._selected = (source, False)
            present = _present(conn, uids)
            if not present:
                return "OK", [b""]
            uid_set = _uid_set(present)
            if can_move:
                return conn.uid("MOVE", uid_set, quote(target))
            status, data = conn.uid("COPY", uid_set, quote(target))
            if status != "OK":
                return status, data
            conn.uid("STORE", uid_set, "+FLAGS.SILENT", "(\\Deleted)")
            if self._advertises(conn, "UIDPLUS"):
                how = "uids"
                return conn.uid("EXPUNGE", uid_set)
            how = "flagged"
            return status, data

        # Never retried: a COPY that ran before the link dropped would be
        # copied a second time.
        status, data = await self._call(_move, retry=False)
        if status != "OK":
            raise ImapError(
                f"Could not move messages to {destination!r}.", detail=_first(data)
            )
        return Outcome(
            done=present, missing=[u for u in uids if u not in present], how=how
        )

    async def expunge(
        self,
        folder: str | None,
        uids: list[int] | None = None,
        *,
        allow_folder_wide: bool = True,
    ) -> str:
        """Permanently remove messages flagged ``\\Deleted``.

        With UIDPLUS the expunge is restricted to ``uids``; without it the
        server can only expunge the whole folder, so anything another client
        flagged as deleted goes too. With ``allow_folder_wide=False`` that
        fallback is not taken and the messages stay flagged ("flagged").
        The return value says which happened: "uids", "folder", "flagged" or
        "none".

        An empty ``uids`` list means "these messages", not "every message":
        it expunges nothing. Only ``uids=None`` asks for the folder-wide form.
        """
        self._guard_read_only("expunging messages")
        if uids is not None and not uids:
            return "none"
        raw = await self.resolve_folder(folder)
        uid_set = ",".join(str(u) for u in (uids or []))
        scope = "folder"

        def _expunge(conn: imaplib.IMAP4):
            nonlocal scope
            targeted = bool(uids) and self._advertises(conn, "UIDPLUS")
            scope = "uids" if targeted else "folder"
            if not targeted and uids and not allow_folder_wide:
                scope = "flagged"
                return "OK", [b""]
            status, data = conn.select(quote(raw), readonly=False)
            if status != "OK":
                raise ImapError(
                    f"Could not open folder {mutf7.decode(raw)!r} for writing.",
                    detail=_first(data),
                )
            self._selected = (raw, False)
            if targeted:
                return conn.uid("EXPUNGE", uid_set)
            return conn.expunge()

        status, data = await self._call(_expunge)
        if status != "OK":
            raise ImapError("Could not expunge the folder.", detail=_first(data))
        return scope

    async def append(
        self,
        folder: str,
        message: bytes,
        *,
        flags: str = "",
        when: datetime | None = None,
    ) -> int | None:
        """Store a message in a folder; returns its new UID when the server says.

        A server with UIDPLUS answers ``OK [APPENDUID <validity> <uid>]``, which
        is the only way to name the message that was just written. Without it
        the caller gets ``None`` and has to search for it.
        """
        self._guard_read_only("saving messages")
        raw = await self.resolve_folder(folder)
        stamp = imaplib.Time2Internaldate(when.timestamp() if when else time.time())

        def _append(conn: imaplib.IMAP4):
            return conn.append(quote(raw), flags, stamp, message)

        # Never retried: an APPEND whose reply was lost may already be stored.
        status, data = await self._call(_append, retry=False)
        if status != "OK":
            raise ImapError(
                f"Could not save the message to {mutf7.decode(raw)!r}.",
                detail=_first(data),
            )
        # The folder gained a message, so any cached selection is stale.
        self._selected = None
        match = _APPENDUID_RE.search(_first(data).encode())
        return int(match.group(1)) if match else None


def _quiet_logout(conn: imaplib.IMAP4) -> None:
    try:
        conn.logout()
    except Exception:
        pass


def _first(data: Any) -> str:
    if isinstance(data, (list, tuple)) and data:
        head = data[0]
        if isinstance(head, bytes):
            return head.decode(errors="replace")
        return str(head)
    return str(data)


def _readable(error: Exception) -> str:
    text = str(error)
    if text.startswith("b'") or text.startswith('b"'):
        text = text[2:-1]
    return text


def _parse_fetch_item(item: Any) -> dict[str, Any] | None:
    """Turn one imaplib FETCH response item into a summary dict."""
    if not isinstance(item, tuple) or len(item) < 2:
        return None
    preamble, payload = item[0] or b"", item[1] or b""
    uid_match = _UID_RE.search(preamble)
    if not uid_match:
        return None
    flags_match = _FLAGS_RE.search(preamble)
    size_match = _SIZE_RE.search(preamble)
    date_match = _INTERNALDATE_RE.search(preamble)
    internal_date = None
    if date_match:
        try:
            internal_date = imaplib.Internaldate2tuple(
                b"INTERNALDATE \"" + date_match.group(1) + b"\""
            )
        except Exception:
            internal_date = None
    return {
        "uid": int(uid_match.group(1)),
        "flags": [f.decode(errors="replace") for f in (
            flags_match.group(1).split() if flags_match else []
        )],
        "size": int(size_match.group(1)) if size_match else None,
        "internal_date": (
            datetime.fromtimestamp(time.mktime(internal_date)) if internal_date else None
        ),
        "headers_raw": payload,
    }
