"""Activity log: what each agent did, through which connector and mailbox.

Every MCP tool call is recorded as one JSON line: when, which connector, which
mailbox, which tool, the arguments that are safe to keep, and how it ended.
The web UI reads it back at ``/logs``.

What is **not** recorded: message bodies, HTML, attachment payloads and any
credential. Subjects, recipients, folders and UIDs are kept, because an
activity log that cannot answer "what did it send, and to whom?" is not worth
having. Values are truncated so one call cannot bloat the file.

The file is append-only JSONL next to the store, trimmed to the most recent
``MAIL_ACTIVITY_MAX_ENTRIES`` lines (default 5000, ``0`` disables logging).
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger("mail-mcp.activity")

DEFAULT_MAX_ENTRIES = 5000
VALUE_LIMIT = 160

# Arguments that would put message content or secrets on disk.
_NEVER_LOG = frozenset(
    {
        "body",
        "html",
        "attachments",
        "secret",
        "password",
        "content_base64",
        "content",
        "oauth_client_secret",
    }
)


@dataclass
class ActivityEntry:
    """One tool call, as it is written to disk and shown in the UI."""

    ts: float
    tool: str
    status: str = "ok"  # ok | error | denied
    owner_id: str = ""
    connection_id: str = ""
    connection_label: str = ""
    account: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    detail: str = ""
    duration_ms: int = 0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)

    @classmethod
    def from_json(cls, line: str) -> ActivityEntry | None:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict) or "tool" not in payload:
            return None
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in payload.items() if k in known})


def redact(arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Keep the arguments worth auditing, drop content and secrets."""
    safe: dict[str, Any] = {}
    for name, value in (arguments or {}).items():
        if name in _NEVER_LOG:
            if value:
                safe[name] = f"<{name} omitted>"
            continue
        if isinstance(value, str):
            safe[name] = value[:VALUE_LIMIT] + ("..." if len(value) > VALUE_LIMIT else "")
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[name] = value
        elif isinstance(value, list):
            safe[name] = [str(item)[:VALUE_LIMIT] for item in value[:20]]
        else:
            safe[name] = str(value)[:VALUE_LIMIT]
    return safe


# The entry being built for the call in flight, so the tools can name the
# mailbox they resolved and the error they turned into text.
_CURRENT: ContextVar[ActivityEntry | None] = ContextVar("mail_mcp_activity", default=None)


def start(entry: ActivityEntry) -> None:
    _CURRENT.set(entry)


def current() -> ActivityEntry | None:
    return _CURRENT.get()


def note_account(address: str) -> None:
    """Called once a tool knows which mailbox it is acting on."""
    entry = _CURRENT.get()
    if entry is not None and address:
        entry.account = address


def note_error(message: str, status: str = "error") -> None:
    """Called when a tool returns a failure to the agent instead of raising.

    ``status`` is ``denied`` when the gateway itself refused (a read-only
    mailbox), ``error`` when the server or the network did.
    """
    entry = _CURRENT.get()
    if entry is not None:
        entry.status = status
        entry.detail = message[:VALUE_LIMIT]


class ActivityLog:
    """Append-only JSONL log with a bounded number of entries."""

    def __init__(self, path: str | None = None, max_entries: int | None = None):
        self._path = Path(
            path
            or os.environ.get("MAIL_ACTIVITY_LOG", "")
            or _default_path()
        )
        if max_entries is None:
            try:
                max_entries = int(
                    os.environ.get("MAIL_ACTIVITY_MAX_ENTRIES", DEFAULT_MAX_ENTRIES)
                )
            except ValueError:
                max_entries = DEFAULT_MAX_ENTRIES
        self._max_entries = max(0, max_entries)
        self._lock = Lock()
        self._since_trim = 0

    @property
    def enabled(self) -> bool:
        return self._max_entries > 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def capacity(self) -> int:
        """How many entries the log keeps at most (1 when it is off)."""
        return self._max_entries or 1

    def append(self, entry: ActivityEntry) -> None:
        """Write one entry. Never raises: logging must not break a tool call."""
        if not self.enabled:
            return
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                new_file = not self._path.exists()
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(entry.to_json() + "\n")
                if new_file:
                    # It records subjects and recipients, so it is no more
                    # readable than the store it sits beside.
                    try:
                        self._path.chmod(0o600)
                    except OSError:
                        pass
                self._since_trim += 1
                # Amortise trimming: check once every 10% of the budget.
                if self._since_trim >= max(50, self._max_entries // 10):
                    self._since_trim = 0
                    self._trim_locked()
        except OSError as e:
            logger.warning("Could not write the activity log: %s", e)

    def _trim_locked(self) -> None:
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if len(lines) <= self._max_entries:
            return
        kept = lines[-self._max_entries :]
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
        tmp.replace(self._path)
        logger.info("Trimmed the activity log to the last %d entries", len(kept))

    def read(
        self,
        *,
        owner_id: str | None = None,
        connection_id: str | None = None,
        account: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[ActivityEntry]:
        """Most recent entries first, filtered. Unreadable lines are skipped."""
        if not self._path.exists():
            return []
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.warning("Could not read the activity log: %s", e)
            return []

        out: list[ActivityEntry] = []
        for line in reversed(lines):
            entry = ActivityEntry.from_json(line)
            if entry is None:
                continue
            if owner_id is not None and entry.owner_id != owner_id:
                continue
            if connection_id and entry.connection_id != connection_id:
                continue
            if account and entry.account != account:
                continue
            if tool and entry.tool != tool:
                continue
            if status and entry.status != status:
                continue
            out.append(entry)
            if len(out) >= max(1, limit):
                break
        return out

    def stats(self, owner_id: str | None = None) -> dict[str, Any]:
        """Counts for the header of the logs page."""
        return stats_of(self.read(owner_id=owner_id, limit=self.capacity))


def stats_of(entries: list[ActivityEntry]) -> dict[str, Any]:
    """Counts over entries already read, so a page reads the file once."""
    day_ago = time.time() - 86400
    return {
        "total": len(entries),
        "errors": sum(1 for e in entries if e.status != "ok"),
        "last_24h": sum(1 for e in entries if e.ts >= day_ago),
        "tools": sorted({e.tool for e in entries}),
        "accounts": sorted({e.account for e in entries if e.account}),
    }


def select(
    entries: list[ActivityEntry],
    *,
    connection_id: str | None = None,
    account: str | None = None,
    tool: str | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[ActivityEntry]:
    """Filter entries already read (most recent first), like ``read`` does."""
    out: list[ActivityEntry] = []
    for entry in entries:
        if connection_id and entry.connection_id != connection_id:
            continue
        if account and entry.account != account:
            continue
        if tool and entry.tool != tool:
            continue
        if status and entry.status != status:
            continue
        out.append(entry)
        if len(out) >= max(1, limit):
            break
    return out


def _default_path() -> str:
    """Sit next to the connection store, wherever that lives."""
    store = os.environ.get("MAIL_STORE", "") or "/data/mail_connections.json"
    return str(Path(store).with_name("mail_activity.jsonl"))


@dataclass
class Overview:
    """Everything the dashboard and the activity page plot, from one read.

    The log is a file: reading it once and deriving every figure keeps a busy
    page from re-reading it five times.
    """

    days: list[dict[str, Any]] = field(default_factory=list)
    tools: list[tuple[str, int]] = field(default_factory=list)
    by_connection: dict[str, dict[str, Any]] = field(default_factory=dict)
    total: int = 0
    failed: int = 0
    last_24h: int = 0
    accounts: list[str] = field(default_factory=list)
    # For the home dashboard.
    previous_24h: int = 0  # the 24 hours before the last 24
    failed_24h: int = 0
    window_calls: int = 0  # calls inside the ``days`` window
    window_failed: int = 0
    median_ms: int = 0  # typical duration of a call in the window
    by_account: list[tuple[str, int]] = field(default_factory=list)
    recent: list[ActivityEntry] = field(default_factory=list)
    recent_failures: list[ActivityEntry] = field(default_factory=list)

    @property
    def success_rate(self) -> float | None:
        """Share of calls in the window that succeeded, or None without calls."""
        if not self.window_calls:
            return None
        return (self.window_calls - self.window_failed) / self.window_calls


def overview(
    log: ActivityLog,
    owner_id: str,
    *,
    days: int = 14,
    now: float | None = None,
    entries: list[ActivityEntry] | None = None,
) -> Overview:
    """Aggregate this owner's activity over the last ``days`` days.

    ``entries`` spares a second read when the caller already has them.
    """
    import datetime as _dt

    moment = now if now is not None else time.time()
    today = _dt.datetime.fromtimestamp(moment).date()
    span = [today - _dt.timedelta(days=offset) for offset in range(days - 1, -1, -1)]
    index = {day: position for position, day in enumerate(span)}

    buckets = [
        {"date": day, "label": day.strftime("%d"), "full": day.isoformat(), "ok": 0, "failed": 0}
        for day in span
    ]
    tools: dict[str, int] = {}
    per_connection: dict[str, dict[str, Any]] = {}
    accounts: set[str] = set()
    account_calls: dict[str, int] = {}
    durations: list[int] = []
    recent: list[ActivityEntry] = []
    recent_failures: list[ActivityEntry] = []
    total = failed = last_24h = previous_24h = failed_24h = 0
    window_calls = window_failed = 0
    day_ago = moment - 86400
    two_days_ago = moment - 2 * 86400
    week_ago = moment - 7 * 86400

    if entries is None:
        entries = log.read(owner_id=owner_id, limit=log.capacity)
    for entry in entries:
        total += 1
        succeeded = entry.status == "ok"
        if not succeeded:
            failed += 1
        if entry.ts >= day_ago:
            last_24h += 1
            if not succeeded:
                failed_24h += 1
        elif entry.ts >= two_days_ago:
            previous_24h += 1
        if entry.account:
            accounts.add(entry.account)
        tools[entry.tool] = tools.get(entry.tool, 0) + 1
        # Entries come most recent first.
        if len(recent) < 8:
            recent.append(entry)
        if not succeeded and entry.ts >= week_ago and len(recent_failures) < 5:
            recent_failures.append(entry)

        bucket = per_connection.setdefault(
            entry.connection_id,
            {"last_ts": 0.0, "calls_7d": 0, "errors_7d": 0, "series": [0] * days},
        )
        bucket["last_ts"] = max(bucket["last_ts"], entry.ts)

        position = index.get(_dt.datetime.fromtimestamp(entry.ts).date())
        if position is None:
            continue
        window_calls += 1
        if not succeeded:
            window_failed += 1
        if entry.duration_ms:
            durations.append(entry.duration_ms)
        if entry.account:
            account_calls[entry.account] = account_calls.get(entry.account, 0) + 1
        buckets[position]["ok" if succeeded else "failed"] += 1
        bucket["series"][position] += 1
        if entry.ts >= moment - 7 * 86400:
            bucket["calls_7d"] += 1
            if not succeeded:
                bucket["errors_7d"] += 1

    ranked = sorted(tools.items(), key=lambda item: (-item[1], item[0]))
    durations.sort()
    return Overview(
        days=buckets,
        tools=ranked,
        by_connection=per_connection,
        total=total,
        failed=failed,
        last_24h=last_24h,
        accounts=sorted(accounts),
        previous_24h=previous_24h,
        failed_24h=failed_24h,
        window_calls=window_calls,
        window_failed=window_failed,
        median_ms=durations[len(durations) // 2] if durations else 0,
        by_account=sorted(account_calls.items(), key=lambda item: (-item[1], item[0])),
        recent=recent,
        recent_failures=recent_failures,
    )


def summarise_by_connection(log: ActivityLog, owner_id: str) -> dict[str, dict[str, Any]]:
    """Per-connector activity for the dashboard: last use, recent volume, errors.

    One pass over the entries this owner can see, so showing "last used" on the
    dashboard costs no extra read.
    """
    week_ago = time.time() - 7 * 86400
    out: dict[str, dict[str, Any]] = {}
    for entry in log.read(owner_id=owner_id, limit=log._max_entries or 1):
        bucket = out.setdefault(
            entry.connection_id, {"last_ts": 0.0, "calls_7d": 0, "errors_7d": 0}
        )
        bucket["last_ts"] = max(bucket["last_ts"], entry.ts)
        if entry.ts >= week_ago:
            bucket["calls_7d"] += 1
            if entry.status != "ok":
                bucket["errors_7d"] += 1
    return out


def humanise_age(stamp: float, now: float) -> str:
    """'3 minutes ago' and friends, for a timestamp that may be zero."""
    if not stamp:
        return ""
    seconds = max(0, int(now - stamp))
    if seconds < 60:
        return "just now"
    for below, unit, name in (
        (3600, 60, "minute"),
        (86400, 3600, "hour"),
        (604800, 86400, "day"),
    ):
        if seconds < below:
            count = max(1, seconds // unit)
            return f"{count} {name}{'s' if count > 1 else ''} ago"
    weeks = max(1, seconds // 604800)
    return f"{weeks} week{'s' if weeks > 1 else ''} ago"
