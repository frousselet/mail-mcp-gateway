"""The activity log: what it keeps, what it refuses to keep, how it is read."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mail_mcp.activity import ActivityEntry, ActivityLog, redact


@pytest.fixture
def log(tmp_path) -> ActivityLog:
    return ActivityLog(str(tmp_path / "activity.jsonl"), max_entries=100)


def _entry(**overrides) -> ActivityEntry:
    base = dict(
        ts=time.time(),
        tool="send_message",
        owner_id="usr_1",
        connection_id="con_1",
        connection_label="Work",
        account="ada@example.test",
    )
    base.update(overrides)
    return ActivityEntry(**base)


def test_content_and_secrets_are_never_written():
    safe = redact(
        {
            "to": "bob@example.test",
            "subject": "Invoice 42",
            "body": "Confidential payment details",
            "html": "<p>secret</p>",
            "attachments": [{"filename": "a.pdf", "content_base64": "AAAA"}],
            "secret": "hunter2",
        }
    )
    assert safe["to"] == "bob@example.test"
    assert safe["subject"] == "Invoice 42"
    for hidden in ("body", "html", "attachments", "secret"):
        assert "omitted" in safe[hidden]
    assert "hunter2" not in str(safe)
    assert "Confidential" not in str(safe)


def test_long_values_are_truncated():
    safe = redact({"subject": "x" * 500, "uids": list(range(100))})
    assert len(safe["subject"]) <= 170
    assert safe["subject"].endswith("...")
    assert len(safe["uids"]) == 20


def test_empty_content_fields_are_not_mentioned():
    assert redact({"body": "", "to": "bob@example.test"}) == {"to": "bob@example.test"}


def test_append_and_read_newest_first(log):
    for index in range(3):
        log.append(_entry(tool=f"tool_{index}", ts=time.time() + index))
    entries = log.read(owner_id="usr_1")
    assert [e.tool for e in entries] == ["tool_2", "tool_1", "tool_0"]


def test_filters(log):
    log.append(_entry(tool="send_message", account="ada@example.test"))
    log.append(_entry(tool="get_message", account="other@example.test", status="error"))
    log.append(_entry(tool="get_message", owner_id="usr_2"))

    assert len(log.read(owner_id="usr_1")) == 2
    assert len(log.read(owner_id="usr_2")) == 1
    assert log.read(owner_id="usr_1", tool="send_message")[0].tool == "send_message"
    assert log.read(owner_id="usr_1", status="error")[0].account == "other@example.test"
    assert log.read(owner_id="usr_1", account="ada@example.test")[0].tool == "send_message"
    assert log.read(owner_id="usr_1", connection_id="con_nope") == []


def test_limit(log):
    for index in range(10):
        log.append(_entry(ts=time.time() + index))
    assert len(log.read(owner_id="usr_1", limit=4)) == 4


def test_old_entries_are_trimmed(tmp_path):
    path = tmp_path / "activity.jsonl"
    log = ActivityLog(str(path), max_entries=100)
    for index in range(400):
        log.append(_entry(tool=f"tool_{index}"))
    lines = path.read_text().splitlines()
    assert len(lines) <= 200  # trimmed back to the budget as it grows
    # The newest entry always survives.
    assert log.read(owner_id="usr_1", limit=1)[0].tool == "tool_399"


def test_corrupt_lines_are_skipped(log):
    log.append(_entry(tool="good"))
    with Path(log.path).open("a") as handle:
        handle.write("not json at all\n")
        handle.write('{"unrelated": true}\n')
    log.append(_entry(tool="also_good"))
    assert [e.tool for e in log.read(owner_id="usr_1")] == ["also_good", "good"]


def test_stats(log):
    now = time.time()
    log.append(_entry(tool="a", ts=now))
    log.append(_entry(tool="b", ts=now, status="error"))
    log.append(_entry(tool="c", ts=now - 90000))
    stats = log.stats(owner_id="usr_1")
    assert stats["total"] == 3
    assert stats["errors"] == 1
    assert stats["last_24h"] == 2
    assert stats["tools"] == ["a", "b", "c"]
    assert stats["accounts"] == ["ada@example.test"]


def test_logging_can_be_switched_off(tmp_path):
    path = tmp_path / "off.jsonl"
    log = ActivityLog(str(path), max_entries=0)
    assert log.enabled is False
    log.append(_entry())
    assert not path.exists()
    assert log.read() == []


def test_a_broken_log_never_breaks_a_call(tmp_path):
    # A directory where the file should be: writing must fail quietly.
    path = tmp_path / "activity.jsonl"
    path.mkdir()
    log = ActivityLog(str(path), max_entries=10)
    log.append(_entry())  # must not raise
    assert log.read() == []


# ---------------------------------------------------------------------------
# The aggregation behind the dashboard charts
# ---------------------------------------------------------------------------


def test_overview_buckets_by_day_and_ranks_tools(log):
    from mail_mcp.activity import overview

    now = time.time()
    for offset, tool, status in (
        (0, "search_messages", "ok"),
        (0, "search_messages", "ok"),
        (0, "send_message", "error"),
        (86400, "search_messages", "ok"),
        (86400 * 3, "get_message", "denied"),
    ):
        log.append(_entry(tool=tool, status=status, ts=now - offset))

    result = overview(log, "usr_1", days=14, now=now)
    assert result.total == 5
    assert result.failed == 2
    assert [day["ok"] for day in result.days][-1] == 2
    assert [day["failed"] for day in result.days][-1] == 1
    assert result.tools[0] == ("search_messages", 3)
    assert len(result.days) == 14
    assert result.accounts == ["ada@example.test"]


def test_overview_gives_each_connector_its_own_series(log):
    from mail_mcp.activity import overview

    now = time.time()
    log.append(_entry(connection_id="con_a", ts=now))
    log.append(_entry(connection_id="con_a", ts=now - 86400))
    log.append(_entry(connection_id="con_b", ts=now))

    result = overview(log, "usr_1", days=7, now=now)
    assert sum(result.by_connection["con_a"]["series"]) == 2
    assert sum(result.by_connection["con_b"]["series"]) == 1
    assert len(result.by_connection["con_a"]["series"]) == 7


def test_overview_ignores_entries_older_than_the_window_in_the_series(log):
    from mail_mcp.activity import overview

    now = time.time()
    log.append(_entry(ts=now - 86400 * 40))
    result = overview(log, "usr_1", days=14, now=now)
    assert result.total == 1  # still counted overall
    assert sum(day["ok"] + day["failed"] for day in result.days) == 0  # not plotted


def test_overview_of_another_owner_is_empty(log):
    from mail_mcp.activity import overview

    log.append(_entry())
    assert overview(log, "usr_other", days=7).total == 0
