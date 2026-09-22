"""The charts: structure, honesty of the marks, and accessibility."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from mail_mcp import charts
from mail_mcp.charts import DayPoint, daily_activity_chart, sparkline, tool_usage_chart


def _days(pattern: list[tuple[int, int]]) -> list[DayPoint]:
    return [
        DayPoint(label=f"{i + 1:02d}", full=f"2026-09-{i + 1:02d}", ok=ok, failed=failed)
        for i, (ok, failed) in enumerate(pattern)
    ]


SAMPLE = _days([(3, 0), (12, 1), (0, 0), (24, 3), (18, 0), (7, 2), (31, 0)])
TOOLS = [("search_messages", 60), ("get_message", 57), ("list_messages", 39)]


def _columns(html: str) -> list[int]:
    """Each column's height against the axis, in percent."""
    return [int(value) for value in re.findall(r'class="col v(\d+)"', html)]


def _segments(html: str) -> list[tuple[str, int]]:
    """Each segment's share of its own column."""
    return [
        (kind, int(value))
        for kind, value in re.findall(r'class="seg seg-(\w+) v(\d+)', html)
    ]


# ---------------------------------------------------------------------------
# The marks must not lie, and must not need a stylesheet exception
# ---------------------------------------------------------------------------


def test_charts_carry_no_inline_style_or_script():
    """They render under a strict CSP: magnitudes ride on classes, not style."""
    for html in (
        daily_activity_chart(SAMPLE, title="Calls per day"),
        tool_usage_chart(TOOLS, title="Tools"),
        sparkline([1, 2, 3], label="x"),
    ):
        assert " style=" not in html
        assert "<script" not in html
        assert "onclick" not in html


def test_every_magnitude_class_exists_in_the_stylesheet():
    """A class the sheet does not define would silently render a flat bar."""
    from mail_mcp.assets import APP_CSS

    html = daily_activity_chart(SAMPLE, title="x") + tool_usage_chart(TOOLS, title="y")
    for name in set(re.findall(r'class="[^"]*\b([vw]\d+)\b', html)):
        assert f".{name}{{" in APP_CSS, f"{name} is used but never defined"


def test_column_heights_are_proportional_to_the_axis_top():
    html = daily_activity_chart(_days([(25, 0), (50, 0)]), title="x")
    # Axis tops out at 50, so the columns are half and full height.
    assert _columns(html) == [50, 100]


def test_segments_always_add_up_to_their_column():
    """Otherwise a stack overflows its slot and the chart overstates the day."""
    for pattern in ([(24, 3)], [(199, 1)], [(0, 9)], [(48, 0)], [(1, 1)]):
        html = daily_activity_chart(_days(pattern), title="x")
        total = sum(share for _, share in _segments(html))
        assert total == 100, pattern


def test_a_single_failure_stays_visible_without_being_inflated():
    html = daily_activity_chart(_days([(199, 1)]), title="x")
    segments = dict(_segments(html))
    assert segments["alert"] == 6, "a lone failure gets a small floor, not a fat segment"
    assert segments["ok"] == 94, "and the floor comes out of the success segment"
    assert "199 succeeded, 1 failed or refused" in html  # the truth is one hover away


def test_stacked_segments_are_separated_by_surface_not_a_stroke():
    html = daily_activity_chart(_days([(10, 10)]), title="x")
    assert "seg-alert" in html and "gapped" in html
    assert "border:" not in html and "stroke" not in html


def test_a_column_with_no_failures_is_rounded_on_top():
    html = daily_activity_chart(_days([(10, 0)]), title="x")
    assert "seg-ok v100 capped" in html
    stacked = daily_activity_chart(_days([(10, 10)]), title="x")
    assert "capped" not in stacked  # the failure segment carries the rounding


def test_the_axis_tops_out_on_a_round_number():
    html = daily_activity_chart(_days([(37, 0)]), title="x")
    assert "<span>50</span><span>25</span><span>0</span>" in html


def test_the_axis_does_not_print_zero_twice_when_the_top_is_one():
    html = daily_activity_chart(_days([(1, 0)]), title="x")
    assert "<span>1</span><span>0</span>" in html
    assert "<span>0</span><span>0</span>" not in html


@pytest.mark.parametrize("value, expected", [(1, 1), (4, 4), (7, 10), (37, 50), (120, 200)])
def test_nice_ceiling(value, expected):
    assert charts._nice_ceiling(value) == expected


# ---------------------------------------------------------------------------
# Labels, legends and the table
# ---------------------------------------------------------------------------


def test_values_are_labelled_selectively_not_everywhere():
    html = daily_activity_chart(SAMPLE, title="x")
    labels = re.findall(r'class="col-value">(\d+)<', html)
    assert labels == ["31"], "only the peak is labelled; the axis carries the rest"


def test_axis_labels_are_thinned_so_they_cannot_collide():
    html = daily_activity_chart(_days([(1, 0)] * 30), title="x")
    ticks = re.findall(r'class="tick">([^<]*)</span>', html)
    assert len(ticks) == 30
    assert len([tick for tick in ticks if tick]) <= 8


def test_two_series_always_carry_a_legend_in_words():
    html = daily_activity_chart(SAMPLE, title="x")
    assert "Succeeded" in html and "Failed or refused" in html
    assert 'class="key key-ok"' in html


def test_a_single_series_gets_no_legend_box():
    assert 'class="legend"' not in tool_usage_chart(TOOLS, title="Tools")


def test_every_mark_has_a_native_tooltip():
    html = daily_activity_chart(SAMPLE, title="x")
    assert len(re.findall(r'class="slot" title="', html)) == len(SAMPLE)
    assert "24 succeeded, 3 failed or refused" in html
    assert 'title="search_messages: 60 call(s)"' in tool_usage_chart(TOOLS, title="x")


def test_charts_are_described_and_backed_by_a_table():
    html = daily_activity_chart(SAMPLE, title="Calls per day")
    assert 'role="img"' in html
    assert "aria-label=" in html
    assert "peaking at" in html
    assert "<table" in html and "See the numbers" in html
    for day in SAMPLE:
        assert day.full in html

    tools = tool_usage_chart(TOOLS, title="Tools")
    assert 'role="img"' in tools
    assert "<table" in tools
    for name, count in TOOLS:
        assert name in tools and str(count) in tools


def test_values_are_escaped():
    html = tool_usage_chart([("<script>alert(1)</script>", 3)], title="x")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Empty states and the sparkline
# ---------------------------------------------------------------------------


def test_an_empty_period_says_so_instead_of_drawing_nothing():
    html = daily_activity_chart(_days([(0, 0)] * 7), title="x")
    assert 'class="plot"' not in html
    assert "No activity in this period yet" in html
    assert tool_usage_chart([], title="x") == ""
    assert sparkline([0, 0, 0], label="x") == ""


def test_a_sparkline_is_small_well_formed_and_described():
    svg = sparkline([1, 4, 2, 8], label="15 calls over the last 4 days")
    root = ET.fromstring(svg)
    assert root.get("role") == "img"
    assert root.get("aria-label") == "15 calls over the last 4 days"
    assert root.get("viewBox") == "0 0 110 22"
    bars = root.findall("{http://www.w3.org/2000/svg}rect") or root.findall("rect")
    assert len(bars) == 4
    for bar in bars:
        assert 0 <= float(bar.get("x")) <= 110
        assert 0 <= float(bar.get("y")) <= 22
        assert float(bar.get("height")) >= 2
