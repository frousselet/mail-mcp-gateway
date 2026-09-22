"""Server-rendered charts.

No charting library and no script: the page ships finished markup, which keeps
the strict Content-Security-Policy intact and works with scripting off.

The bars are HTML, not SVG. A scaled SVG shrinks its own labels, so on a phone
an SVG chart turns into an unreadable thumbnail; HTML bars reflow while the
text keeps its size. Since a strict CSP also forbids inline ``style``
attributes, the magnitudes ride on pre-generated utility classes (``v0``-``v100``)
that :mod:`mail_mcp.assets` emits once.

The marks follow a fixed spec: a bar never fills its slot, the data end is
rounded and the baseline square, 2px of surface separates touching segments
instead of a stroke, gridlines are recessive, values are labelled selectively
rather than on every mark, and text wears text tokens rather than the series
colour. Every chart names its series in words, carries a description for
screen readers, and is followed by the same numbers as a table.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from html import escape


def _esc(value: object) -> str:
    return escape(str(value), quote=True)


def _pct(value: float, total: float) -> int:
    """A percentage snapped to the utility-class grid."""
    if total <= 0:
        return 0
    return max(0, min(100, round(value / total * 100)))


def _nice_ceiling(value: int) -> int:
    """A clean axis top: 1, 2, 5, 10, 20, 50, 100..."""
    if value <= 5:
        return max(1, value)
    step = 1
    while step * 10 < value:
        step *= 10
    for factor in (1, 2, 5, 10):
        if step * factor >= value:
            return step * factor
    return value


@dataclass
class DayPoint:
    label: str  # axis label, e.g. "22"
    full: str  # accessible label, e.g. "2026-09-22"
    ok: int
    failed: int

    @property
    def total(self) -> int:
        return self.ok + self.failed


def daily_activity_chart(days: Sequence[DayPoint], *, title: str) -> str:
    """Calls per day, successes and failures stacked.

    Two series, so the legend is always there and both are named; colour only
    reinforces what the words already say.
    """
    if not days or not any(day.total for day in days):
        return (
            '<p class="muted">No activity in this period yet. Once an agent starts '
            "using a connector, its volume shows up here.</p>"
        )

    top = _nice_ceiling(max(day.total for day in days))
    peak = max(range(len(days)), key=lambda index: days[index].total)
    label_every = max(1, len(days) // 7)

    midpoint = top // 2
    scale = (
        f"<span>{top}</span><span>{midpoint}</span><span>0</span>"
        if 0 < midpoint < top
        else f"<span>{top}</span><span>0</span>"
    )

    columns = []
    for index, day in enumerate(days):
        # Two levels: the column's height is the day against the axis, and each
        # segment's height is its share of that column.
        column_height = _pct(day.total, top)
        segments = []
        # A floor keeps a lone failure from rounding away; the exact count is in
        # the tooltip and the table, so it costs a little area, not the truth.
        # Whatever it takes comes out of the success segment, so the two always
        # add up to the column.
        alert_share = max(6, _pct(day.failed, day.total)) if day.failed else 0
        if day.failed:
            gap = " gapped" if day.ok else ""
            segments.append(f'<span class="seg seg-alert v{alert_share}{gap}"></span>')
        if day.ok:
            share = 100 - alert_share
            segments.append(
                f'<span class="seg seg-ok v{share}{"" if day.failed else " capped"}"></span>'
            )
        value = (
            f'<span class="col-value">{day.total}</span>'
            if index == peak and day.total
            else ""
        )
        columns.append(
            f'<div class="slot" title="{_esc(day.full)}: {day.ok} succeeded, '
            f'{day.failed} failed or refused">'
            f'<span class="col v{column_height}">{value}{"".join(segments)}</span></div>'
        )

    axis = "".join(
        f'<span class="tick">{_esc(day.label) if index % label_every == 0 else ""}</span>'
        for index, day in enumerate(days)
    )
    rows = "".join(
        f'<tr><th scope="row">{_esc(day.full)}</th><td>{day.ok}</td><td>{day.failed}</td></tr>'
        for day in days
    )
    total_ok = sum(day.ok for day in days)
    total_failed = sum(day.failed for day in days)

    return f"""
<figure class="chart">
  <figcaption>{_esc(title)}</figcaption>
  <p class="legend">
    <span><span class="key key-ok"></span>Succeeded</span>
    <span><span class="key key-alert"></span>Failed or refused</span>
  </p>
  <div class="plot" role="img" aria-label="{_esc(title)}: {total_ok} succeeded and
    {total_failed} failed or refused over {len(days)} days, peaking at
    {days[peak].total} on {_esc(days[peak].full)}.">
    <div class="scale" aria-hidden="true">{scale}</div>
    <div class="cols">{"".join(columns)}</div>
    <div class="axis" aria-hidden="true">{axis}</div>
  </div>
  <details class="chart-data">
    <summary>See the numbers</summary>
    <div class="table-wrap"><table>
      <caption class="sr-only">{_esc(title)}</caption>
      <thead><tr><th scope="col">Day</th><th scope="col">Succeeded</th>
        <th scope="col">Failed or refused</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
  </details>
</figure>"""


def tool_usage_chart(
    counts: Sequence[tuple[str, int]], *, title: str, column: str = "Tool"
) -> str:
    """Ranked horizontal bars (tools, mailboxes...). One series, so no legend."""
    if not counts:
        return ""
    top = max(count for _, count in counts)
    rows = "".join(
        f'<div class="bar-row">'
        f'<span class="bar-label">{_esc(tool)}</span>'
        f'<span class="bar-track" title="{_esc(tool)}: {count} call(s)">'
        f'<span class="bar w{max(1, _pct(count, top))}"></span></span>'
        f'<span class="bar-value">{count}</span>'
        f"</div>"
        for tool, count in counts
    )
    table_rows = "".join(
        f'<tr><th scope="row">{_esc(tool)}</th><td>{count}</td></tr>'
        for tool, count in counts
    )
    return f"""
<figure class="chart">
  <figcaption>{_esc(title)}</figcaption>
  <div class="bars" role="img" aria-label="{_esc(title)}: {_esc(counts[0][0])} leads
    with {counts[0][1]} calls, out of {len(counts)} shown.">{rows}</div>
  <details class="chart-data">
    <summary>See the numbers</summary>
    <div class="table-wrap"><table>
      <caption class="sr-only">{_esc(title)}</caption>
      <thead><tr><th scope="col">{_esc(column)}</th><th scope="col">Calls</th></tr></thead>
      <tbody>{table_rows}</tbody>
    </table></div>
  </details>
</figure>"""


def sparkline(values: Sequence[int], *, label: str) -> str:
    """A connector's last fortnight, small enough to sit in a card header.

    This one stays SVG: it carries no text, so scaling it costs nothing.
    """
    if not values or not any(values):
        return ""
    width, height = 110, 22
    top = max(values)
    slot = width / len(values)
    bar_w = max(2.0, slot - 2)
    marks = []
    for index, value in enumerate(values):
        if not value:
            continue
        bar_h = max(2.0, (value / top) * (height - 2))
        x = index * slot
        marks.append(
            f'<rect class="c-ok" x="{x:.2f}" y="{height - bar_h:.2f}" '
            f'width="{bar_w:.2f}" height="{bar_h:.2f}" rx="1.5"/>'
        )
    return (
        f'<svg class="c-spark" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{_esc(label)}">{"".join(marks)}</svg>'
    )
