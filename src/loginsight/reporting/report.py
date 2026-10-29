"""The report: everything an analysis found, as one value, plus JSON and Markdown renderings.

This module never touches the file system and never looks at the clock, so the same log always
gives byte-identical output. The source is recorded by file name only, never by path.
"""

import json
from dataclasses import dataclass
from datetime import datetime

from loginsight import __version__
from loginsight.analysis.summary import Summary, summarize
from loginsight.analysis.timeseries import BUCKET_SIZES, TimeBucket, requests_per_bucket
from loginsight.detection.models import Detection
from loginsight.parsing.models import ParseResult, ParseStats

TOOL_NAME = "loginsight"

# The Markdown tables stop here so a huge log gives a report a person can still read. The JSON
# report always holds everything.
MAX_TABLE_ROWS = 100
# Lines shown in the "Parse problems" section.
MAX_PROBLEMS_SHOWN = 10

# Characters that Markdown or HTML would read as formatting inside a table cell.
_MARKDOWN_SPECIAL = frozenset("\\`*_[]()<>|&#~!")

CHART_FILES = {
    "Status codes": "charts/status.png",
    "Traffic": "charts/traffic.png",
    "Top paths": "charts/top_paths.png",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Report:
    """One analysis, ready to be written out.

    Frozen in the same limited sense as :class:`Summary`: the lists inside are ordinary ones,
    so treat a report as read-only.
    """

    source_name: str
    stats: ParseStats
    summary: Summary
    bucket: str
    buckets: list[TimeBucket]
    detections: list[Detection]


def _file_name(name: str) -> str:
    """The last part of a path written with ``/`` or ``\\``, so no folder ends up in a report."""
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def build_report(
    parse_result: ParseResult,
    detections: list[Detection],
    *,
    source_name: str,
    top_n: int = 10,
    bucket: str = "hour",
) -> Report:
    """Gather the statistics, the traffic over time and the detections into a :class:`Report`.

    ``source_name`` is reduced to its file name. ``top_n`` and ``bucket`` ("minute" or "hour")
    are checked here and raise :class:`ValueError` when wrong, even for a log with no entries.
    Detections are put in the order of :attr:`Detection.sort_key`.
    """
    if bucket not in BUCKET_SIZES:
        raise ValueError(f"bucket must be one of: {', '.join(BUCKET_SIZES)}; got {bucket!r}")
    entries = parse_result.entries
    return Report(
        source_name=_file_name(source_name),
        stats=parse_result.stats,
        summary=summarize(entries, top_n),
        bucket=bucket,
        buckets=requests_per_bucket(entries, bucket),
        detections=sorted(detections, key=lambda detection: detection.sort_key),
    )


def _stats_dict(stats: ParseStats) -> dict:
    return {
        "total_lines": stats.total_lines,
        "parsed": stats.parsed,
        "skipped": stats.skipped,
        "success_rate": stats.success_rate,
        "skipped_by_reason": dict(sorted(stats.skipped_by_reason.items())),
        "first_errors": [
            {"line_number": issue.line_number, "reason": issue.reason, "line": issue.line}
            for issue in stats.first_errors[:MAX_PROBLEMS_SHOWN]
        ],
    }


def to_dict(report: Report) -> dict:
    """The report as plain data, in the order the JSON file uses."""
    return {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "source": {"name": report.source_name, "parse": _stats_dict(report.stats)},
        "summary": report.summary.to_dict(),
        "traffic": {
            "bucket": report.bucket,
            "buckets": [
                {
                    "start": bucket.start.isoformat(),
                    "requests": bucket.requests,
                    "errors": bucket.errors,
                }
                for bucket in report.buckets
            ],
        },
        "detections": [detection.to_dict() for detection in report.detections],
    }


def render_json(report: Report) -> str:
    """The report as JSON: fixed key order, 2-space indent, ending with a newline."""
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def _escape(text: str) -> str:
    """``text`` made safe to put in a Markdown table cell.

    Line breaks and other control characters become spaces (a newline would end the table row)
    and each character Markdown or HTML could act on gets a backslash, so log text can neither
    break the table nor add formatting, links or tags.
    """
    cleaned = "".join(char if char.isprintable() else " " for char in text)
    return "".join(f"\\{char}" if char in _MARKDOWN_SPECIAL else char for char in cleaned)


def periods(count: int) -> str:
    return f"{count} period" + ("" if count == 1 else "s")


def _time(moment: datetime | None) -> str:
    return moment.isoformat() if moment else "-"


def human_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{count} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    """A Markdown table, cut at :data:`MAX_TABLE_ROWS` with a note saying how many are left."""
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(" --- " for _ in header) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows[:MAX_TABLE_ROWS]]
    hidden = len(rows) - MAX_TABLE_ROWS
    if hidden > 0:
        lines += ["", f"_{hidden} more not shown; the JSON report has them all._"]
    return lines


def render_markdown(report: Report, *, charts: bool = False) -> str:
    """The report as Markdown. With ``charts`` it links the PNG files in ``charts/``.

    Everything taken from the log is escaped. The result ends with a newline.
    """
    summary, stats = report.summary, report.stats
    lines = [f"# Log report: {_escape(report.source_name)}", ""]

    lines += ["## Summary", ""]
    lines += [
        f"- Lines read: {stats.total_lines} ({stats.parsed} parsed, {stats.skipped} skipped)",
        f"- Requests: {summary.total_requests}",
        f"- Unique IP addresses: {summary.unique_ips}",
        f"- Data sent: {human_bytes(summary.total_bytes)}",
        f"- Error rate (4xx and 5xx): {summary.error_rate:.1%}",
        f"- First request: {_time(summary.first_time)}",
        f"- Last request: {_time(summary.last_time)}",
        "",
    ]
    if summary.top_ips:
        lines += ["**Top IP addresses**", ""]
        lines += _table(["IP", "Requests"], [[_escape(ip), str(n)] for ip, n in summary.top_ips])
        lines.append("")
    if summary.top_paths:
        lines += ["**Top paths**", ""]
        lines += _table(
            ["Path", "Requests"], [[_escape(path), str(n)] for path, n in summary.top_paths]
        )
        lines.append("")

    lines += ["## Status codes", ""]
    lines += _table(
        ["Class", "Requests"], [[name, str(n)] for name, n in summary.status_classes.items()]
    )
    lines.append("")
    if summary.status_codes:
        lines += _table(
            ["Code", "Requests"], [[str(code), str(n)] for code, n in summary.status_codes.items()]
        )
        lines.append("")

    lines += ["## Traffic", ""]
    if report.buckets:
        busiest = max(report.buckets, key=lambda bucket: bucket.requests)  # first of equals
        lines += [
            f"Requests per {report.bucket}, over {periods(len(report.buckets))}. "
            f"The busiest started at {busiest.start.isoformat()} with {busiest.requests} requests.",
            "",
        ]
        lines += _table(
            ["Start (UTC)", "Requests", "Errors"],
            [[b.start.isoformat(), str(b.requests), str(b.errors)] for b in report.buckets],
        )
    else:
        lines.append("No traffic.")
    lines.append("")

    lines += ["## Detections", ""]
    if report.detections:
        lines += _table(
            ["Severity", "Rule", "IP", "Time", "Count", "Evidence"],
            [
                [
                    str(d.severity),
                    _escape(d.rule_id),
                    _escape(d.ip),
                    d.time.isoformat(),
                    str(d.count),
                    _escape(d.evidence),
                ]
                for d in report.detections
            ],
        )
    else:
        lines.append("No detections found.")
    lines.append("")

    if stats.skipped:
        lines += ["## Parse problems", ""]
        lines += [
            f"{stats.skipped} of {stats.total_lines} lines could not be read "
            f"({', '.join(f'{r}: {n}' for r, n in sorted(stats.skipped_by_reason.items()))}).",
            "",
        ]
        shown = stats.first_errors[:MAX_PROBLEMS_SHOWN]
        if stats.skipped > len(shown):
            lines += [f"The first {len(shown)} are listed.", ""]
        lines += _table(
            ["Line", "Reason", "Text"],
            [[str(i.line_number), _escape(i.reason), _escape(i.line)] for i in shown],
        )
        lines.append("")

    if charts:
        lines += ["## Charts", ""]
        lines += [f"![{title}]({path})" for title, path in CHART_FILES.items()]
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"
