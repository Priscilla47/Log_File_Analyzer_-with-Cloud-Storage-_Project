"""The plain-text views the command line prints: one for ``analyze`` and one for ``detect``.

Text from the log (paths, evidence, addresses) is shown with every control character turned
into a visible escape such as ``\\x1b``, so a hostile log line cannot send commands to the
reader's terminal.
"""

from loginsight.reporting.report import Report, human_bytes, periods

VIEWS = ("analyze", "detect")


def _escape_char(char: str) -> str:
    code = ord(char)
    return (
        f"\\x{code:02x}"
        if code < 0x100
        else f"\\u{code:04x}"
        if code < 0x10000
        else f"\\U{code:08x}"
    )


def printable(text: str) -> str:
    """``text`` with each non-printable character replaced by a visible ``\\xNN`` escape."""
    return "".join(char if char.isprintable() else _escape_char(char) for char in text)


def _time(moment) -> str:
    return moment.isoformat() if moment else "-"


def _lines_section(report: Report) -> list[str]:
    stats = report.stats
    lines = [
        f"File: {printable(report.source_name)}",
        f"Lines: {stats.total_lines} read, {stats.parsed} parsed, {stats.skipped} skipped "
        f"({stats.success_rate:.1%} parsed)",
    ]
    if stats.skipped_by_reason:
        reasons = ", ".join(f"{r}: {n}" for r, n in sorted(stats.skipped_by_reason.items()))
        lines.append(f"Skipped lines: {reasons}")
    return lines


def _ranked(title: str, rows: list[tuple[str, int]]) -> list[str]:
    if not rows:
        return []
    width = max(len(printable(name)) for name, _ in rows)
    return ["", title] + [f"  {printable(name):<{width}}  {count}" for name, count in rows]


def _analyze(report: Report) -> list[str]:
    summary = report.summary
    lines = _lines_section(report)
    if not summary.total_requests:
        return lines + ["", "No requests found."]

    classes = ", ".join(f"{name} {n}" for name, n in summary.status_classes.items() if n)
    lines += [
        "",
        "Summary",
        f"  Requests:     {summary.total_requests}",
        f"  Unique IPs:   {summary.unique_ips}",
        f"  Data sent:    {human_bytes(summary.total_bytes)}",
        f"  Error rate:   {summary.error_rate:.1%} (4xx and 5xx)",
        f"  First:        {_time(summary.first_time)}",
        f"  Last:         {_time(summary.last_time)}",
        f"  Status:       {classes}",
        "  Methods:      " + ", ".join(f"{m} {n}" for m, n in summary.methods.items()),
    ]
    lines += _ranked("Top IP addresses", summary.top_ips)
    lines += _ranked("Top paths", summary.top_paths)

    busiest = max(report.buckets, key=lambda bucket: bucket.requests)  # first of equals
    lines += [
        "",
        f"Traffic per {report.bucket}: {periods(len(report.buckets))}, the busiest started at "
        f"{busiest.start.isoformat()} with {busiest.requests} requests",
        "",
        f"Detections: {len(report.detections)} (list them with `loginsight detect`)",
    ]
    return lines


def _detect(report: Report) -> list[str]:
    lines = _lines_section(report) + [""]
    if not report.detections:
        return lines + ["No detections found."]

    rows = [
        (
            str(d.severity),
            d.rule_id,
            printable(d.ip),
            d.time.isoformat(),
            str(d.count),
            printable(d.evidence),
        )
        for d in report.detections
    ]
    header = ("SEVERITY", "RULE", "IP", "TIME", "COUNT", "EVIDENCE")
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(5)]
    lines.append(f"Detections: {len(rows)}")
    for row in [header, *rows]:
        cells = [f"{cell:<{widths[i]}}" for i, cell in enumerate(row[:5])]
        lines.append("  " + "  ".join([*cells, row[5]]))
    return lines


def render_text(report: Report, view: str) -> str:
    """The plain-text report for ``view``: ``"analyze"`` or ``"detect"``. Ends with a newline."""
    if view not in VIEWS:
        raise ValueError(f"view must be one of: {', '.join(VIEWS)}; got {view!r}")
    lines = _analyze(report) if view == "analyze" else _detect(report)
    return "\n".join(lines) + "\n"
