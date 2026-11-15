"""One analysis, from the text of a log to a report: the steps every interface shares.

The command line and the dashboard both call :func:`analyze_text`, so they cannot disagree
about a number: the format detection, the parsing, the checks on how much was readable, the
detection rules and the report all happen here, once.
"""

import io
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TextIO

from loginsight.detection import Detection, Severity, detect, load_rules
from loginsight.detection.ruleset import RuleSet
from loginsight.parsing.detect import detect_log_format_lines
from loginsight.parsing.models import LogEntry, ParseResult, ParseStats
from loginsight.parsing.parser import parse_lines
from loginsight.reporting.report import Report, build_report

# More skipped lines than this share of the log earns a warning.
SKIP_WARNING_SHARE = 0.10


class NothingReadError(ValueError):
    """The text has lines, but none of them could be read as an access-log entry.

    A report would say "no attacks" about a log that was never understood, so this is an error.
    ``reasons`` lists why the lines were skipped, for example ``"no_match: 4"``.
    """

    def __init__(self, stats: ParseStats) -> None:
        self.total_lines = stats.total_lines
        self.reasons = ", ".join(
            f"{name}: {count}" for name, count in stats.skipped_by_reason.items()
        )
        super().__init__(
            f"none of the {self.total_lines} lines could be read as an access-log entry "
            f"({self.reasons})"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Reading:
    """What reading a log gives, before any report is built from it.

    The slow part of an analysis (parsing and detection) is here, and a report for any traffic
    period is built from it with :func:`build`, so an interface can offer several periods
    without reading the file again. ``warnings`` is text for the person reading the result;
    ``entries`` are the parsed requests in log order. Treat it as read-only.
    """

    result: ParseResult
    log_format: str
    detections: list[Detection]
    warnings: list[str]

    @property
    def entries(self) -> list[LogEntry]:
        """The parsed requests, in log order."""
        return self.result.entries


@dataclass(frozen=True, slots=True, kw_only=True)
class Analysis:
    """A report, the warnings that go with it and the entries it was built from.

    ``warnings`` is text for the person reading the result. ``entries`` are the parsed requests
    in log order, kept so an interface can look at one address without reading the file again.
    """

    report: Report
    warnings: list[str]
    entries: list[LogEntry] = field(default_factory=list)


def read_lines(
    open_lines: Callable[[], TextIO],
    *,
    rules: RuleSet | None = None,
    min_severity: Severity = Severity.LOW,
) -> Reading:
    """Read an access log a line at a time: detect its format, parse it and apply the rules.

    ``open_lines`` opens the log as text and is called twice, once to detect the format (which
    stops reading early) and once to parse, so the whole text is never held in memory, only the
    parsed requests. Each opened file is closed. The ``rules`` are the built-in ones for
    ``None`` and detections below ``min_severity`` are dropped. Raises
    :class:`NothingReadError` if the log has lines and none could be read. An empty log is not
    an error.
    """
    with open_lines() as lines:
        log_format = detect_log_format_lines(lines)
    with open_lines() as lines:
        result = parse_lines(lines, log_format)
    stats = result.stats
    if stats.total_lines and not stats.parsed:
        raise NothingReadError(stats)
    warnings = []
    if stats.total_lines and stats.skipped / stats.total_lines > SKIP_WARNING_SHARE:
        warnings.append(
            f"{stats.skipped} of {stats.total_lines} lines "
            f"({stats.skipped / stats.total_lines:.0%}) could not be read"
        )
    detections = detect(result.entries, rules if rules is not None else load_rules())
    detections = [d for d in detections if d.severity >= min_severity]
    return Reading(result=result, log_format=log_format, detections=detections, warnings=warnings)


def read_text(
    text: str, *, rules: RuleSet | None = None, min_severity: Severity = Severity.LOW
) -> Reading:
    """Read the text of an access log: :func:`read_lines` over the lines of the text."""
    return read_lines(
        lambda: io.StringIO(text, newline=None), rules=rules, min_severity=min_severity
    )


def read_bytes(
    raw: bytes, *, rules: RuleSet | None = None, min_severity: Severity = Severity.LOW
) -> Reading:
    """Read the bytes of an access log as the command line reads a file: UTF-8, a leading byte
    order mark dropped, invalid bytes replaced. No second copy of the log as text is made."""

    def open_lines() -> TextIO:
        return io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8-sig", errors="replace")

    return read_lines(open_lines, rules=rules, min_severity=min_severity)


def build(reading: Reading, source_name: str, *, top_n: int = 10, bucket: str = "hour") -> Report:
    """The report of a :class:`Reading`, with the traffic grouped by ``bucket``.

    ``source_name`` is reduced to a file name. Raises :class:`ValueError` for a wrong ``top_n``
    or ``bucket``.
    """
    return build_report(
        reading.result,
        reading.detections,
        source_name=source_name,
        top_n=top_n,
        bucket=bucket,
        log_format=reading.log_format,
    )


def analyze_text(
    text: str,
    source_name: str,
    *,
    rules: RuleSet | None = None,
    min_severity: Severity = Severity.LOW,
    top_n: int = 10,
    bucket: str = "hour",
) -> Analysis:
    """Analyse the text of an access log: :func:`read_text` and then :func:`build`.

    ``source_name`` is reduced to a file name in the report. Raises :class:`NothingReadError` if
    the text has lines and none could be read, and :class:`ValueError` for a wrong ``top_n`` or
    ``bucket``. An empty text is not an error: it gives an empty report.
    """
    reading = read_text(text, rules=rules, min_severity=min_severity)
    report = build(reading, source_name, top_n=top_n, bucket=bucket)
    return Analysis(report=report, warnings=reading.warnings, entries=reading.entries)
