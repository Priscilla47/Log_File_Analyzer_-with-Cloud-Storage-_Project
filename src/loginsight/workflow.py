"""One analysis, from the text of a log to a report: the steps every interface shares.

The command line and the dashboard both call :func:`analyze_text`, so they cannot disagree
about a number: the format detection, the parsing, the checks on how much was readable, the
detection rules and the report all happen here, once.
"""

from dataclasses import dataclass

from loginsight.detection import Severity, detect, load_rules
from loginsight.detection.ruleset import RuleSet
from loginsight.parsing.detect import detect_log_format
from loginsight.parsing.models import ParseStats
from loginsight.parsing.parser import parse_text
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
class Analysis:
    """A report and the warnings that go with it (text for the person reading the result)."""

    report: Report
    warnings: list[str]


def analyze_text(
    text: str,
    source_name: str,
    *,
    rules: RuleSet | None = None,
    min_severity: Severity = Severity.LOW,
    top_n: int = 10,
    bucket: str = "hour",
) -> Analysis:
    """Analyse the text of an access log.

    The format (Apache or Nginx) is detected, the text parsed, the ``rules`` (the built-in ones
    for ``None``) applied, and detections below ``min_severity`` dropped. ``source_name`` is
    reduced to a file name in the report. Raises :class:`NothingReadError` if the text has lines
    and none could be read, and :class:`ValueError` for a wrong ``top_n`` or ``bucket``. An empty
    text is not an error: it gives an empty report.
    """
    log_format = detect_log_format(text)
    result = parse_text(text, log_format)
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
    report = build_report(
        result,
        detections,
        source_name=source_name,
        top_n=top_n,
        bucket=bucket,
        log_format=log_format,
    )
    return Analysis(report=report, warnings=warnings)
