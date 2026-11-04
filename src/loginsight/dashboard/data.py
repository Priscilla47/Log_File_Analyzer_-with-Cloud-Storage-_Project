"""What the dashboard shows, computed without Streamlit.

The page only draws what this module hands it, so everything that can be wrong can be tested
without a browser. It never imports Streamlit. The numbers come from the same
:func:`loginsight.workflow.analyze_text` the command line uses, so the two cannot disagree.
"""

from dataclasses import dataclass, field

from loginsight.reporting.report import Report, human_bytes
from loginsight.reporting.text import printable
from loginsight.workflow import NothingReadError, analyze_text

APP_TITLE = "LogInsight"
EMPTY_MESSAGE = (
    "Choose an Apache or Nginx access log to see what happened and what looks like an attack."
)

# Bigger logs are better read with the command line; this also bounds the memory one page uses.
UPLOAD_LIMIT_MB = 50
UPLOAD_LIMIT_BYTES = UPLOAD_LIMIT_MB * 1024 * 1024


# The periods the traffic can be grouped by, and the one shown first.
BUCKETS = ("minute", "hour", "day")
DEFAULT_BUCKET = "hour"

# A path longer than this is shortened in the chart so the bars stay readable.
MAX_PATH_LABEL = 60

# From the Okabe-Ito palette, which people with the common kinds of colour blindness can tell
# apart: blue for the traffic and vermillion for the errors.
COLOUR_MAIN = "#0072B2"
COLOUR_ERRORS = "#D55E00"

# The status classes that are always charted; "1xx" and "other" only when they have requests.
_MAIN_CLASSES = ("2xx", "3xx", "4xx", "5xx")


@dataclass(frozen=True, slots=True, kw_only=True)
class Card:
    """One headline number: a label, the value as text, and a sentence explaining it."""

    label: str
    value: str
    help: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Charts:
    """The three tables the page draws, as columns of plain Python values.

    ``bucket`` is the period the traffic is grouped by. ``gaps_filled`` is ``False`` when the
    log covers so long a time that only the periods with requests could be listed.
    """

    status: dict[str, list]
    traffic: dict[str, list]
    top_paths: dict[str, list]
    bucket: str
    gaps_filled: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Outcome:
    """Everything the page shows for one uploaded file.

    Exactly one of ``error`` and ``report`` is set. ``cards`` are the headline numbers,
    ``facts`` lines about the file, ``warnings`` things worth knowing (shown above the numbers)
    and ``notice`` a note for a file with no requests in it. None of the texts holds anything
    taken from the file, apart from the lines of ``facts``, which are shown as plain text.
    """

    name: str
    report: Report | None = None
    cards: list[Card] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notice: str | None = None
    error: str | None = None
    charts: Charts | None = None


def overview(report: Report) -> list[Card]:
    """The five headline numbers of ``report``, in the order the page shows them."""
    stats, summary = report.stats, report.summary
    return [
        Card(
            label="Requests",
            value=str(summary.total_requests),
            help="Lines of the log that were read as a request.",
        ),
        Card(
            label="Unique IPs",
            value=str(summary.unique_ips),
            help="Different client addresses that sent a request.",
        ),
        Card(
            label="Error rate",
            value=f"{summary.error_rate:.1%}",
            help="Share of requests answered with an error (4xx and 5xx).",
        ),
        Card(
            label="Data sent",
            value=human_bytes(summary.total_bytes),
            help="Total size of the responses, as the server logged it.",
        ),
        Card(
            label="Skipped lines",
            value=str(stats.skipped),
            help=f"Lines that could not be read, out of {stats.total_lines} lines in the file.",
        ),
    ]


def status_table(report: Report) -> dict[str, list]:
    """Requests per status class: the four main classes always, others only when used."""
    classes = report.summary.status_classes
    names = [name for name in classes if name in _MAIN_CLASSES or classes[name] > 0]
    return {"Status class": names, "Requests": [classes[name] for name in names]}


def traffic_table(report: Report) -> dict[str, list]:
    """Requests and errors for each period of the report's traffic series, in time order."""
    return {
        "Time (UTC)": [bucket.start for bucket in report.buckets],
        "Requests": [bucket.requests for bucket in report.buckets],
        "Errors": [bucket.errors for bucket in report.buckets],
    }


def _label(path: str) -> str:
    """A path as a chart label: escapes for control characters, shortened, never empty."""
    if not path:
        return "(no path)"
    label = printable(path)
    if len(label) > MAX_PATH_LABEL:
        label = label[: MAX_PATH_LABEL - 1] + "…"
    return label


def top_paths_table(report: Report) -> dict[str, list]:
    """The most requested paths, busiest first, as labels that are unique in the chart.

    Two different paths can look the same once shortened, and a chart would merge them into one
    bar, so a repeated label gets a number added to it.
    """
    labels: list[str] = []
    seen: dict[str, int] = {}
    for path, _ in report.summary.top_paths:
        label = _label(path)
        seen[label] = seen.get(label, 0) + 1
        labels.append(label if seen[label] == 1 else f"{label} ({seen[label]})")
    return {"Path": labels, "Requests": [count for _, count in report.summary.top_paths]}


def _facts(report: Report) -> list[str]:
    stats = report.stats
    return [
        f"File: {report.source_name}",
        f"Format: {report.log_format}",
        f"Lines: {stats.total_lines} read, {stats.parsed} parsed, {stats.skipped} skipped "
        f"({stats.success_rate:.1%} parsed)",
    ]


def analyze_upload(
    raw: bytes, name: str, *, limit: int = UPLOAD_LIMIT_BYTES, bucket: str = DEFAULT_BUCKET
) -> Outcome:
    """Analyse the bytes of an uploaded log and describe what the page should show.

    The bytes are read like the command line reads a file: UTF-8, a leading byte order mark
    dropped, invalid bytes replaced. A file over ``limit`` bytes, or one where no line can be
    read as a log entry, gives an ``error`` with a readable message and no numbers; an empty
    file is not an error. ``bucket`` is the period the traffic chart groups by (one of
    :data:`BUCKETS`, otherwise :class:`ValueError`). Nothing else here raises for a problem with
    the file.
    """
    if len(raw) > limit:
        return Outcome(
            name=name,
            error=(
                f"This file is {limit_text(len(raw))}, and the dashboard takes files up to "
                f"{limit_text(limit, decimals=False)}. For a bigger log use the command line: "
                "loginsight analyze FILE"
            ),
        )
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        analysis = analyze_text(text, name, bucket=bucket)
    except NothingReadError as error:
        return Outcome(
            name=name,
            error=(
                f"None of the {error.total_lines} lines could be read as an access-log entry "
                f"({error.reasons}). Is this an Apache or Nginx access log?"
            ),
        )
    report = analysis.report
    has_requests = bool(report.summary.total_requests)
    return Outcome(
        name=name,
        report=report,
        cards=overview(report),
        facts=_facts(report),
        warnings=analysis.warnings,
        notice=None if has_requests else "The file has no requests in it.",
        charts=_charts(report) if has_requests else None,
    )


def _charts(report: Report) -> Charts:
    return Charts(
        status=status_table(report),
        traffic=traffic_table(report),
        top_paths=top_paths_table(report),
        bucket=report.bucket,
        gaps_filled=report.gaps_filled,
    )


def limit_text(count: int, *, decimals: bool = True) -> str:
    """A byte count in megabytes for the messages about the size limit: ``50.0 MB`` or ``50 MB``."""
    megabytes = count / (1024 * 1024)
    return f"{megabytes:.1f} MB" if decimals else f"{round(megabytes, 1):g} MB"
