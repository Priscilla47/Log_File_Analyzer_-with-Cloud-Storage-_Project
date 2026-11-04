"""What the dashboard shows, computed without Streamlit.

The page only draws what this module hands it, so everything that can be wrong can be tested
without a browser. It never imports Streamlit. The numbers come from the same
:func:`loginsight.workflow.analyze_text` the command line uses, so the two cannot disagree.
"""

from dataclasses import dataclass, field

from loginsight.reporting.report import Report, human_bytes
from loginsight.workflow import NothingReadError, analyze_text

APP_TITLE = "LogInsight"
EMPTY_MESSAGE = (
    "Choose an Apache or Nginx access log to see what happened and what looks like an attack."
)

# Bigger logs are better read with the command line; this also bounds the memory one page uses.
UPLOAD_LIMIT_MB = 50
UPLOAD_LIMIT_BYTES = UPLOAD_LIMIT_MB * 1024 * 1024


@dataclass(frozen=True, slots=True, kw_only=True)
class Card:
    """One headline number: a label, the value as text, and a sentence explaining it."""

    label: str
    value: str
    help: str


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


def _facts(report: Report) -> list[str]:
    stats = report.stats
    return [
        f"File: {report.source_name}",
        f"Format: {report.log_format}",
        f"Lines: {stats.total_lines} read, {stats.parsed} parsed, {stats.skipped} skipped "
        f"({stats.success_rate:.1%} parsed)",
    ]


def analyze_upload(raw: bytes, name: str, *, limit: int = UPLOAD_LIMIT_BYTES) -> Outcome:
    """Analyse the bytes of an uploaded log and describe what the page should show.

    The bytes are read like the command line reads a file: UTF-8, a leading byte order mark
    dropped, invalid bytes replaced. A file over ``limit`` bytes, or one where no line can be
    read as a log entry, gives an ``error`` with a readable message and no numbers; an empty
    file is not an error. Nothing here raises for a problem with the file.
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
        analysis = analyze_text(text, name)
    except NothingReadError as error:
        return Outcome(
            name=name,
            error=(
                f"None of the {error.total_lines} lines could be read as an access-log entry "
                f"({error.reasons}). Is this an Apache or Nginx access log?"
            ),
        )
    report = analysis.report
    return Outcome(
        name=name,
        report=report,
        cards=overview(report),
        facts=_facts(report),
        warnings=analysis.warnings,
        notice="The file has no requests in it." if not report.summary.total_requests else None,
    )


def limit_text(count: int, *, decimals: bool = True) -> str:
    """A byte count in megabytes for the messages about the size limit: ``50.0 MB`` or ``50 MB``."""
    megabytes = count / (1024 * 1024)
    return f"{megabytes:.1f} MB" if decimals else f"{round(megabytes, 1):g} MB"
