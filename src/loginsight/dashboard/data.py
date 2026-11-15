"""What the dashboard shows, computed without Streamlit.

The page only draws what this module hands it, so everything that can be wrong can be tested
without a browser. It never imports Streamlit. The numbers come from the same
:func:`loginsight.workflow.analyze_text` the command line uses, so the two cannot disagree.
"""

from dataclasses import dataclass, field
from datetime import timedelta, timezone

from loginsight.dashboard.filters import MAX_ADDRESS_CHOICES, canonical_address, cell, ip_counts
from loginsight.dashboard.profile import IpProfile
from loginsight.parsing.models import LogEntry
from loginsight.reporting.report import Report, human_bytes
from loginsight.reporting.text import printable
from loginsight.workflow import NothingReadError, Reading, build, read_bytes

APP_TITLE = "LogInsight"
EMPTY_MESSAGE = (
    "Choose an Apache or Nginx access log to see what happened and what looks like an attack."
)

# Bigger logs are better read with the command line; this also bounds the memory one page uses.
# Streamlit's ``maxUploadSize`` counts decimal megabytes (1 MB = 1,000,000 bytes), so this does
# too. Counted in MiB the limit would be looser than the uploader's, which refuses a file of
# 52.1 MB before our own message can be shown.
UPLOAD_LIMIT_MB = 50
BYTES_PER_MB = 1_000_000
UPLOAD_LIMIT_BYTES = UPLOAD_LIMIT_MB * BYTES_PER_MB


# The periods the traffic can be grouped by, and the one shown first.
BUCKETS = ("minute", "hour", "day")
DEFAULT_BUCKET = "hour"

# At most this many addresses are offered for the per-address view (the same number as in the
# detections filter), so a log with tens of thousands of addresses cannot make the list unusable.
MAX_IP_CHOICES = MAX_ADDRESS_CHOICES

# The traffic is first grouped by the finest period that still gives a readable line: minutes for
# a log of up to this many hours, hours up to this many days, days for a longer one.
MINUTES_UP_TO_HOURS = 3
HOURS_UP_TO_DAYS = 3

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
    entries: list[LogEntry] = field(default_factory=list)


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
        f"File: {printable(report.source_name)}",
        f"Format: {report.log_format}",
        f"Lines: {stats.total_lines} read, {stats.parsed} parsed, {stats.skipped} skipped "
        f"({stats.success_rate:.1%} parsed)",
    ]


@dataclass(slots=True)
class Upload:
    """An uploaded file after it was read, before it is shown for one traffic period.

    Reading is the slow part, so the page keeps this and only asks :func:`show` for the period
    chosen. Exactly one of ``reading`` and ``error`` is set. ``shown`` remembers what was built
    for each period (a period is built once); apart from that, treat it as read-only.
    """

    name: str
    reading: Reading | None = None
    error: str | None = None
    shown: dict[str, Outcome] = field(default_factory=dict)


def read_upload(raw: bytes, name: str, *, limit: int = UPLOAD_LIMIT_BYTES) -> Upload:
    """Read the bytes of an uploaded log, like the command line reads a file.

    UTF-8, a leading byte order mark dropped, invalid bytes replaced. A file over ``limit``
    bytes, or one where no line can be read as a log entry, gives an ``error`` with a readable
    message; an empty file is not an error. Nothing here raises for a problem with the file.
    """
    if len(raw) > limit:
        return Upload(
            name=name,
            error=(
                f"This file is {limit_text(len(raw))}, and the dashboard takes files up to "
                f"{limit_text(limit, decimals=False)}. For a bigger log use the command line: "
                "loginsight analyze FILE"
            ),
        )
    try:
        reading = read_bytes(raw)
    except NothingReadError as error:
        return Upload(
            name=name,
            error=(
                f"None of the {error.total_lines} lines could be read as an access-log entry "
                f"({error.reasons}). Is this an Apache or Nginx access log?"
            ),
        )
    return Upload(name=name, reading=reading)


def show(upload: Upload, bucket: str = DEFAULT_BUCKET) -> Outcome:
    """What the page shows for ``upload`` with the traffic grouped by ``bucket``.

    ``bucket`` is one of :data:`BUCKETS`, otherwise :class:`ValueError`. Only the traffic
    depends on it: the requests, the detections and the numbers are the same for every period.
    """
    if upload.error is not None:
        return Outcome(name=upload.name, error=upload.error)
    if bucket in upload.shown:
        return upload.shown[bucket]
    reading = upload.reading
    assert reading is not None  # an upload has a reading or an error
    report = build(reading, upload.name, bucket=bucket)
    has_requests = bool(report.summary.total_requests)
    outcome = Outcome(
        name=upload.name,
        report=report,
        cards=overview(report),
        facts=_facts(report),
        warnings=reading.warnings,
        notice=None if has_requests else "The file has no requests in it.",
        charts=_charts(report) if has_requests else None,
        entries=reading.entries,
    )
    upload.shown[bucket] = outcome
    return outcome


def suggested_bucket(upload: Upload) -> str:
    """The period to group the traffic by at first: fine enough for the line to show something.

    A log of ten minutes grouped by the hour is one point, which draws no line at all, so the
    period follows how long the log is (see :data:`MINUTES_UP_TO_HOURS`); a log that could not
    be read, or has no requests, gets :data:`DEFAULT_BUCKET`.
    """
    if upload.error is not None:
        return DEFAULT_BUCKET
    summary = show(upload, DEFAULT_BUCKET).report.summary  # type: ignore[union-attr]
    if summary.first_time is None or summary.last_time is None:
        return DEFAULT_BUCKET
    span = summary.last_time - summary.first_time
    if span <= timedelta(hours=MINUTES_UP_TO_HOURS):
        return "minute"
    if span <= timedelta(days=HOURS_UP_TO_DAYS):
        return "hour"
    return "day"


def analyze_upload(
    raw: bytes, name: str, *, limit: int = UPLOAD_LIMIT_BYTES, bucket: str = DEFAULT_BUCKET
) -> Outcome:
    """Read an uploaded log and show it: :func:`read_upload` and then :func:`show`."""
    return show(read_upload(raw, name, limit=limit), bucket)


def _charts(report: Report) -> Charts:
    return Charts(
        status=status_table(report),
        traffic=traffic_table(report),
        top_paths=top_paths_table(report),
        bucket=report.bucket,
        gaps_filled=report.gaps_filled,
    )


def ip_choices(report: Report, *, limit: int = MAX_IP_CHOICES) -> list[str]:
    """The addresses offered for a closer look, at most ``limit`` of them.

    First those with detections (the most detections first), then the busiest addresses of the
    report, without repeats. An address is listed once however it is spelled in the log, in its
    canonical form (see :func:`~loginsight.dashboard.filters.canonical_address`).
    """
    chosen = dict.fromkeys(ip_counts(report.detections))
    chosen.update(dict.fromkeys(canonical_address(ip) for ip, _ in report.summary.top_ips))
    return list(chosen)[:limit]


def limit_text(count: int, *, decimals: bool = True) -> str:
    """A byte count in megabytes for the messages about the size limit.

    With ``decimals`` it is rounded **up** to a tenth (``50.1 MB``), so a file just over a
    limit of 50 MB never reads as "50.0 MB"; without, it is the exact limit (``50 MB``).
    """
    megabyte = BYTES_PER_MB
    if decimals:
        tenths = -(-count * 10 // megabyte)  # a ceiling, in whole numbers
        return f"{tenths / 10:.1f} MB"
    return f"{round(count / megabyte, 1):g} MB"


def _moment(value) -> str:
    """A time in UTC (the log's own offset is converted; no offset means UTC), or ``-``."""
    if not value:
        return "-"
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def profile_facts(profile: IpProfile) -> list[str]:
    """When the address was first and last seen, as lines of plain text.

    They are text and not cards: a full date and time is too wide for a card, and a browser
    check showed it cut to ``2026-01-01 00:09:...``.
    """
    return [
        f"First seen: {_moment(profile.first_seen)}",
        f"Last seen: {_moment(profile.last_seen)}",
    ]


def profile_cards(profile: IpProfile) -> list[Card]:
    """The headline numbers of one address, in the order the page shows them."""
    return [
        Card(label="Requests", value=str(profile.requests), help="Requests this address sent."),
        Card(
            label="Detections",
            value=str(len(profile.detections)),
            help="Detections that name this address.",
        ),
    ]


def profile_status_table(profile: IpProfile) -> dict[str, list]:
    """The responses this address got, by status class (the classes it got only)."""
    names = [name for name, count in profile.status_classes.items() if count]
    return {"Status class": names, "Requests": [profile.status_classes[name] for name in names]}


def profile_paths_table(profile: IpProfile) -> dict[str, list]:
    """The paths this address asked for, busiest first, then one row for all the others.

    A path a spreadsheet would read as a formula is quoted (see ``filters.cell``).
    """
    paths = [cell(_label(path)) for path, _ in profile.top_paths]
    counts = [count for _, count in profile.top_paths]
    if profile.other_requests:
        others = profile.distinct_paths - len(profile.top_paths)
        paths.append(f"(other paths: {others})")
        counts.append(profile.other_requests)
    return {"Path": paths, "Requests": counts}
