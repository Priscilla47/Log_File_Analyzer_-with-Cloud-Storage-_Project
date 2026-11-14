"""Narrowing the detections the dashboard lists, and turning them into a table.

Pure functions on :class:`~loginsight.detection.models.Detection` objects, so everything that
can go wrong is tested without a browser. Text that comes from the log (the evidence) is never
interpreted: the table holds it as plain text with control characters escaped.
"""

import ipaddress
from collections import Counter
from collections.abc import Collection, Iterable
from datetime import datetime, timedelta, timezone

from loginsight.detection.models import Detection, Severity
from loginsight.reporting.text import printable

# A badge for each severity: a coloured square for a quick look and the word for everyone,
# so the meaning never depends on telling colours apart.
BADGES = {
    Severity.CRITICAL: "\U0001f7e5 critical",
    Severity.HIGH: "\U0001f7e7 high",
    Severity.MEDIUM: "\U0001f7e8 medium",
    Severity.LOW: "\U0001f7e6 low",
}

# How finely the time slider moves: the logs are timed to the second.
SLIDER_STEP = timedelta(seconds=1)

COLUMNS = ("Severity", "Class", "Rule", "IP", "Time (UTC)", "Requests", "Evidence")


def _utc(moment: datetime) -> datetime:
    """``moment`` in UTC; a time without a time zone is taken to be UTC, as the parser does."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def same_address(first: str, second: str) -> bool:
    """Whether two addresses are the same: equal text, or the same IPv4 or IPv6 address.

    ``2001:DB8::1`` and ``2001:0db8:0:0:0:0:0:1`` are one address. Text that is not an address
    only equals itself.
    """
    if first == second:
        return True
    try:
        return ipaddress.ip_address(first) == ipaddress.ip_address(second)
    except ValueError:
        return False


def filter_detections(
    detections: Iterable[Detection],
    severities: Collection[Severity] | None = None,
    labels: Collection[str] | None = None,
    ip: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[Detection]:
    """The detections that meet every condition given, in their original order.

    A condition left as ``None`` is not applied. An empty ``severities`` or ``labels`` matches
    nothing (nothing is allowed), which is not the same as ``None``. ``ip`` must be the
    address of the detection (see :func:`same_address`). The time range is half open: a
    detection at ``start`` is in, one at ``end`` is out. Times without a time zone are UTC.
    """
    start_utc = _utc(start) if start is not None else None
    end_utc = _utc(end) if end is not None else None
    kept = []
    for detection in detections:
        if severities is not None and detection.severity not in severities:
            continue
        if labels is not None and detection.label not in labels:
            continue
        if ip is not None and not same_address(detection.ip, ip):
            continue
        if start_utc is not None or end_utc is not None:
            when = _utc(detection.time)
            if (start_utc is not None and when < start_utc) or (
                end_utc is not None and when >= end_utc
            ):
                continue
        kept.append(detection)
    return kept


def severity_counts(detections: Iterable[Detection]) -> dict[Severity, int]:
    """Detections per severity, most serious first; every severity is there, even with 0."""
    counted = Counter(detection.severity for detection in detections)
    return {severity: counted[severity] for severity in sorted(Severity, reverse=True)}


def label_counts(detections: Iterable[Detection]) -> dict[str, int]:
    """Detections per class, the most frequent first (ties by name); only classes that occur."""
    counted = Counter(detection.label for detection in detections)
    return dict(sorted(counted.items(), key=lambda item: (-item[1], item[0])))


def ip_counts(detections: Iterable[Detection]) -> dict[str, int]:
    """Detections per address, the most frequent first (ties by address)."""
    counted = Counter(detection.ip for detection in detections)
    return dict(sorted(counted.items(), key=lambda item: (-item[1], item[0])))


def detections_table(detections: Iterable[Detection]) -> dict[str, list]:
    """The detections as columns of plain values, in the order given.

    Text from the log is escaped with :func:`~loginsight.reporting.text.printable`, so it is
    shown exactly as logged and cannot hide anything in control characters.
    """
    rows = list(detections)
    return {
        "Severity": [BADGES[row.severity] for row in rows],
        "Class": [row.label for row in rows],
        "Rule": [row.rule_id for row in rows],
        "IP": [printable(row.ip) for row in rows],
        "Time (UTC)": [_utc(row.time).replace(tzinfo=None) for row in rows],
        "Requests": [row.count for row in rows],
        "Evidence": [printable(row.evidence) for row in rows],
    }


def time_bounds(detections: Iterable[Detection]) -> tuple[datetime, datetime] | None:
    """The first and last detection time, to the second, in UTC without a time zone.

    That is what a time slider needs. ``None`` when there is nothing to choose between: no
    detections, or all within the same second.
    """
    times = [_utc(detection.time).replace(tzinfo=None, microsecond=0) for detection in detections]
    if not times or min(times) == max(times):
        return None
    return min(times), max(times)


def range_to_filter(
    full: tuple[datetime, datetime], chosen: tuple[datetime, datetime]
) -> tuple[datetime | None, datetime | None]:
    """The ``start`` and ``end`` to give :func:`filter_detections` for a slider range.

    The slider's end is a moment that must still be included, and ``end`` is excluded, so one
    second is added to it. The whole range, which excludes nothing, gives ``(None, None)``.
    """
    if chosen == full:
        return None, None
    return chosen[0], chosen[1] + timedelta(seconds=1)
