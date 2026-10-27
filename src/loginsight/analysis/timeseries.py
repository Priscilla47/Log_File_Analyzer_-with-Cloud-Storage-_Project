"""Traffic over time: requests and errors per minute or hour, and the busiest window.

Pure Python, no files and no pandas. Every timestamp is converted to UTC first, so entries
logged in different time zones fall in the right bucket. A timestamp without a time zone is
taken to be UTC, as the parser does.
"""

from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from loginsight.parsing.models import LogEntry

BUCKET_SIZES = {"minute": timedelta(minutes=1), "hour": timedelta(hours=1)}

# Filling gaps creates one object per bucket, so one stray timestamp (a log line dated 1970)
# must not be able to ask for millions of them.
MAX_BUCKETS = 100_000

_ERROR_STATUS = 400  # status codes from here up count as errors


@dataclass(frozen=True, slots=True, kw_only=True)
class TimeBucket:
    """Requests in one minute or hour. ``start`` is in UTC; ``errors`` counts status 400+."""

    start: datetime
    requests: int
    errors: int

    @property
    def error_rate(self) -> float:
        """Share of requests that were errors, ``0.0`` for an empty bucket."""
        return self.errors / self.requests if self.requests else 0.0


@dataclass(frozen=True, slots=True, kw_only=True)
class Window:
    """A stretch of time (``start`` included, ``end`` excluded, both UTC) and its requests."""

    start: datetime
    end: datetime
    requests: int


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _floor(moment: datetime, bucket: str) -> datetime:
    if bucket == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    return moment.replace(second=0, microsecond=0)


def requests_per_bucket(entries: Iterable[LogEntry], bucket: str = "hour") -> list[TimeBucket]:
    """Count requests and errors per ``"minute"`` or ``"hour"``, in time order.

    Quiet periods between the first and last request appear as buckets with zero requests.
    Raises :class:`ValueError` for an unknown ``bucket`` (even for empty input) and when the
    range would need more than :data:`MAX_BUCKETS` buckets.
    """
    if not isinstance(bucket, str) or bucket not in BUCKET_SIZES:
        raise ValueError(f"bucket must be one of {sorted(BUCKET_SIZES)}, not {bucket!r}")
    step = BUCKET_SIZES[bucket]

    requests: Counter[datetime] = Counter()
    errors: Counter[datetime] = Counter()
    for entry in entries:
        start = _floor(_utc(entry.time), bucket)
        requests[start] += 1
        if entry.status >= _ERROR_STATUS:
            errors[start] += 1

    if not requests:
        return []

    first, last = min(requests), max(requests)
    count = (last - first) // step + 1
    if count > MAX_BUCKETS:
        raise ValueError(
            f"time range too large for this bucket size: {count:,} {bucket} buckets "
            f"(the limit is {MAX_BUCKETS:,})"
        )
    return [
        TimeBucket(start=start, requests=requests[start], errors=errors[start])
        for start in (first + step * n for n in range(count))
    ]


def busiest_window(entries: Iterable[LogEntry], minutes: float = 5) -> Window | None:
    """The stretch of ``minutes`` minutes holding the most requests, or ``None`` for no entries.

    Windows start at a request and are half open (a request exactly ``minutes`` minutes after
    the start is outside). Ties go to the earliest window. Raises :class:`ValueError` if
    ``minutes`` is less than 1.
    """
    if minutes < 1:
        raise ValueError("minutes must be at least 1")
    times = sorted(_utc(entry.time) for entry in entries)
    if not times:
        return None

    length = timedelta(minutes=minutes)
    best_start = best_count = 0
    for index, start in enumerate(times):
        count = bisect_left(times, start + length) - index
        if count > best_count:
            best_start, best_count = index, count

    start = times[best_start]
    return Window(start=start, end=start + length, requests=best_count)
