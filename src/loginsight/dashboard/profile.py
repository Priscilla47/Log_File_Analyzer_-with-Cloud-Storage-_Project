"""Everything one address did, for the dashboard's per-IP view.

Built from the same parsed entries and detections as the rest of the report, so the numbers
add up: the status classes sum to the requests, and over all addresses the requests sum to the
total. No Streamlit and no file access.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from loginsight.analysis.summary import summarize
from loginsight.dashboard.filters import canonical_address
from loginsight.detection.models import Detection
from loginsight.parsing.models import LogEntry

TOP_PATHS = 10


@dataclass(frozen=True, slots=True, kw_only=True)
class IpProfile:
    """What one address did. ``known`` is ``False`` when it appears in neither the requests nor
    the detections; every number is then 0 and the lists are empty.

    ``top_paths`` are the most requested paths (without query strings) and ``other_requests``
    the requests to all the other paths, so the two always add up to ``requests``.
    """

    ip: str
    known: bool
    requests: int
    first_seen: datetime | None
    last_seen: datetime | None
    status_classes: dict[str, int]
    distinct_paths: int
    top_paths: list[tuple[str, int]]
    other_requests: int
    detections: list[Detection]


def ip_profile(
    entries: Iterable[LogEntry],
    detections: Iterable[Detection],
    ip: str,
    *,
    top_n: int = TOP_PATHS,
) -> IpProfile:
    """The profile of ``ip`` (compared as in :func:`~loginsight.dashboard.filters.same_address`).

    An address that never appears gives an empty profile, not an exception. ``top_n`` is how
    many paths are listed (a negative number raises :class:`ValueError`).
    """
    wanted = canonical_address(ip)  # worked out once; the others are remembered per address
    mine = [e for e in entries if e.ip == ip or canonical_address(e.ip) == wanted]
    found = [d for d in detections if d.ip == ip or canonical_address(d.ip) == wanted]
    everything = summarize(mine, top_n=top_n)
    distinct = len({entry.path for entry in mine})
    listed = sum(count for _, count in everything.top_paths)
    return IpProfile(
        ip=ip,
        known=bool(mine or found),
        requests=everything.total_requests,
        first_seen=everything.first_time,
        last_seen=everything.last_time,
        status_classes=everything.status_classes,
        distinct_paths=distinct,
        top_paths=everything.top_paths,
        other_requests=everything.total_requests - listed,
        detections=found,
    )
