"""Behavioural detection: rules that look across the requests of one address.

A signature rule judges one request on its own. These rules judge what an address does over
time: many failed logins in a short while is a password-guessing attack, even though each
single failed login is perfectly normal.

Timestamps are compared in UTC, so logs that mix time zones, and logs whose lines are
slightly out of order, give the same answer as a sorted UTC log. A timestamp without a time
zone is taken to be UTC.
"""

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from loginsight.detection.models import Detection, Severity
from loginsight.detection.ruleset import BruteForceSettings
from loginsight.parsing.models import LogEntry

RULE_ID_BRUTE_FORCE = "behaviour-brute-force"

# A burst this many times larger than the threshold is escalated one step. Every behavioural
# rule uses this one number, so the severity scale is defined in a single place.
ESCALATION_FACTOR = 5

_FAILED_LOGIN_STATUSES = (401, 403)


def burst_severity(count: int, threshold: int) -> Severity:
    """How serious a burst of ``count`` events is for a rule whose trigger is ``threshold``.

    ``MEDIUM`` for a burst that just reaches the threshold, ``HIGH`` once it is
    :data:`ESCALATION_FACTOR` times the threshold or more.
    """
    return Severity.HIGH if count >= ESCALATION_FACTOR * threshold else Severity.MEDIUM


def _utc(moment: datetime) -> datetime:
    """``moment`` in UTC. Raises :class:`ValueError` for an instant that cannot be converted."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    try:
        return moment.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError(f"timestamp out of range: {moment.isoformat()}") from None


def _chains(events: list, window: timedelta) -> list[list]:
    """Split time-ordered ``(utc_time, index, entry)`` events where the gap exceeds ``window``."""
    chains: list[list] = []
    for event in events:
        if chains and event[0] - chains[-1][-1][0] <= window:
            chains[-1].append(event)
        else:
            chains.append([event])
    return chains


def _has_dense_window(chain: list, threshold: int, window: timedelta) -> bool:
    """Whether some stretch of ``window`` (ends included) holds ``threshold`` events."""
    if len(chain) < threshold:
        return False
    start = 0
    for end in range(len(chain)):
        while chain[end][0] - chain[start][0] > window:
            start += 1
        if end - start + 1 >= threshold:
            return True
    return False


def _failed_login_evidence(chain: list) -> str:
    first, last = chain[0], chain[-1]
    seconds = int((last[0] - first[0]).total_seconds())
    noun = "failed login" if len(chain) == 1 else "failed logins"
    return f"{len(chain)} {noun} in {seconds} s (first: {first[2].method} {first[2].path})"


def detect_brute_force(
    entries: Iterable[LogEntry], settings: BruteForceSettings | None = None
) -> list[Detection]:
    """Report each burst of failed logins from one address as one :class:`Detection`.

    A failed login is a request to one of ``settings.login_paths`` (query string ignored)
    answered with 401 or 403. The failures of each address are put in time order and split
    into bursts wherever two are more than ``settings.window_seconds`` apart. A burst is
    reported when some stretch of ``window_seconds`` holds ``settings.threshold`` failures,
    so a slow trickle that never gets that dense is not. Different addresses are never
    combined.

    The detection's ``count`` is every failure in the burst, ``first_index`` and
    ``last_index`` are the lowest and highest positions among them in ``entries``, and
    ``time`` is the time of the earliest failure. Severity comes from :func:`burst_severity`.
    The result is ordered by position, then address.
    """
    settings = settings or BruteForceSettings()
    window = timedelta(seconds=settings.window_seconds)
    login_paths = frozenset(settings.login_paths)

    by_ip: dict[str, list] = defaultdict(list)
    for index, entry in enumerate(entries):
        if entry.status in _FAILED_LOGIN_STATUSES and entry.path in login_paths:
            by_ip[entry.ip].append((_utc(entry.time), index, entry))

    found = []
    for ip, events in by_ip.items():
        events.sort(key=lambda event: event[0])  # stable: equal times keep input order
        for chain in _chains(events, window):
            if not _has_dense_window(chain, settings.threshold, window):
                continue
            indexes = [event[1] for event in chain]
            found.append(
                Detection(
                    rule_id=RULE_ID_BRUTE_FORCE,
                    label="brute_force",
                    severity=burst_severity(len(chain), settings.threshold),
                    ip=ip,
                    time=chain[0][2].time,
                    first_index=min(indexes),
                    last_index=max(indexes),
                    count=len(chain),
                    evidence=_failed_login_evidence(chain),
                )
            )
    found.sort(key=lambda d: (d.first_index, d.ip))
    return found
