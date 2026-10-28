"""Behavioural detection: rules that look across the requests of one address.

A signature rule judges one request on its own. These rules judge what an address does over
time: many failed logins in a short while is a password-guessing attack, even though each
single failed login is perfectly normal.

Timestamps are compared in UTC, so logs that mix time zones, and logs whose lines are
slightly out of order, give the same answer as a sorted UTC log. A timestamp without a time
zone is taken to be UTC.
"""

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from loginsight.detection.models import Detection, Severity, shorten_evidence
from loginsight.detection.ruleset import BruteForceSettings, ScannerSettings
from loginsight.parsing.models import LogEntry

RULE_ID_BRUTE_FORCE = "behaviour-brute-force"
RULE_ID_SCANNER_BURST = "behaviour-scanner-burst"
RULE_ID_SCANNER_TOOL = "behaviour-scanner-tool"

# A burst this many times larger than the threshold is escalated one step. Every behavioural
# rule uses this one number, so the severity scale is defined in a single place.
ESCALATION_FACTOR = 5

_FAILED_LOGIN_STATUSES = (401, 403)
_NOT_FOUND = 404


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


def _has_dense_window(chain: list, threshold: int, window: timedelta, key=None) -> bool:
    """Whether some stretch of ``window`` (ends included) holds ``threshold`` events.

    With ``key`` given, events are counted by distinct ``key(event)`` instead of one each, so
    the same page requested a hundred times in a window still counts once.
    """
    if len(chain) < threshold:
        return False
    seen: Counter = Counter()
    start = 0
    for end in range(len(chain)):
        seen[key(chain[end]) if key else end] += 1
        while chain[end][0] - chain[start][0] > window:
            gone = key(chain[start]) if key else start
            seen[gone] -= 1
            if not seen[gone]:
                del seen[gone]
            start += 1
        if len(seen) >= threshold:
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


def _scan_burst_evidence(chain: list) -> str:
    first, last = chain[0], chain[-1]
    seconds = int((last[0] - first[0]).total_seconds())
    distinct = len({event[2].path for event in chain})
    return (
        f"{distinct} distinct missing paths in {seconds} s "
        f"(first: {first[2].method} {first[2].path})"
    )


def _tool_evidence(tool: str, events: list) -> str:
    count = len(events)
    noun = "request" if count == 1 else "requests"
    return (
        f"{count} {noun} with the {tool!r} user agent "
        f"(first: {shorten_evidence(events[0][2].request)})"
    )


def detect_scanners(
    entries: Iterable[LogEntry], settings: ScannerSettings | None = None
) -> list[Detection]:
    """Find scanning behaviour: bursts of distinct missing pages, and known scanning tools.

    **Burst rule** (``behaviour-scanner-burst``). The 404 responses of each address are put in
    time order and split into runs wherever two are more than ``settings.window_seconds``
    apart. A run is reported when some stretch of ``window_seconds`` holds
    ``settings.threshold`` *different* paths (the query string is ignored), so a broken link
    requested a hundred times is not a scan. ``count`` is every 404 in the run, the evidence
    says how many different paths it covered, and the severity comes from
    :func:`burst_severity` on that number. Requests without a path are ignored.

    **Tool rule** (``behaviour-scanner-tool``). A request whose user agent contains one of
    ``settings.user_agents`` (ignoring case; a request naming several tools counts for the
    first in the settings order) gives one low-severity detection per address and tool, at the
    first such request, with ``count`` the number of requests that used it. User agents can be
    faked, and a plain substring can match an innocent one that happens to contain the name,
    which is why this rule is only ever low. A missing user agent never matches.

    The result is ordered by position, then address, then rule.
    """
    settings = settings or ScannerSettings()
    window = timedelta(seconds=settings.window_seconds)
    tools = [name.lower() for name in settings.user_agents if name]

    missing: dict[str, list] = defaultdict(list)
    by_tool: dict[tuple[str, str], list] = defaultdict(list)
    for index, entry in enumerate(entries):
        is_miss = entry.status == _NOT_FOUND and bool(entry.path)
        agent = entry.user_agent.lower() if entry.user_agent and tools else ""
        named = next((name for name in tools if name in agent), None) if agent else None
        if not (is_miss or named):
            continue
        event = (_utc(entry.time), index, entry)
        if is_miss:
            missing[entry.ip].append(event)
        if named:
            by_tool[(entry.ip, named)].append(event)

    found = []
    for ip, events in missing.items():
        events.sort(key=lambda event: event[0])  # stable: equal times keep input order
        for chain in _chains(events, window):
            if not _has_dense_window(chain, settings.threshold, window, key=lambda e: e[2].path):
                continue
            indexes = [event[1] for event in chain]
            distinct = len({event[2].path for event in chain})
            found.append(
                Detection(
                    rule_id=RULE_ID_SCANNER_BURST,
                    label="scanner",
                    severity=burst_severity(distinct, settings.threshold),
                    ip=ip,
                    time=chain[0][2].time,
                    first_index=min(indexes),
                    last_index=max(indexes),
                    count=len(chain),
                    evidence=_scan_burst_evidence(chain),
                )
            )
    for (ip, name), events in by_tool.items():
        events.sort(key=lambda event: event[0])
        indexes = [event[1] for event in events]
        found.append(
            Detection(
                rule_id=RULE_ID_SCANNER_TOOL,
                label="scanner",
                severity=Severity.LOW,
                ip=ip,
                time=events[0][2].time,
                first_index=min(indexes),
                last_index=max(indexes),
                count=len(events),
                evidence=_tool_evidence(name, events),
            )
        )
    found.sort(key=lambda d: (d.first_index, d.ip, d.rule_id))
    return found
