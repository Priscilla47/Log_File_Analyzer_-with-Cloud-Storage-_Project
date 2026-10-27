"""Summary statistics over parsed log entries.

Pure Python: no files, no pandas. Everything is deterministic, so the same entries always give
the same summary whatever order they arrive in.
"""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from loginsight.parsing.models import LogEntry

STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx", "other")
NO_METHOD = "(none)"  # shown for a request line the parser could not split


def _status_class(status: int) -> str:
    """``"2xx"`` for 200 to 299 and so on, ``"other"`` for anything outside 100 to 599."""
    return f"{status // 100}xx" if 100 <= status <= 599 else "other"


def _ranked(counter: Counter, limit: int | None = None) -> list[tuple]:
    """Items from most to least common, ties broken by the value itself, ascending."""
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return ranked if limit is None else ranked[:limit]


@dataclass(frozen=True, slots=True, kw_only=True)
class Summary:
    """The headline numbers for a set of log entries.

    ``status_classes`` always has all six keys (``1xx`` to ``5xx`` and ``other``, which holds
    status numbers outside 100 to 599). ``error_rate`` is the share of 4xx and 5xx responses.
    ``first_time`` and ``last_time`` are ``None`` for no entries. Timestamps are compared as
    instants, so entries logged in different time zones can be mixed, but timestamps with and
    without a time zone cannot.

    The dataclass is frozen, so a field cannot be reassigned, but the lists and dicts inside
    it are ordinary ones and could still be changed in place. Treat a ``Summary`` as read-only.
    :meth:`to_dict` returns copies, so its result is safe to modify.
    """

    total_requests: int
    unique_ips: int
    top_ips: list[tuple[str, int]]
    top_paths: list[tuple[str, int]]
    status_classes: dict[str, int]
    status_codes: dict[int, int]
    methods: dict[str, int]
    total_bytes: int
    error_rate: float
    first_time: datetime | None
    last_time: datetime | None

    def to_dict(self) -> dict:
        """A JSON-safe dict: timestamps as ISO 8601 text and status codes as string keys."""
        return {
            "total_requests": self.total_requests,
            "unique_ips": self.unique_ips,
            "top_ips": [{"ip": ip, "requests": n} for ip, n in self.top_ips],
            "top_paths": [{"path": path, "requests": n} for path, n in self.top_paths],
            "status_classes": dict(self.status_classes),
            "status_codes": {str(code): n for code, n in self.status_codes.items()},
            "methods": dict(self.methods),
            "total_bytes": self.total_bytes,
            "error_rate": self.error_rate,
            "first_time": self.first_time.isoformat() if self.first_time else None,
            "last_time": self.last_time.isoformat() if self.last_time else None,
        }


def summarize(entries: Iterable[LogEntry], top_n: int = 10) -> Summary:
    """Summarise ``entries`` in a single pass.

    ``top_n`` limits the ``top_ips`` and ``top_paths`` lists (``0`` gives empty lists, a
    negative number raises :class:`ValueError`). Paths are counted without their query string.
    """
    if top_n < 0:
        raise ValueError("top_n must not be negative")

    ips: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    codes: Counter[int] = Counter()
    methods: Counter[str] = Counter()
    classes = dict.fromkeys(STATUS_CLASSES, 0)
    total = total_bytes = 0
    first = last = None

    for entry in entries:
        total += 1
        total_bytes += entry.size
        ips[entry.ip] += 1
        paths[entry.path] += 1
        codes[entry.status] += 1
        methods[entry.method or NO_METHOD] += 1
        classes[_status_class(entry.status)] += 1
        if first is None or entry.time < first:
            first = entry.time
        if last is None or entry.time > last:
            last = entry.time

    errors = classes["4xx"] + classes["5xx"]
    return Summary(
        total_requests=total,
        unique_ips=len(ips),
        top_ips=_ranked(ips, top_n),
        top_paths=_ranked(paths, top_n),
        status_classes=classes,
        status_codes=dict(sorted(codes.items())),
        methods=dict(_ranked(methods)),
        total_bytes=total_bytes,
        error_rate=errors / total if total else 0.0,
        first_time=first,
        last_time=last,
    )
