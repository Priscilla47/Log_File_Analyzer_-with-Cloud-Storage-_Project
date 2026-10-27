"""Data models for parsed access-log lines."""

from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class LogEntry:
    """One parsed line of a web server access log.

    The entry is immutable. Fields that could not be read from a malformed request line are
    empty strings, and ``request`` always keeps the raw request line exactly as logged.
    """

    ip: str
    time: datetime
    method: str
    path: str
    query: str
    protocol: str
    status: int
    size: int
    referer: str | None = None
    user_agent: str | None = None
    request: str

    @property
    def target(self) -> str:
        """The path with its query string, as the client requested it."""
        return f"{self.path}?{self.query}" if self.query else self.path

    def to_dict(self) -> dict:
        """All fields as a plain dict, for building DataFrames and JSON output."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """One line that could not be parsed, with where it was and why."""

    line_number: int
    reason: str
    line: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ParseStats:
    """What happened while reading a log file.

    Blank lines are not counted, so ``parsed + skipped == total_lines`` always holds.
    ``first_errors`` keeps only the first few problems, with the line text shortened.

    The dataclass is frozen, so a field cannot be reassigned, but ``skipped_by_reason`` and
    ``first_errors`` are an ordinary dict and list that could still be changed in place. Treat
    the statistics as read-only.
    """

    total_lines: int
    parsed: int
    skipped: int
    skipped_by_reason: dict[str, int]
    first_errors: list[ParseIssue]

    @property
    def success_rate(self) -> float:
        """Share of lines that were parsed, or ``1.0`` for a file with no lines."""
        return self.parsed / self.total_lines if self.total_lines else 1.0


@dataclass(frozen=True, slots=True)
class ParseResult:
    """The entries read from a file together with the statistics about the read.

    Frozen in the same limited sense as :class:`ParseStats`: ``entries`` is an ordinary list.
    """

    entries: list[LogEntry]
    stats: ParseStats
