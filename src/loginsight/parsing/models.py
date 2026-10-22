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
