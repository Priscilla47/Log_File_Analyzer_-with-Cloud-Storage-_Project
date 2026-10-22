"""Tolerant parser for Common and Combined access-log lines.

Real logs are messy and attackers send odd requests on purpose, so a line the parser can
place in time is kept even when its request line is malformed. Lines that cannot be read
raise :class:`LogParseError` with a ``reason`` saying why.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from loginsight.parsing.models import LogEntry

# Longer lines are rejected before matching, which bounds the work done per line.
MAX_LINE_LENGTH = 8192

_QUOTED = r'(?:[^"\\]|\\.)*'  # text inside quotes, allowing backslash-escaped characters

_LINE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]*)\] "
    rf'"(?P<request>{_QUOTED})" '
    r"(?P<status>[0-9]{3}) (?P<size>\S+)"
    rf'(?: "(?P<referer>{_QUOTED})" "(?P<user_agent>{_QUOTED})")?'
    r"\s*"
)

_METHOD = re.compile(r"[A-Za-z]+")


class LogParseError(ValueError):
    """A log line could not be parsed.

    ``reason`` is one of ``no_match``, ``bad_timestamp``, ``bad_size`` or ``line_too_long``.
    """

    def __init__(self, reason: str, line: str = ""):
        self.reason = reason
        self.line = line
        super().__init__(f"{reason}: {line[:80]!r}")


def _parse_time(text: str, line: str) -> datetime:
    """Parse an access-log timestamp. A missing timezone is assumed to be UTC."""
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise LogParseError("bad_timestamp", line) from None


def _parse_size(text: str, line: str) -> int:
    if text == "-":
        return 0
    if text.isascii() and text.isdigit():
        return int(text)
    raise LogParseError("bad_size", line)


def _split_request(request: str) -> tuple[str, str, str, str]:
    """Split a raw request line into ``(method, path, query, protocol)``.

    The first token is the method, a trailing ``HTTP/x`` token is the protocol, and whatever
    is in between is the target, so a path containing spaces survives. A request that does
    not start with a method (``-``, escaped binary, ...) gives four empty strings.
    """
    method, _, rest = request.partition(" ")
    if not _METHOD.fullmatch(method):
        return "", "", "", ""

    target = rest.lstrip(" ")
    protocol = ""
    head, separator, last = target.rpartition(" ")
    if separator and last.upper().startswith("HTTP/"):
        target, protocol = head.rstrip(" "), last

    path, _, query = target.partition("?")
    return method, path, query, protocol


def parse_line(line: str) -> LogEntry:
    """Parse one Common or Combined format line into a :class:`LogEntry`.

    Raises :class:`LogParseError` if the line cannot be read.
    """
    line = line.rstrip("\r\n")
    if len(line) > MAX_LINE_LENGTH:
        raise LogParseError("line_too_long", line)

    match = _LINE.fullmatch(line)
    if match is None:
        raise LogParseError("no_match", line)

    time = _parse_time(match["time"], line)
    size = _parse_size(match["size"], line)
    request = match["request"]
    method, path, query, protocol = _split_request(request)
    referer = match["referer"]
    user_agent = match["user_agent"]

    return LogEntry(
        ip=match["ip"],
        time=time,
        method=method,
        path=path,
        query=query,
        protocol=protocol,
        status=int(match["status"]),
        size=size,
        referer=None if referer in (None, "-") else referer,
        user_agent=None if user_agent in (None, "-") else user_agent,
        request=request,
    )


def parse_file(filepath: str | Path) -> list[LogEntry]:
    """Parse every readable line of a log file.

    Blank lines and lines that raise :class:`LogParseError` are skipped. Statistics about
    what was skipped are added in a later change.
    """
    entries = []
    with open(filepath, encoding="utf-8") as file:
        for raw in file:
            if not raw.strip():
                continue
            try:
                entries.append(parse_line(raw))
            except LogParseError:
                continue
    return entries
