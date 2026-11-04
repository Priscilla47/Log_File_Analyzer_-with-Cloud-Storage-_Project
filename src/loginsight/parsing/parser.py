"""Tolerant parser for Common and Combined access-log lines.

Real logs are messy and attackers send odd requests on purpose, so a line the parser can
place in time is kept even when its request line is malformed. Lines that cannot be read
raise :class:`LogParseError` with a ``reason`` saying why.

Apache and Nginx write the same Combined layout, so one pattern reads both. They differ in how
they write special characters inside a quoted field: Apache logs a quote as ``\\"`` and a
backslash as ``\\\\``, Nginx logs ``\\x22``, ``\\x5C`` and every control or non-ASCII byte as an
upper-case ``\\xHH``. With ``log_format="nginx"`` those escapes are decoded; the ``apache`` mode
leaves the text as logged.

Fields a server appends after the user agent are ignored. A Common-format line with extra
fields, a virtual-host prefix, or a client name containing a space is not recognised and is
reported as ``no_match``.
"""

import io
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from loginsight.parsing.models import LogEntry, ParseIssue, ParseResult, ParseStats

LOG_FORMATS = ("apache", "nginx")

# Nginx writes bytes it cannot show as a backslash, x and two upper-case hex digits.
_NGINX_ESCAPES = re.compile(r"(?:\\x[0-9A-F]{2})+")

# Longer lines are rejected before matching, which bounds the work done per line.
MAX_LINE_LENGTH = 8192

# A size with more digits than this cannot be a byte count (19 digits still fit a signed 64-bit
# integer), and Python refuses to convert a string of more than 4300 digits at all.
MAX_SIZE_DIGITS = 19

# Parse statistics keep only the first few problems, each with a shortened copy of the line.
MAX_FIRST_ERRORS = 10
MAX_ERROR_LINE_LENGTH = 200

_QUOTED = r'(?:[^"\\]|\\.)*'  # text inside quotes, allowing backslash-escaped characters

_LINE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]*)\] "
    rf'"(?P<request>{_QUOTED})" '
    r"(?P<status>[0-9]{3}) (?P<size>\S+)"
    # Combined format. Servers often append fields after the user agent (a request time, the
    # forwarded-for address, ...), so anything after the user agent is accepted and ignored.
    rf'(?: "(?P<referer>{_QUOTED})" "(?P<user_agent>{_QUOTED})"(?:\s.*)?)?'
    r"\s*"
)

_METHOD = re.compile(r"[A-Za-z]+")


class LogParseError(ValueError):
    """A log line could not be parsed.

    ``reason`` is one of ``no_match``, ``bad_timestamp``, ``bad_size`` or ``line_too_long``.
    """

    def __init__(self, reason: str, line: str = "") -> None:
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
    if text.isascii() and text.isdigit() and len(text) <= MAX_SIZE_DIGITS:
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


def _check_format(log_format: str) -> None:
    if log_format not in LOG_FORMATS:
        raise ValueError(
            f"unknown log format {log_format!r}; expected one of: {', '.join(LOG_FORMATS)}"
        )


def _unescape_nginx(text: str) -> str:
    """Decode Nginx's ``\\xHH`` escapes. Runs of them are read as UTF-8 bytes, so ``\\xC3\\xA9``
    is one character; bytes that are not valid UTF-8 become the replacement character."""
    if "\\x" not in text:
        return text
    return _NGINX_ESCAPES.sub(
        lambda found: bytes.fromhex(found[0].replace("\\x", "")).decode("utf-8", "replace"), text
    )


def parse_line(line: str, log_format: str = "apache") -> LogEntry:
    """Parse one Common or Combined format line into a :class:`LogEntry`.

    ``log_format`` is ``"apache"`` or ``"nginx"`` (see the module notes). Raises
    :class:`LogParseError` if the line cannot be read and :class:`ValueError` for an unknown
    format.
    """
    _check_format(log_format)
    line = line.rstrip("\r\n")
    if len(line) > MAX_LINE_LENGTH:
        raise LogParseError("line_too_long", line)

    match = _LINE.fullmatch(line)
    if match is None:
        raise LogParseError("no_match", line)

    time = _parse_time(match["time"], line)
    size = _parse_size(match["size"], line)
    request = match["request"]
    referer = match["referer"]
    user_agent = match["user_agent"]
    if log_format == "nginx":
        request = _unescape_nginx(request)
        referer = None if referer is None else _unescape_nginx(referer)
        user_agent = None if user_agent is None else _unescape_nginx(user_agent)
    method, path, query, protocol = _split_request(request)

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


def _parse_lines(lines: Iterable[str], log_format: str) -> ParseResult:
    entries: list[LogEntry] = []
    skipped_by_reason: dict[str, int] = {}
    first_errors: list[ParseIssue] = []
    total_lines = 0

    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        total_lines += 1
        try:
            entries.append(parse_line(raw, log_format))
        except LogParseError as error:
            skipped_by_reason[error.reason] = skipped_by_reason.get(error.reason, 0) + 1
            if len(first_errors) < MAX_FIRST_ERRORS:
                text = raw.rstrip("\r\n")[:MAX_ERROR_LINE_LENGTH]
                first_errors.append(ParseIssue(line_number, error.reason, text))

    skipped = sum(skipped_by_reason.values())
    stats = ParseStats(
        total_lines=total_lines,
        parsed=len(entries),
        skipped=skipped,
        skipped_by_reason=skipped_by_reason,
        first_errors=first_errors,
    )
    return ParseResult(entries=entries, stats=stats)


def parse_text(text: str, log_format: str = "apache") -> ParseResult:
    """Parse the text of a log and report what was read and what was skipped.

    Lines end at ``\\n``, ``\\r\\n`` or ``\\r``, exactly as when a file is read. Blank lines are
    ignored but still count towards line numbers; a line that raises :class:`LogParseError` is
    skipped and counted in the statistics.
    """
    _check_format(log_format)
    return _parse_lines(io.StringIO(text, newline=None), log_format)


def parse_file(filepath: str | Path, log_format: str = "apache") -> ParseResult:
    """Parse a log file and report what was read and what was skipped.

    The rules are those of :func:`parse_text`. The file is read as UTF-8: a leading byte order
    mark is dropped and invalid bytes are replaced, so neither stops the parse. A missing file
    or a directory raises the usual :class:`OSError` subclass.
    """
    _check_format(log_format)
    with open(filepath, encoding="utf-8-sig", errors="replace") as file:
        return _parse_lines(file, log_format)
