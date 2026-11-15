r"""Tell whether a log was written by Apache or by Nginx.

The two write the same Combined layout, so the shape of a line cannot tell them apart. What
differs is how the server escapes special characters inside a quoted field: Nginx writes a
quote as ``\x22``, a backslash as ``\x5C`` and other bytes as upper-case ``\xHH``; Apache
writes ``\"``, ``\\`` and lower-case ``\xhh``. Digits-only escapes such as ``\x16`` are written
the same by both and prove nothing.

A log with no such evidence reads identically in either mode, so it is called ``apache``.
Both servers escape a backslash sent by the client, so a client cannot easily fake the
evidence: an escaped backslash is read as one unit, and what follows it is plain text.
"""

import re
from collections.abc import Iterable, Iterator
from itertools import islice

# A backslash and what follows it: another backslash, a quote, or ``x`` and two hex digits.
_ESCAPE = re.compile(r'\\(?:\\|"|x[0-9A-Fa-f]{2})')

# Looking at this many escapes is plenty, and bounds the work on a file made of backslashes.
MAX_ESCAPES_EXAMINED = 100_000


def _format_of(escapes: Iterable[str]) -> str:
    """The format the escapes (each one as found, backslash first) point to."""
    nginx = apache = 0
    for found in islice(escapes, MAX_ESCAPES_EXAMINED):
        kind = found[1:]
        if kind == "x22":
            nginx += 1
        elif kind in ("\\", '"'):
            apache += 1
        else:
            digits = kind[1:]
            if digits.isdigit():
                continue  # both servers write it the same way
            if digits.upper() == digits:
                nginx += 1
            elif digits.lower() == digits:
                apache += 1
    return "nginx" if nginx > apache else "apache"


def detect_log_format(text: str) -> str:
    """``"nginx"`` if the escapes in ``text`` are Nginx's, otherwise ``"apache"``.

    The format with more evidence wins, and a tie or no evidence gives ``"apache"``. Only the
    first :data:`MAX_ESCAPES_EXAMINED` escapes are counted.
    """
    return _format_of(found[0] for found in _ESCAPE.finditer(text))


def detect_log_format_lines(lines: Iterable[str]) -> str:
    """The same as :func:`detect_log_format` for a log given as lines, one at a time.

    An escape never spans two lines, so the answer is the one for the whole text, and the
    lines after the first :data:`MAX_ESCAPES_EXAMINED` escapes are not even read.
    """

    def escapes() -> Iterator[str]:
        for line in lines:
            for found in _ESCAPE.finditer(line):
                yield found[0]

    return _format_of(escapes())
