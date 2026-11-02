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

# A backslash and what follows it: another backslash, a quote, or ``x`` and two hex digits.
_ESCAPE = re.compile(r'\\(?:\\|"|x[0-9A-Fa-f]{2})')

# Looking at this many escapes is plenty, and bounds the work on a file made of backslashes.
MAX_ESCAPES_EXAMINED = 100_000


def detect_log_format(text: str) -> str:
    """``"nginx"`` if the escapes in ``text`` are Nginx's, otherwise ``"apache"``.

    The format with more evidence wins, and a tie or no evidence gives ``"apache"``. Only the
    first :data:`MAX_ESCAPES_EXAMINED` escapes are counted.
    """
    nginx = apache = 0
    for number, found in enumerate(_ESCAPE.finditer(text)):
        if number >= MAX_ESCAPES_EXAMINED:
            break
        kind = found[0][1:]
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
