"""Signature detection: match each request against the rules, after undoing the disguises.

Attackers hide patterns with URL encoding, so a rule is not matched against the request as
logged but against a normalised version of its path and query string (see :func:`normalise`).
Only the path and query are looked at, never the user agent or the referer.

Limits worth knowing:

* Only the first :data:`MAX_TARGET_LENGTH` characters of a request are examined, which bounds
  the work done per line. An attack that starts after that point is not seen.
* Up to :data:`MAX_DECODE_PASSES` layers of percent-encoding are removed. Older tricks such as
  overlong UTF-8 (``%c0%ae`` for a dot) and IIS-style ``%u0041`` are not decoded.
* Patterns are ordinary regular expressions, which can be slow on hostile input if written
  with nested repeats such as ``(a+)+``. Keep rule patterns simple.
"""

import re
from collections.abc import Iterable
from urllib.parse import unquote

from loginsight.detection.models import Detection, SignatureRule, shorten_evidence
from loginsight.detection.ruleset import RuleSet
from loginsight.parsing.models import LogEntry

# Longer requests are cut before anything else is done to them.
MAX_TARGET_LENGTH = 2048
# Encoded text is decoded again up to this many times, so %252e (a dot encoded twice) is found.
MAX_DECODE_PASSES = 3

_WHITESPACE = re.compile(r"\s+")


def normalise(target: str) -> str:
    """The text the rules are matched against.

    In order: cut to :data:`MAX_TARGET_LENGTH` characters; remove up to
    :data:`MAX_DECODE_PASSES` layers of percent-encoding (an invalid escape such as ``%zz``
    is left as it is, and bytes that are not valid UTF-8 become replacement characters);
    turn ``+`` into a space; remove NUL characters; collapse each run of whitespace into one
    space; lower-case everything.
    """
    text = target[:MAX_TARGET_LENGTH]
    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote(text, errors="replace")
        if decoded == text:
            break
        text = decoded
    text = text.replace("+", " ").replace("\x00", "")
    return _WHITESPACE.sub(" ", text).lower()


def detect_signatures(
    entries: Iterable[LogEntry], rules: RuleSet | Iterable[SignatureRule]
) -> list[Detection]:
    """One :class:`Detection` for every rule that matches a request.

    ``rules`` is a :class:`RuleSet` or any iterable of :class:`SignatureRule`. The result is
    in entry order and then rule order, so it is the same every time. Several rules can match
    one request, and each gives its own detection; removing the overlap is left to the caller.
    """
    signatures = rules.signatures if isinstance(rules, RuleSet) else tuple(rules)
    found = []
    for index, entry in enumerate(entries):
        text = normalise(entry.target)
        for rule in signatures:
            if rule.compiled.search(text):
                found.append(
                    Detection(
                        rule_id=rule.id,
                        label=rule.label,
                        severity=rule.severity,
                        ip=entry.ip,
                        time=entry.time,
                        first_index=index,
                        last_index=index,
                        count=1,
                        evidence=shorten_evidence(entry.request),
                    )
                )
    return found
