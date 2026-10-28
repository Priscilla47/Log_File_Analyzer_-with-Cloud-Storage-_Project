"""``detect()``: run every detection rule over a log and return one tidy list.

Signature rules, brute-force detection and scanner detection each report what they see. This
module puts the results together: it merges signature rules that fired on the same request
into one detection, and orders everything from most to least serious.
"""

from collections.abc import Iterable
from dataclasses import replace

from loginsight.detection.behaviour import detect_brute_force, detect_scanners
from loginsight.detection.models import Detection
from loginsight.detection.ruleset import RuleSet, load_rules
from loginsight.detection.signatures import detect_signatures
from loginsight.parsing.models import LogEntry


def _merge_overlapping(detections: list[Detection]) -> list[Detection]:
    """One detection per request: the most serious, with the others named in ``also_matched``.

    ``detections`` must be in rule order within each request, which ``detect_signatures``
    guarantees. The most serious wins, and among equals the rule that comes first in the
    rules file.
    """
    by_request: dict[int, list[Detection]] = {}
    for detection in detections:
        by_request.setdefault(detection.first_index, []).append(detection)

    merged = []
    for group in by_request.values():
        best = max(group, key=lambda detection: detection.severity)  # first of equals
        others = tuple(d.rule_id for d in group if d is not best)
        merged.append(replace(best, also_matched=others) if others else best)
    return merged


def detect(entries: Iterable[LogEntry], rules: RuleSet | None = None) -> list[Detection]:
    """Find everything the rules can find in ``entries``.

    ``rules`` is a :class:`RuleSet`, or ``None`` for the default rules. The result holds:

    * one detection per request that matched a signature rule. If several rules matched the
      same request only the most serious is kept (ties go to the rule that comes first in the
      rules file) and the others are listed in its ``also_matched``;
    * the brute-force and scanner detections, which describe an address over time and are
      never merged with a signature detection, even on the same line.

    The list is ordered from the most to the least serious, then by position, then by rule
    id, so the same input always gives the same output. It is empty for no entries or when
    nothing matches. ``entries`` may be any iterable, including a generator.
    """
    if rules is None:
        rules = load_rules()
    entries = list(entries)

    found = _merge_overlapping(detect_signatures(entries, rules))
    found += detect_brute_force(entries, rules.brute_force)
    found += detect_scanners(entries, rules.scanner)
    found.sort(key=lambda detection: detection.sort_key)
    return found
