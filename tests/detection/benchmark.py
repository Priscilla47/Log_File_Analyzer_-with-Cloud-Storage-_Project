"""Scoring helpers for the detection benchmark.

The generator writes a log and says exactly which lines are attacks. These helpers compare
what ``detect()`` found with that ground truth and turn it into recall and precision for each
of the seven attack classes. They are plain functions so the benchmark test can also use them
to prove the benchmark itself works (a weakened rule must lower recall, a widened one must
lower precision).

How a class is scored
---------------------
*Signature classes* are scored per line. A line is *found* for class C when some detection on
that line has label C, either as the kept detection or among its ``also_matched`` rules (when
several rules fire on one request only the most serious is kept, so the others would
otherwise be invisible).

*Behavioural classes* (brute force, scanner) are scored per burst. The labelled lines of a
class are grouped by address, and a burst is *found* when a detection of that class and
address overlaps its lines.

For both kinds, a detection of class C is
  * a **true positive** when it sits on a labelled line (or burst) of class C;
  * a **false positive** when it sits on a line, or comes from an address, that has no label
    at all, i.e. it accused a normal visitor;
  * **cross-class** otherwise: it is on an attack of a different class. Attacks overlap (a
    scanner requests ``/phpmyadmin``, and the generator gives attackers tool-like user agents
    at random), so these are reported but not held against precision.
"""

from collections import defaultdict
from dataclasses import dataclass

from loginsight.detection.models import BEHAVIOURAL_LABELS, LABELS, Detection


@dataclass(frozen=True)
class ClassScore:
    """Counts for one attack class. ``labelled`` is lines (signature) or bursts (behavioural)."""

    label: str
    labelled: int = 0
    found: int = 0
    true_positives: int = 0
    false_positives: int = 0
    cross_class: int = 0

    @property
    def recall(self) -> float:
        return self.found / self.labelled if self.labelled else 1.0

    @property
    def precision(self) -> float:
        reported = self.true_positives + self.false_positives
        return self.true_positives / reported if reported else 1.0

    def __add__(self, other: "ClassScore") -> "ClassScore":
        assert self.label == other.label
        return ClassScore(
            self.label,
            self.labelled + other.labelled,
            self.found + other.found,
            self.true_positives + other.true_positives,
            self.false_positives + other.false_positives,
            self.cross_class + other.cross_class,
        )


def _is_behavioural(detection: Detection) -> bool:
    return detection.rule_id.startswith("behaviour-")


def score(labels: list[dict], detections: list[Detection], rules) -> dict[str, ClassScore]:
    """Score ``detections`` against the generator's ``labels`` for every class.

    ``labels`` are the generator's objects (``line`` from 1, ``label``, ``kind``, ``ip``) and
    ``rules`` is the ``RuleSet`` that produced the detections (to learn the class of each rule
    named in an ``also_matched``).
    """
    rule_label = {rule.id: rule.label for rule in rules.signatures}
    labelled_lines = {item["line"] - 1: item for item in labels}
    labelled_ips = {item["ip"] for item in labels}

    # Signature detections: the classes seen on each line, kept detection and merged rules.
    classes_at: dict[int, set[str]] = defaultdict(set)
    for detection in detections:
        if _is_behavioural(detection):
            continue
        classes_at[detection.first_index].add(detection.label)
        classes_at[detection.first_index].update(
            rule_label[rule_id] for rule_id in detection.also_matched if rule_id in rule_label
        )

    result = {}
    for label in LABELS:
        if label in BEHAVIOURAL_LABELS:
            result[label] = _score_behavioural(label, labels, detections, labelled_ips)
        else:
            result[label] = _score_signature(label, labelled_lines, classes_at)
    return result


def _score_signature(label: str, labelled_lines: dict, classes_at: dict) -> ClassScore:
    wanted = {line for line, item in labelled_lines.items() if item["label"] == label}
    found = sum(1 for line in wanted if label in classes_at.get(line, ()))
    true_positives = false_positives = cross = 0
    for line, classes in classes_at.items():
        if label not in classes:
            continue
        if line in wanted:
            true_positives += 1
        elif line in labelled_lines:
            cross += 1
        else:
            false_positives += 1
    return ClassScore(label, len(wanted), found, true_positives, false_positives, cross)


def _score_behavioural(label: str, labels: list[dict], detections, labelled_ips) -> ClassScore:
    bursts: dict[str, set[int]] = defaultdict(set)  # address -> labelled lines of this class
    for item in labels:
        if item["label"] == label:
            bursts[item["ip"]].add(item["line"] - 1)

    def overlaps(detection: Detection) -> bool:
        lines = bursts.get(detection.ip, ())
        return any(detection.first_index <= line <= detection.last_index for line in lines)

    mine = [d for d in detections if _is_behavioural(d) and d.label == label]
    found_ips = {d.ip for d in mine if overlaps(d)}
    true_positives = sum(1 for d in mine if overlaps(d))
    false_positives = sum(1 for d in mine if d.ip not in labelled_ips)
    cross = len(mine) - true_positives - false_positives
    return ClassScore(label, len(bursts), len(found_ips), true_positives, false_positives, cross)


def pool(scores: list[dict[str, ClassScore]]) -> dict[str, ClassScore]:
    """Add up the scores of several logs, class by class (counts first, then ratios)."""
    total = {label: ClassScore(label) for label in LABELS}
    for one in scores:
        for label, value in one.items():
            total[label] = total[label] + value
    return total


def format_table(scores: dict[str, ClassScore]) -> str:
    """The scores as a text table, for ``pytest -s``."""
    columns = ("class", "labelled", "found", "recall", "precision", "false+", "cross-class")
    head = f"{columns[0]:22s} " + " ".join(f"{name:>{max(len(name), 6)}s}" for name in columns[1:])
    rows = [head, "-" * len(head)]
    for label in LABELS:
        s = scores[label]
        rows.append(
            f"{label:22s} {s.labelled:>8d} {s.found:>6d} {s.recall:>6.3f} {s.precision:>9.3f} "
            f"{s.false_positives:>6d} {s.cross_class:>11d}"
        )
    return "\n".join(rows)
