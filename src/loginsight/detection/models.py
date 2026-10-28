"""The data types detection is built on: severities, detections and signature rules.

Everything here is a plain immutable value with no file or network access, so the rules, the
reports and the interfaces can all share the same definitions.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

# The attack classes. They are spelled exactly like the labels in the sample data generator,
# which is what lets detections be scored against the ground truth.
SIGNATURE_LABELS = (
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
    "sensitive_file_probe",
)
BEHAVIOURAL_LABELS = ("brute_force", "scanner")
LABELS = SIGNATURE_LABELS + BEHAVIOURAL_LABELS

# Evidence quoted from a log line is cut to this many characters.
MAX_EVIDENCE_LENGTH = 200


class Severity(IntEnum):
    """How serious a detection is. Members compare and sort: ``HIGH > MEDIUM``."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """The severity called ``name``, ignoring case. Raises :class:`ValueError` otherwise."""
        member = cls.__members__.get(name.upper()) if isinstance(name, str) else None
        if member is not None:
            return member
        valid = ", ".join(str(member) for member in cls)
        raise ValueError(f"unknown severity {name!r}; expected one of: {valid}")


def shorten_evidence(text: str) -> str:
    """``text`` cut to :data:`MAX_EVIDENCE_LENGTH` characters."""
    return text[:MAX_EVIDENCE_LENGTH]


def _check_label(label, owner: str) -> None:
    if label not in LABELS:
        raise ValueError(f"{owner}: unknown label {label!r}; expected one of: {', '.join(LABELS)}")


def _check_severity(severity, owner: str) -> None:
    if not isinstance(severity, Severity):
        raise TypeError(f"{owner}: severity must be a Severity, not {severity!r}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Detection:
    """One finding: what was detected, how serious it is, who did it, and the evidence.

    ``first_index`` and ``last_index`` are 0-based positions in the list of entries that was
    analysed (both included), and ``count`` is how many of those lines are involved: 1 for a
    single request, more for a burst of lines from one address. ``time`` is the time of the
    first line. ``also_matched`` holds the ids of other rules that fired on the same line.
    """

    rule_id: str
    label: str
    severity: Severity
    ip: str
    time: datetime
    first_index: int
    last_index: int
    count: int
    evidence: str
    also_matched: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError(f"rule_id must be a non-empty string, not {self.rule_id!r}")
        owner = f"detection {self.rule_id!r}"
        _check_label(self.label, owner)
        _check_severity(self.severity, owner)
        if self.first_index < 0:
            raise ValueError(f"{owner}: index must not be negative, got {self.first_index}")
        if self.first_index > self.last_index:
            raise ValueError(
                f"{owner}: first_index {self.first_index} is after last_index {self.last_index}"
            )
        if self.count < 1:
            raise ValueError(f"{owner}: count must be at least 1, got {self.count}")
        span = self.last_index - self.first_index + 1
        if self.count > span:
            raise ValueError(f"{owner}: count {self.count} does not fit in {span} line(s)")
        if not isinstance(self.also_matched, tuple) or not all(
            isinstance(rule_id, str) for rule_id in self.also_matched
        ):
            raise TypeError(f"{owner}: also_matched must be a tuple of rule ids")
        if self.rule_id in self.also_matched:
            raise ValueError(f"{owner}: also_matched must not list the rule itself")

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Orders detections by severity (highest first), then position, then rule id."""
        return (-int(self.severity), self.first_index, self.rule_id)

    def to_dict(self) -> dict:
        """A JSON-safe dict: the severity as its name and the time as ISO 8601 text."""
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "severity": str(self.severity),
            "ip": self.ip,
            "time": self.time.isoformat(),
            "first_index": self.first_index,
            "last_index": self.last_index,
            "count": self.count,
            "evidence": self.evidence,
            "also_matched": list(self.also_matched),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SignatureRule:
    """A rule that flags a request whose path and query match a regular expression.

    The pattern is compiled, ignoring case, when the rule is created, so a broken pattern
    fails at once with an error naming the rule instead of failing later in the middle of an
    analysis.
    """

    id: str
    label: str
    severity: Severity
    description: str
    pattern: str
    compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError(f"a rule needs a non-empty id, not {self.id!r}")
        owner = f"rule {self.id!r}"
        _check_label(self.label, owner)
        _check_severity(self.severity, owner)
        if not self.pattern:
            raise ValueError(f"{owner}: the pattern is empty, so it would match every request")
        try:
            compiled = re.compile(self.pattern, re.IGNORECASE)
        except re.error as error:
            raise ValueError(f"{owner}: invalid pattern {self.pattern!r}: {error}") from None
        object.__setattr__(self, "compiled", compiled)
