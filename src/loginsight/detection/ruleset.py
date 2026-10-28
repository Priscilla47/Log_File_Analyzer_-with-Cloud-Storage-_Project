"""Load detection rules from a TOML file and check them.

Rules are data, not code: adding a rule means adding an entry to the file. The loader is
strict, because a typo in a rule file would otherwise silently turn a rule off. Every mistake
in a file is collected and reported together in one :class:`RulesError`, each naming the rule
or table and the field, so a file can be fixed in one pass.

The default rules ship inside the package as ``rules/default.toml``.
"""

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

try:  # the standard library reads TOML from Python 3.11
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - only on Python 3.10
    import tomli as tomllib

from loginsight.detection.models import BEHAVIOURAL_LABELS, LABELS, Severity, SignatureRule

# A rule is matched against up to 2,048 characters per request, so very long patterns only
# add risk of slow matching.
MAX_PATTERN_LENGTH = 500

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SIGNATURE_KEYS = ("id", "label", "severity", "description", "pattern")
_TOP_LEVEL_KEYS = ("signature", "behaviour")
_BEHAVIOUR_TABLES = ("brute_force", "scanner")


class RulesError(ValueError):
    """A rules file could not be loaded. ``problems`` lists every mistake that was found."""

    def __init__(self, source: str, problems: list[str]):
        self.source = source
        self.problems = list(problems)
        count = len(self.problems)
        lines = "".join(f"\n  - {problem}" for problem in self.problems)
        super().__init__(f"{source}: {count} problem{'s' if count != 1 else ''}:{lines}")


@dataclass(frozen=True, slots=True, kw_only=True)
class BruteForceSettings:
    """Brute force: ``threshold`` failed logins on ``login_paths`` within ``window_seconds``."""

    threshold: int = 10
    window_seconds: int = 120
    login_paths: tuple[str, ...] = ("/login", "/signin", "/wp-login.php")


@dataclass(frozen=True, slots=True, kw_only=True)
class ScannerSettings:
    """Scanning: ``threshold`` distinct 404 paths within ``window_seconds``, or a listed tool."""

    threshold: int = 15
    window_seconds: int = 60
    user_agents: tuple[str, ...] = (
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "dirbuster",
        "gobuster",
        "wfuzz",
        "nuclei",
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleSet:
    """Everything detection needs: signature rules and the behavioural settings."""

    signatures: tuple[SignatureRule, ...] = ()
    brute_force: BruteForceSettings = field(default_factory=BruteForceSettings)
    scanner: ScannerSettings = field(default_factory=ScannerSettings)


def _describe(value) -> str:
    return repr(value) if not isinstance(value, (dict, list)) else type(value).__name__


def _unknown_keys(table: dict, allowed, owner: str, problems: list[str]) -> None:
    for key in table:
        if key not in allowed:
            problems.append(f"{owner}: unknown key {key!r} (expected: {', '.join(allowed)})")


def _build_signature(entry: dict, number: int, seen: dict, problems: list[str]):
    """One ``[[signature]]`` table to a rule, or ``None`` after recording what is wrong."""
    rule_id = entry.get("id")
    owner = (
        f"signature {rule_id!r}" if isinstance(rule_id, str) and rule_id else f"signature #{number}"
    )
    found = []  # this rule's own problems, so a bad rule is not built

    _unknown_keys(entry, _SIGNATURE_KEYS, owner, found)
    for key in _SIGNATURE_KEYS:
        if key not in entry:
            found.append(f"{owner}: missing required key {key!r}")
        elif not isinstance(entry[key], str):
            found.append(f"{owner}: {key} must be text, not {_describe(entry[key])}")
    text = {key: entry[key] for key in _SIGNATURE_KEYS if isinstance(entry.get(key), str)}

    if "id" in text:
        if not _ID.fullmatch(text["id"]):
            found.append(
                f"{owner}: id {text['id']!r} must be lower-case letters, digits and single "
                "hyphens, such as 'sqli-union-select'"
            )
        elif text["id"] in seen:
            found.append(f"{owner}: duplicate id (already used by signature #{seen[text['id']]})")
        else:
            seen[text["id"]] = number
    if "label" in text:
        if text["label"] not in LABELS:
            found.append(f"{owner}: label {text['label']!r} must be one of: {', '.join(LABELS)}")
        elif text["label"] in BEHAVIOURAL_LABELS:
            found.append(
                f"{owner}: label {text['label']!r} is behavioural, so it is set up under "
                "[behaviour.*], not as a signature"
            )
    severity = None
    if "severity" in text:
        try:
            severity = Severity.from_name(text["severity"])
        except ValueError as error:
            found.append(f"{owner}: severity: {error}")
    if "description" in text and not text["description"].strip():
        found.append(f"{owner}: description must not be empty")
    if "pattern" in text:
        pattern = text["pattern"]
        if not pattern:
            found.append(f"{owner}: pattern is empty, so it would match every request")
        elif len(pattern) > MAX_PATTERN_LENGTH:
            found.append(
                f"{owner}: pattern is {len(pattern)} characters long, "
                f"the limit is {MAX_PATTERN_LENGTH}"
            )
        else:
            try:
                re.compile(pattern)
            except re.error as error:
                found.append(f"{owner}: pattern is not a valid regular expression: {error}")

    problems.extend(found)
    if found:
        return None
    return SignatureRule(
        id=text["id"],
        label=text["label"],
        severity=severity,
        description=text["description"],
        pattern=text["pattern"],
    )


def _count(table: dict, key: str, owner: str, problems: list[str]):
    """An integer of at least 1, or ``None`` if the key is absent or wrong."""
    if key not in table:
        return None
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        problems.append(
            f"{owner}: {key} must be a whole number of at least 1, not {_describe(value)}"
        )
        return None
    return value


def _strings(table: dict, key: str, owner: str, problems: list[str], *, slash: bool):
    """A list of non-empty strings as a tuple, or ``None`` if the key is absent or wrong."""
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        problems.append(f"{owner}: {key} must be a list of text values, not {_describe(value)}")
        return None
    bad = False
    for item in value:
        if slash and not item.startswith("/"):  # also catches an empty text
            problems.append(f"{owner}: {key} entry {item!r} must start with '/'")
            bad = True
        elif not item:
            problems.append(
                f"{owner}: {key} must not contain an empty text (it would match everything)"
            )
            bad = True
    return None if bad else tuple(value)


def _build_behaviour(data, problems: list[str]) -> tuple[BruteForceSettings, ScannerSettings]:
    brute_force, scanner = BruteForceSettings(), ScannerSettings()
    if data is None:
        return brute_force, scanner
    if not isinstance(data, dict):
        problems.append(f"behaviour must be a table, not {_describe(data)}")
        return brute_force, scanner
    for name in data:
        if name not in _BEHAVIOUR_TABLES:
            problems.append(
                f"behaviour: unknown table {name!r} (expected: {', '.join(_BEHAVIOUR_TABLES)})"
            )
    for name in _BEHAVIOUR_TABLES:
        if name not in data:
            continue
        table, owner = data[name], f"behaviour.{name}"
        if not isinstance(table, dict):
            problems.append(f"{owner} must be a table, not {_describe(table)}")
            continue
        if name == "brute_force":
            _unknown_keys(table, ("threshold", "window_seconds", "login_paths"), owner, problems)
            values = {
                "threshold": _count(table, "threshold", owner, problems),
                "window_seconds": _count(table, "window_seconds", owner, problems),
                "login_paths": _strings(table, "login_paths", owner, problems, slash=True),
            }
            kept = {key: value for key, value in values.items() if value is not None}
            brute_force = BruteForceSettings(**kept)
        else:
            _unknown_keys(table, ("threshold", "window_seconds", "user_agents"), owner, problems)
            values = {
                "threshold": _count(table, "threshold", owner, problems),
                "window_seconds": _count(table, "window_seconds", owner, problems),
                "user_agents": _strings(table, "user_agents", owner, problems, slash=False),
            }
            kept = {key: value for key, value in values.items() if value is not None}
            scanner = ScannerSettings(**kept)
    return brute_force, scanner


def parse_rules(text: str, source: str = "<string>") -> RuleSet:
    """Read rules from TOML ``text``. ``source`` is the name used in error messages."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise RulesError(source, [f"not valid TOML: {error}"]) from None

    problems: list[str] = []
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            problems.append(
                f"unknown key or table {key!r} (expected: {', '.join(_TOP_LEVEL_KEYS)})"
            )

    signatures = []
    entries = data.get("signature", [])
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        problems.append("signature must be a list of [[signature]] tables")
    else:
        seen: dict[str, int] = {}
        for number, entry in enumerate(entries, start=1):
            rule = _build_signature(entry, number, seen, problems)
            if rule is not None:
                signatures.append(rule)

    brute_force, scanner = _build_behaviour(data.get("behaviour"), problems)
    if problems:
        raise RulesError(source, problems)
    return RuleSet(signatures=tuple(signatures), brute_force=brute_force, scanner=scanner)


def load_rules(path: str | Path | None = None) -> RuleSet:
    """Load the rules in ``path``, or the default rules shipped with the package.

    Raises :class:`RulesError` for a file that cannot be read, is not valid TOML, or holds
    any invalid rule.
    """
    if path is None:
        resource = resources.files("loginsight.detection").joinpath("rules", "default.toml")
        return parse_rules(resource.read_text(encoding="utf-8"), source="the default rules")

    source = str(path)
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise RulesError(source, ["cannot read the file: it is not valid UTF-8 text"]) from None
    except OSError as error:
        raise RulesError(source, [f"cannot read the file: {error.strerror}"]) from None
    return parse_rules(text, source=source)
