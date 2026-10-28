"""Tests for loading and validating the rules file."""

import re
import sys
from importlib import resources
from pathlib import Path

import pytest

from loginsight.detection.models import LABELS, Severity, SignatureRule
from loginsight.detection.ruleset import (
    MAX_PATTERN_LENGTH,
    BruteForceSettings,
    RulesError,
    RuleSet,
    ScannerSettings,
    load_rules,
    parse_rules,
)

ROOT = Path(__file__).resolve().parents[2]

GOOD_RULE = """
[[signature]]
id = "sqli-union-select"
label = "sql_injection"
severity = "high"
description = "UNION SELECT used to read other tables"
pattern = '''union\\s+select'''
"""


def rule_text(**overrides):
    """A [[signature]] table, with some keys changed. A value of None removes the key."""
    values = {
        "id": '"a-rule"',
        "label": '"xss"',
        "severity": '"medium"',
        "description": '"a test rule"',
        "pattern": "'<script'",
    }
    values.update(overrides)
    lines = [f"{key} = {value}" for key, value in values.items() if value is not None]
    return "[[signature]]\n" + "\n".join(lines) + "\n"


def problems_of(text):
    with pytest.raises(RulesError) as info:
        parse_rules(text)
    return info.value.problems


def only_problem(text):
    found = problems_of(text)
    assert len(found) == 1, found
    return found[0]


# --- a valid file ---------------------------------------------------------------------


def test_a_valid_rule_is_loaded_with_all_its_fields():
    rules = parse_rules(GOOD_RULE)
    (rule,) = rules.signatures
    assert isinstance(rule, SignatureRule)
    assert (rule.id, rule.label, rule.severity) == (
        "sqli-union-select",
        "sql_injection",
        Severity.HIGH,
    )
    assert rule.description == "UNION SELECT used to read other tables"
    assert rule.compiled.search("1 UNION   SELECT 2")


def test_rules_keep_the_order_of_the_file():
    text = "".join(rule_text(id=f'"rule-{n}"') for n in (3, 1, 2))
    assert [r.id for r in parse_rules(text).signatures] == ["rule-3", "rule-1", "rule-2"]


def test_signatures_are_a_tuple_and_the_ruleset_is_immutable():
    rules = parse_rules(rule_text())
    assert isinstance(rules.signatures, tuple)
    with pytest.raises(AttributeError):
        rules.signatures = ()  # type: ignore[misc]


def test_every_severity_name_works_in_any_case():
    for name, severity in (
        ("low", Severity.LOW),
        ("MEDIUM", Severity.MEDIUM),
        ("High", Severity.HIGH),
        ("critical", Severity.CRITICAL),
    ):
        (rule,) = parse_rules(rule_text(severity=f'"{name}"')).signatures
        assert rule.severity is severity


@pytest.mark.parametrize(
    "label", [label for label in LABELS if label not in ("brute_force", "scanner")]
)
def test_every_signature_label_is_accepted(label):
    (rule,) = parse_rules(rule_text(label=f'"{label}"')).signatures
    assert rule.label == label


def test_an_empty_file_is_valid_and_gives_default_settings():
    rules = parse_rules("")
    assert rules.signatures == ()
    assert rules.brute_force == BruteForceSettings()
    assert rules.scanner == ScannerSettings()


def test_comments_and_blank_lines_are_fine():
    text = "# the rules\n\n" + GOOD_RULE + "\n# end\n"
    assert len(parse_rules(text).signatures) == 1


def test_unicode_in_a_description_is_kept():
    (rule,) = parse_rules(rule_text(description='"détecte l\'injection 💉"')).signatures
    assert rule.description == "détecte l'injection 💉"


def test_a_pattern_in_a_literal_string_keeps_its_backslashes():
    (rule,) = parse_rules(rule_text(pattern=r"'\.\./'")).signatures
    assert rule.pattern == r"\.\./"


# --- behaviour settings ---------------------------------------------------------------


def test_the_documented_defaults():
    assert BruteForceSettings() == BruteForceSettings(
        threshold=10, window_seconds=120, login_paths=("/login", "/signin", "/wp-login.php")
    )
    scanner = ScannerSettings()
    assert (scanner.threshold, scanner.window_seconds) == (15, 60)
    assert {
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "dirbuster",
        "gobuster",
        "wfuzz",
        "nuclei",
    } <= set(scanner.user_agents)


def test_omitting_the_behaviour_tables_gives_the_defaults():
    rules = parse_rules(GOOD_RULE)
    assert rules.brute_force == BruteForceSettings()
    assert rules.scanner == ScannerSettings()


def test_a_table_can_override_only_some_fields():
    rules = parse_rules("[behaviour.brute_force]\nthreshold = 3\n")
    assert rules.brute_force.threshold == 3
    assert rules.brute_force.window_seconds == 120
    assert rules.brute_force.login_paths == BruteForceSettings().login_paths
    assert rules.scanner == ScannerSettings()


def test_all_the_behaviour_fields_can_be_set():
    rules = parse_rules(
        '[behaviour.brute_force]\nthreshold = 5\nwindow_seconds = 30\nlogin_paths = ["/auth"]\n'
        '[behaviour.scanner]\nthreshold = 8\nwindow_seconds = 10\nuser_agents = ["evilbot"]\n'
    )
    assert rules.brute_force == BruteForceSettings(
        threshold=5, window_seconds=30, login_paths=("/auth",)
    )
    assert rules.scanner == ScannerSettings(
        threshold=8, window_seconds=10, user_agents=("evilbot",)
    )


def test_settings_lists_become_tuples():
    rules = parse_rules('[behaviour.scanner]\nuser_agents = ["a", "b"]\n')
    assert rules.scanner.user_agents == ("a", "b")


def test_an_empty_user_agent_list_switches_the_tool_rule_off():
    assert parse_rules("[behaviour.scanner]\nuser_agents = []\n").scanner.user_agents == ()


def test_a_threshold_of_one_is_allowed():
    assert (
        parse_rules("[behaviour.scanner]\nthreshold = 1\nwindow_seconds = 1\n").scanner.threshold
        == 1
    )


@pytest.mark.parametrize("table", ["brute_force", "scanner"])
@pytest.mark.parametrize("field", ["threshold", "window_seconds"])
@pytest.mark.parametrize("value", ["0", "-5", "1.5", '"10"', "true", "[1]"])
def test_thresholds_and_windows_must_be_integers_of_at_least_one(table, field, value):
    message = only_problem(f"[behaviour.{table}]\n{field} = {value}\n")
    assert f"behaviour.{table}" in message and field in message


@pytest.mark.parametrize("value", ['"/login"', "[1, 2]", '["/ok", 3]', "5", "{}"])
def test_login_paths_must_be_a_list_of_strings(value):
    message = only_problem(f"[behaviour.brute_force]\nlogin_paths = {value}\n")
    assert "login_paths" in message


@pytest.mark.parametrize("value", ['""', '"login"', '" /login"'])
def test_a_login_path_must_start_with_a_slash(value):
    message = only_problem(f"[behaviour.brute_force]\nlogin_paths = [{value}]\n")
    assert "login_paths" in message and "/" in message


def test_an_empty_user_agent_string_is_rejected_because_it_would_match_everything():
    message = only_problem('[behaviour.scanner]\nuser_agents = ["sqlmap", ""]\n')
    assert "user_agents" in message and "empty" in message


@pytest.mark.parametrize("value", ["[1]", '"sqlmap"', "[true]"])
def test_user_agents_must_be_a_list_of_strings(value):
    assert "user_agents" in only_problem(f"[behaviour.scanner]\nuser_agents = {value}\n")


def test_an_unknown_behaviour_table_is_rejected():
    message = only_problem("[behaviour.brute_forse]\nthreshold = 3\n")
    assert "brute_forse" in message


def test_an_unknown_behaviour_key_is_rejected():
    message = only_problem("[behaviour.scanner]\nthreshhold = 3\n")
    assert "threshhold" in message and "behaviour.scanner" in message


def test_behaviour_must_be_a_table_and_each_entry_a_table():
    assert "behaviour" in only_problem("behaviour = 5\n")
    assert "brute_force" in only_problem("[behaviour]\nbrute_force = 5\n")


# --- signature mistakes ---------------------------------------------------------------


def test_a_typo_in_a_key_is_caught_twice_as_unknown_and_as_missing():
    found = problems_of(rule_text().replace("severity", "severty"))
    assert len(found) == 2
    assert any("'a-rule'" in p and "unknown key 'severty'" in p for p in found)
    assert any("'a-rule'" in p and "missing required key 'severity'" in p for p in found)


def test_each_required_key_must_be_present():
    for key in ("id", "label", "severity", "description", "pattern"):
        message = only_problem(rule_text(**{key: None}))
        assert f"missing required key '{key}'" in message, key


def test_a_rule_without_an_id_is_named_by_its_position():
    text = rule_text(id='"first"') + rule_text(id=None)
    assert "signature #2" in only_problem(text)


def test_duplicate_ids_are_rejected_and_the_first_user_is_named():
    text = rule_text(id='"same"') + rule_text(id='"same"')
    message = only_problem(text)
    assert "duplicate" in message and "'same'" in message and "#1" in message


@pytest.mark.parametrize(
    "rule_id", ["Upper", "has space", "under_score", "-lead", "trail-", "a--b", "é", "a/b", ""]
)
def test_ids_must_be_lower_case_letters_digits_and_single_hyphens(rule_id):
    message = only_problem(rule_text(id=f'"{rule_id}"'))
    assert "id" in message


@pytest.mark.parametrize("rule_id", ["a", "abc", "sqli-union-select", "a1", "rule-2-b", "007"])
def test_valid_ids(rule_id):
    assert parse_rules(rule_text(id=f'"{rule_id}"')).signatures[0].id == rule_id


@pytest.mark.parametrize("label", ["sqli", "SQL_INJECTION", "", "malware"])
def test_an_unknown_label_is_rejected(label):
    message = only_problem(rule_text(label=f'"{label}"'))
    assert "label" in message and "'a-rule'" in message


@pytest.mark.parametrize("label", ["brute_force", "scanner"])
def test_a_signature_rule_cannot_use_a_behavioural_label(label):
    message = only_problem(rule_text(label=f'"{label}"'))
    assert "behavioural" in message and label in message


@pytest.mark.parametrize("severity", ['"urgent"', '""', '"hi"', "3", "true"])
def test_a_bad_severity_is_rejected(severity):
    message = only_problem(rule_text(severity=severity))
    assert "severity" in message


def test_the_severity_error_lists_the_valid_names():
    message = only_problem(rule_text(severity='"urgent"'))
    assert all(name in message for name in ("low", "medium", "high", "critical"))


@pytest.mark.parametrize("pattern", ["'('", "'[a-'", "'*abc'", "'(?P<n'", "'a{2,1}'"])
def test_a_broken_regular_expression_is_rejected(pattern):
    message = only_problem(rule_text(pattern=pattern))
    assert "pattern" in message and "'a-rule'" in message


def test_an_empty_pattern_is_rejected():
    assert "empty" in only_problem(rule_text(pattern="''"))


def test_a_pattern_of_exactly_the_limit_is_accepted_and_one_more_is_not():
    assert MAX_PATTERN_LENGTH == 500
    ok = "a" * 500
    assert parse_rules(rule_text(pattern=f"'{ok}'")).signatures[0].pattern == ok
    message = only_problem(rule_text(pattern=f"'{ok}a'"))
    assert "500" in message and "pattern" in message


@pytest.mark.parametrize("key", ["id", "label", "severity", "description", "pattern"])
@pytest.mark.parametrize("value", ["5", "true", "[1]", "1.5"])
def test_every_text_field_must_be_text(key, value):
    message = only_problem(rule_text(**{key: value}))
    assert key in message


def test_an_empty_description_is_rejected():
    assert "description" in only_problem(rule_text(description='""'))


def test_signature_must_be_a_list_of_tables():
    assert "signature" in only_problem("signature = 5\n")
    assert "signature" in only_problem("[signature]\nid = 'x'\n")
    assert "signature" in only_problem("signature = [1, 2]\n")


def test_an_unknown_top_level_key_or_table_is_rejected():
    assert "rulez" in only_problem("[[rulez]]\nid = 'x'\n")
    assert "stray" in only_problem("stray = 1\n")


# --- all problems at once -------------------------------------------------------------


def test_three_different_mistakes_give_one_error_listing_all_three():
    text = (
        rule_text(id='"first"', severity='"urgent"')
        + rule_text(id='"second"', label='"nope"')
        + "[behaviour.scanner]\nthreshold = 0\n"
    )
    found = problems_of(text)
    assert len(found) == 3
    assert any("'first'" in p and "severity" in p for p in found)
    assert any("'second'" in p and "label" in p for p in found)
    assert any("behaviour.scanner" in p and "threshold" in p for p in found)


def test_several_mistakes_in_one_rule_are_all_reported():
    text = rule_text(label='"nope"', severity='"urgent"', pattern="'('")
    found = problems_of(text)
    assert len(found) == 3


def test_a_bad_rule_does_not_hide_the_problems_in_the_good_ones_after_it():
    text = rule_text(id='"bad"', label='"nope"') + rule_text(id='"worse"', severity="3")
    assert len(problems_of(text)) == 2


def test_the_error_message_lists_every_problem_and_the_source():
    with pytest.raises(RulesError) as info:
        parse_rules(rule_text(label='"nope"', severity='"urgent"'), source="my-rules.toml")
    message = str(info.value)
    assert "my-rules.toml" in message
    assert "2 problem" in message
    assert message.count("\n  - ") == 2
    assert info.value.source == "my-rules.toml"


def test_the_error_message_says_problem_in_the_singular_for_one():
    with pytest.raises(RulesError) as info:
        parse_rules(rule_text(label='"nope"'))
    assert "1 problem:" in str(info.value) and "problems" not in str(info.value)


def test_a_rules_error_is_a_value_error():
    assert issubclass(RulesError, ValueError)


# --- files ----------------------------------------------------------------------------


def test_load_rules_reads_a_file(tmp_path):
    path = tmp_path / "mine.toml"
    path.write_text(GOOD_RULE, encoding="utf-8")
    assert [r.id for r in load_rules(path).signatures] == ["sqli-union-select"]


def test_load_rules_accepts_a_string_path(tmp_path):
    path = tmp_path / "mine.toml"
    path.write_text(GOOD_RULE, encoding="utf-8")
    assert len(load_rules(str(path)).signatures) == 1


def test_a_missing_file_is_a_rules_error_that_names_it(tmp_path):
    with pytest.raises(RulesError) as info:
        load_rules(tmp_path / "missing.toml")
    assert "missing.toml" in str(info.value)
    assert "cannot read" in info.value.problems[0]


def test_a_directory_is_a_rules_error(tmp_path):
    with pytest.raises(RulesError, match="cannot read"):
        load_rules(tmp_path)


def test_invalid_toml_is_a_rules_error_with_the_line(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text('[[signature]]\nid = "ok"\nlabel = \n', encoding="utf-8")
    with pytest.raises(RulesError) as info:
        load_rules(path)
    assert "broken.toml" in str(info.value)
    assert "line 3" in str(info.value)


def test_a_file_that_is_not_utf8_is_a_rules_error(tmp_path):
    path = tmp_path / "latin.toml"
    path.write_bytes(b'# caf\xe9\n[[signature]]\nid = "x"\n')
    with pytest.raises(RulesError, match="UTF-8"):
        load_rules(path)


def test_a_file_that_starts_with_a_byte_order_mark_is_accepted(tmp_path):
    path = tmp_path / "bom.toml"
    path.write_bytes(b"\xef\xbb\xbf" + GOOD_RULE.encode())
    assert len(load_rules(path).signatures) == 1


def test_duplicate_keys_in_the_toml_are_reported_as_invalid_toml():
    assert "TOML" in only_problem('[[signature]]\nid = "a"\nid = "b"\n')


# --- the default file -----------------------------------------------------------------


def test_the_default_rules_load_and_are_not_empty():
    rules = load_rules()
    assert isinstance(rules, RuleSet)
    assert len(rules.signatures) >= 1


def test_the_default_rules_have_unique_valid_ids_and_descriptions():
    rules = load_rules()
    ids = [r.id for r in rules.signatures]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", i) for i in ids)
    assert all(r.description for r in rules.signatures)


def test_the_default_file_is_found_through_the_package_resources():
    data = resources.files("loginsight.detection").joinpath("rules", "default.toml")
    assert data.is_file()
    assert parse_rules(data.read_text(encoding="utf-8")).signatures == load_rules().signatures


def test_the_default_file_has_both_behaviour_tables_with_the_documented_values():
    text = (ROOT / "src" / "loginsight" / "detection" / "rules" / "default.toml").read_text()
    assert "[behaviour.brute_force]" in text and "[behaviour.scanner]" in text
    rules = load_rules()
    assert rules.brute_force == BruteForceSettings()
    assert rules.scanner == ScannerSettings()


def test_loading_the_default_twice_gives_equal_results():
    assert load_rules() == load_rules()


def test_the_default_file_is_declared_as_package_data():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "[tool.setuptools.package-data]" in pyproject
    assert re.search(r"rules/\*\.toml", pyproject)


# --- python versions ------------------------------------------------------------------


def test_the_toml_reader_for_python_3_10_is_a_declared_dependency():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert re.search(r'"tomli>=2\.0;\s*python_version\s*<\s*\'?"?3\.11', pyproject)


def test_the_right_toml_reader_is_in_use():
    from loginsight.detection import ruleset

    expected = "tomli" if sys.version_info < (3, 11) else "tomllib"
    assert ruleset.tomllib.__name__ == expected
