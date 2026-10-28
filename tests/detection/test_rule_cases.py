"""The guard: every rule must have cases, and every case must behave as it says.

The cases live in ``rule_cases.toml``. This file fails when someone adds a rule without cases,
renames a rule without updating its cases, or makes a pattern too broad or too narrow. Each
failure names the rule and the case, so it can be fixed without hunting.
"""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginsight.detection.models import SignatureRule
from loginsight.detection.ruleset import load_rules
from loginsight.detection.signatures import detect_signatures, normalise
from loginsight.parsing.models import LogEntry

ROOT = Path(__file__).resolve().parents[2]
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)
RULES = load_rules().signatures
BY_ID = {rule.id: rule for rule in RULES}

MIN_MATCH = 2
MIN_NO_MATCH = 3
# The cases moved here from the per-class test files, so none may be lost.
FLOOR_MATCH = 209
FLOOR_NO_MATCH = 91
ALLOWED_KEYS = {"match", "no_match"}


def check(rules, cases):
    """Everything wrong with ``rules`` and ``cases`` together, as readable sentences."""
    problems = []
    ids = [rule.id for rule in rules]
    for rule in rules:
        table = cases.get(rule.id)
        if table is None:
            problems.append(f"rule {rule.id!r} has no cases in rule_cases.toml")
            continue
        for key in table:
            if key not in ALLOWED_KEYS:
                problems.append(f"rule {rule.id!r}: unknown key {key!r} (use match / no_match)")
        match, no_match = table.get("match", []), table.get("no_match", [])
        if len(match) < MIN_MATCH:
            problems.append(
                f"rule {rule.id!r} needs at least {MIN_MATCH} match cases, has {len(match)}"
            )
        if len(no_match) < MIN_NO_MATCH:
            problems.append(
                f"rule {rule.id!r} needs at least {MIN_NO_MATCH} no_match cases, "
                f"has {len(no_match)}"
            )
        for target in match:
            if not rule.compiled.search(normalise(target)):
                problems.append(f"rule {rule.id!r} does not catch its match case {target!r}")
        for target in no_match:
            if rule.compiled.search(normalise(target)):
                problems.append(f"rule {rule.id!r} wrongly catches its no_match case {target!r}")
    for name in cases:
        if name not in ids:
            problems.append(
                f"rule_cases.toml has cases for {name!r}, which is not a rule (renamed?)"
            )
    return problems


def entry_for(target):
    path, _, query = target.partition("?")
    return LogEntry(
        ip="203.0.113.7",
        time=WHEN,
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=200,
        size=0,
        request=f"GET {target} HTTP/1.1",
    )


# --- the guard itself, on the real rules and cases ------------------------------------


def test_the_default_rules_and_their_cases_agree(rule_cases):
    problems = check(RULES, rule_cases)
    assert problems == [], "\n" + "\n".join(problems)


def test_each_rule_has_enough_cases(default_rule_id, rule_cases):
    table = rule_cases.get(default_rule_id)
    assert table is not None, f"rule {default_rule_id!r} has no cases in rule_cases.toml"
    assert len(table.get("match", [])) >= MIN_MATCH, f"{default_rule_id!r}: too few match cases"
    assert len(table.get("no_match", [])) >= MIN_NO_MATCH, (
        f"{default_rule_id!r}: too few no_match cases"
    )


def test_every_table_in_the_cases_file_is_a_real_rule(rule_cases):
    assert set(rule_cases) <= set(BY_ID), sorted(set(rule_cases) - set(BY_ID))


def test_no_case_was_lost_in_the_move_to_the_data_file(rule_cases):
    assert sum(len(t["match"]) for t in rule_cases.values()) >= FLOOR_MATCH
    assert sum(len(t["no_match"]) for t in rule_cases.values()) >= FLOOR_NO_MATCH


def test_no_case_is_listed_twice_for_a_rule(rule_cases):
    for rule_id, table in rule_cases.items():
        for key in ("match", "no_match"):
            assert len(table[key]) == len(set(table[key])), f"{rule_id!r}: duplicate {key} case"


def test_a_target_is_never_both_a_match_and_a_no_match_for_the_same_rule(rule_cases):
    for rule_id, table in rule_cases.items():
        assert not set(table["match"]) & set(table["no_match"]), rule_id


# --- every case, one test each --------------------------------------------------------


def test_a_match_case_is_caught_by_its_rule(match_case):
    rule_id, target = match_case
    assert BY_ID[rule_id].compiled.search(normalise(target)), (rule_id, target)


def test_a_match_case_is_caught_however_it_is_written(match_variant):
    rule_id, how, text = match_variant
    assert BY_ID[rule_id].compiled.search(normalise(text)), (rule_id, how, text)


def test_a_match_case_fires_through_the_whole_engine(match_case):
    rule_id, target = match_case
    found = detect_signatures([entry_for("/ok"), entry_for(target)], load_rules())
    ours = [d for d in found if d.rule_id == rule_id]
    assert len(ours) == 1
    assert ours[0].first_index == 1
    assert ours[0].label == BY_ID[rule_id].label
    assert ours[0].severity is BY_ID[rule_id].severity
    assert ours[0].evidence == f"GET {target} HTTP/1.1"[:200]


def test_a_no_match_case_is_left_alone_by_its_rule(no_match_case):
    rule_id, target = no_match_case
    assert not BY_ID[rule_id].compiled.search(normalise(target)), (rule_id, target)


def test_a_probe_hidden_in_the_query_of_another_page_fires_no_probe_rule(probe_path_case):
    _, target = probe_path_case
    text = normalise("/index.php?file=" + target)
    assert not any(rule.compiled.search(text) for rule in RULES if rule.id.startswith("probe-"))


def test_the_match_cases_are_not_copied_from_the_sample_data_generator(rule_cases):
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    used = {
        *generator._SQL_PAYLOADS,
        *generator._XSS_PAYLOADS,
        *generator._TRAVERSAL_PAYLOADS,
        *generator._COMMAND_PAYLOADS,
        *generator._SENSITIVE_PAYLOADS,
    }
    mine = {target for table in rule_cases.values() for target in table["match"]}
    assert mine.isdisjoint(used)


# --- the guard catches the mistakes it exists to catch --------------------------------


def good_cases(rule):
    """A small, valid set of cases for a made-up rule that matches the word 'attack'."""
    return {rule.id: {"match": ["/a?x=attack", "/attack"], "no_match": ["/ok", "/fine", "/home"]}}


def made_up_rule(rule_id="made-up-rule", pattern="attack"):
    return SignatureRule(
        id=rule_id,
        label="sql_injection",
        severity=RULES[0].severity,
        description="a rule made up for these tests",
        pattern=pattern,
    )


def test_the_guard_accepts_a_correct_rule_with_correct_cases():
    rule = made_up_rule()
    assert check([rule], good_cases(rule)) == []


def test_adding_a_rule_without_cases_fails_and_names_the_rule():
    rule = made_up_rule("brand-new-rule")
    problems = check([rule], {})
    assert problems == ["rule 'brand-new-rule' has no cases in rule_cases.toml"]


def new_problems(rules, cases):
    """Problems that appear only because of a change, so a broken real file adds no noise."""
    baseline = check(RULES, cases)
    return [problem for problem in check(rules, cases) if problem not in baseline]


def test_adding_a_rule_to_the_real_set_without_cases_fails(rule_cases):
    extra = made_up_rule("brand-new-rule")
    assert new_problems([*RULES, extra], rule_cases) == [
        "rule 'brand-new-rule' has no cases in rule_cases.toml"
    ]


def test_renaming_a_rule_without_updating_its_cases_fails_in_both_directions():
    old, new = made_up_rule("old-name"), made_up_rule("new-name")
    problems = check([new], good_cases(old))
    assert any("'new-name' has no cases" in p for p in problems)
    assert any("'old-name'" in p and "not a rule" in p for p in problems)
    assert len(problems) == 2


def test_renaming_a_real_rule_fails(rule_cases):
    first = RULES[0]
    renamed = [
        made_up_rule("renamed-rule", first.pattern) if r.id == first.id else r for r in RULES
    ]
    problems = new_problems(renamed, rule_cases)
    assert any("'renamed-rule' has no cases" in p for p in problems)
    assert any(f"{first.id!r}" in p and "not a rule" in p for p in problems)


def test_a_pattern_made_too_broad_fails_on_the_no_match_cases_and_names_each():
    rule = made_up_rule(pattern=".")
    problems = check([rule], good_cases(rule))
    assert len(problems) == 3
    assert all("wrongly catches its no_match case" in p for p in problems)
    assert any("'/ok'" in p for p in problems) and all("'made-up-rule'" in p for p in problems)


def test_making_a_real_pattern_match_everything_is_caught(rule_cases):
    broad = [made_up_rule(r.id, ".") if r.id == "sqli-quote-comment" else r for r in RULES]
    problems = new_problems(broad, rule_cases)
    assert len(problems) == len(rule_cases["sqli-quote-comment"]["no_match"])
    assert all("sqli-quote-comment" in p and "wrongly catches" in p for p in problems)


def test_a_pattern_made_too_narrow_fails_on_the_match_cases():
    rule = made_up_rule(pattern="(?!)")
    problems = check([rule], good_cases(rule))
    assert len(problems) == 2
    assert all("does not catch its match case" in p for p in problems)


@pytest.mark.parametrize(
    ("matches", "no_matches", "words"),
    [
        (1, 3, "at least 2 match"),
        (0, 3, "at least 2 match"),
        (2, 2, "at least 3 no_match"),
        (2, 0, "at least 3 no_match"),
    ],
)
def test_too_few_cases_fail(matches, no_matches, words):
    rule = made_up_rule()
    cases = {
        rule.id: {
            "match": ["/attack", "/b?attack"][:matches],
            "no_match": ["/ok", "/fine", "/home"][:no_matches],
        }
    }
    problems = check([rule], cases)
    assert len(problems) == 1 and words in problems[0]


def test_a_misspelt_key_is_caught_twice_as_unknown_and_as_missing():
    rule = made_up_rule()
    cases = {rule.id: {"matches": ["/attack", "/b?attack"], "no_match": ["/ok", "/fine", "/home"]}}
    problems = check([rule], cases)
    assert any("unknown key 'matches'" in p for p in problems)
    assert any("at least 2 match" in p for p in problems)


def test_a_rule_with_only_one_kind_of_case_fails():
    rule = made_up_rule()
    problems = check([rule], {rule.id: {"match": ["/attack", "/x?attack"]}})
    assert len(problems) == 1 and "no_match" in problems[0]


def test_every_problem_is_reported_not_just_the_first():
    rules = [made_up_rule("rule-one"), made_up_rule("rule-two", "(?!)"), made_up_rule("rule-three")]
    cases = {
        "rule-one": {"match": ["/attack"], "no_match": ["/ok", "/fine", "/home"]},
        "rule-two": {"match": ["/attack", "/b?attack"], "no_match": ["/ok", "/fine", "/home"]},
        "ghost-rule": {"match": [], "no_match": []},
    }
    problems = check(rules, cases)
    assert len(problems) == 5
    text = "\n".join(problems)
    assert "'rule-one' needs at least 2 match" in text
    assert "'rule-two' does not catch" in text
    assert "'rule-three' has no cases" in text
    assert "'ghost-rule'" in text
