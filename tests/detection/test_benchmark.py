"""The detection benchmark: how well do the rules find the generator's labelled attacks?

Run with ``pytest -s tests/detection/test_benchmark.py`` to see the table of scores. The scoring
helpers are in ``benchmark.py`` next to this file, and are tested here too, so the benchmark
itself can be trusted: a weakened rule must lower recall, a widened one must lower precision.
"""

import importlib.util
import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginsight.detection import Detection, Severity, SignatureRule, detect, load_rules
from loginsight.detection.models import LABELS
from loginsight.detection.ruleset import BruteForceSettings, ScannerSettings
from loginsight.parsing.parser import parse_file, parse_line

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FLOOR = 0.95

_spec = importlib.util.spec_from_file_location("detection_benchmark", HERE / "benchmark.py")
bench = importlib.util.module_from_spec(_spec)
sys.modules["detection_benchmark"] = bench
_spec.loader.exec_module(bench)

RULES = load_rules()
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generated(generator, seed, lines, ratio):
    log, labels = generator.generate(seed=seed, lines=lines, attack_ratio=ratio)
    return [parse_line(line) for line in log], labels


@pytest.fixture(scope="module")
def benchmark_logs(generator):
    """The five benchmark logs: seeds 1 to 5, 3,000 lines, a tenth of them attacks."""
    return [generated(generator, seed, 3000, 0.1) for seed in range(1, 6)]


@pytest.fixture(scope="module")
def clean_logs(generator):
    """Twenty attack-free logs of 2,000 lines each."""
    return [generated(generator, 100 + seed, 2000, 0.0)[0] for seed in range(20)]


def pooled(logs, rules=RULES):
    return bench.pool(
        [bench.score(labels, detect(entries, rules), rules) for entries, labels in logs]
    )


def below_floor(scores):
    return {
        label: (round(s.recall, 3), round(s.precision, 3))
        for label, s in scores.items()
        if s.recall < FLOOR or s.precision < FLOOR
    }


def without(rules, *prefixes):
    keep = tuple(r for r in rules.signatures if not r.id.startswith(prefixes))
    return replace(rules, signatures=keep)


def with_rule(rules, rule_id, pattern, label):
    extra = SignatureRule(
        id=rule_id, label=label, severity=Severity.LOW, description="a naive rule", pattern=pattern
    )
    return replace(rules, signatures=(*rules.signatures, extra))


# --- the scoring helpers, on tiny hand-made data --------------------------------------


def label(line, name, ip="198.51.100.1", kind=None):
    kind = kind or ("behavioural" if name in ("brute_force", "scanner") else "signature")
    return {"line": line, "label": name, "kind": kind, "ip": ip}


def finding(index, class_name, rule_id="a-rule", ip="198.51.100.1", also=(), last=None, count=1):
    return Detection(
        rule_id=rule_id,
        label=class_name,
        severity=Severity.HIGH,
        ip=ip,
        time=WHEN,
        first_index=index,
        last_index=index if last is None else last,
        count=count,
        evidence="e",
        also_matched=tuple(also),
    )


def scored(labels, detections):
    return bench.score(labels, detections, RULES)


def test_a_perfect_run_scores_one_for_every_class_it_has_something_to_find():
    labels = [label(1, "sql_injection"), label(2, "sql_injection"), label(3, "xss")]
    found = [finding(0, "sql_injection"), finding(1, "sql_injection"), finding(2, "xss")]
    s = scored(labels, found)
    assert (s["sql_injection"].labelled, s["sql_injection"].found) == (2, 2)
    assert (s["sql_injection"].recall, s["sql_injection"].precision) == (1.0, 1.0)
    assert (s["xss"].recall, s["xss"].precision) == (1.0, 1.0)


def test_a_missed_line_lowers_recall_and_not_precision():
    labels = [label(n, "sql_injection") for n in range(1, 5)]
    s = scored(
        labels,
        [finding(0, "sql_injection"), finding(1, "sql_injection"), finding(2, "sql_injection")],
    )
    assert s["sql_injection"].recall == pytest.approx(0.75)
    assert s["sql_injection"].precision == 1.0


def test_a_detection_on_a_line_with_no_label_is_a_false_positive():
    s = scored([label(1, "xss")], [finding(0, "xss"), finding(7, "xss")])
    assert s["xss"].false_positives == 1
    assert s["xss"].true_positives == 1
    assert s["xss"].precision == pytest.approx(0.5)
    assert s["xss"].recall == 1.0


def test_a_detection_on_a_line_of_another_class_is_cross_class_not_a_false_positive():
    labels = [label(1, "xss"), label(2, "sql_injection")]
    s = scored(labels, [finding(0, "xss"), finding(1, "xss")])  # the second sits on the SQL line
    assert s["xss"].cross_class == 1
    assert s["xss"].false_positives == 0
    assert s["xss"].precision == 1.0
    assert s["sql_injection"].recall == 0.0  # the SQL line was not found as SQL


def test_a_rule_merged_into_another_detection_still_counts_for_its_own_class():
    labels = [label(1, "sql_injection")]
    # The kept detection is the XSS one, and the SQL rule that also fired is in also_matched.
    merged = finding(0, "xss", also=("sqli-union-select",))
    s = scored(labels, [merged])
    assert s["sql_injection"].found == 1 and s["sql_injection"].recall == 1.0
    assert s["sql_injection"].true_positives == 1
    assert s["xss"].cross_class == 1 and s["xss"].false_positives == 0


def test_an_unknown_rule_in_also_matched_is_ignored():
    s = scored([label(1, "xss")], [finding(0, "xss", also=("no-such-rule",))])
    assert s["xss"].recall == 1.0


def test_a_behavioural_burst_is_found_when_a_detection_of_its_class_and_address_overlaps_it():
    labels = [label(n, "brute_force", ip="198.51.100.9", kind="behavioural") for n in (5, 6, 7, 8)]
    hit = finding(
        4, "brute_force", rule_id="behaviour-brute-force", ip="198.51.100.9", last=7, count=4
    )
    s = scored(labels, [hit])["brute_force"]
    assert (s.labelled, s.found, s.true_positives) == (1, 1, 1)
    assert (s.recall, s.precision) == (1.0, 1.0)


def test_a_detection_from_the_wrong_address_does_not_find_the_burst():
    labels = [label(n, "brute_force", ip="198.51.100.9") for n in (5, 6, 7, 8)]
    other = finding(
        4, "brute_force", rule_id="behaviour-brute-force", ip="198.51.100.77", last=7, count=4
    )
    s = scored(labels, [other])["brute_force"]
    assert s.found == 0 and s.recall == 0.0
    assert s.false_positives == 1 and s.precision == 0.0  # that address has no label at all


def test_a_detection_that_misses_the_labelled_lines_is_cross_class():
    labels = [label(n, "brute_force", ip="198.51.100.9") for n in (50, 51)]
    elsewhere = finding(
        0, "brute_force", rule_id="behaviour-brute-force", ip="198.51.100.9", last=3, count=2
    )
    s = scored(labels, [elsewhere])["brute_force"]
    assert (s.found, s.true_positives, s.false_positives, s.cross_class) == (0, 0, 0, 1)


def test_a_scanner_tool_on_a_brute_force_address_is_cross_class_for_the_scanner():
    labels = [label(n, "brute_force", ip="198.51.100.9") for n in (5, 6)]
    tool = finding(
        5, "scanner", rule_id="behaviour-scanner-tool", ip="198.51.100.9", last=6, count=2
    )
    s = scored(labels, [tool])
    assert s["scanner"].cross_class == 1 and s["scanner"].false_positives == 0
    assert s["scanner"].labelled == 0 and s["scanner"].recall == 1.0
    assert s["brute_force"].found == 0


def test_a_scanner_tool_on_an_address_with_no_label_at_all_is_a_false_positive():
    tool = finding(0, "scanner", rule_id="behaviour-scanner-tool", ip="203.0.113.50")
    s = scored([label(1, "xss", ip="198.51.100.1")], [tool])["scanner"]
    assert s.false_positives == 1 and s.precision == 0.0


def test_two_bursts_from_different_addresses_are_two_bursts():
    labels = [label(1, "scanner", ip="198.51.100.1"), label(2, "scanner", ip="198.51.100.2")]
    one = finding(0, "scanner", rule_id="behaviour-scanner-burst", ip="198.51.100.1")
    s = scored(labels, [one])["scanner"]
    assert (s.labelled, s.found, s.recall) == (2, 1, 0.5)


def test_a_behavioural_detection_is_never_counted_as_a_signature_detection():
    labels = [label(1, "sql_injection")]
    burst = finding(0, "scanner", rule_id="behaviour-scanner-burst")
    assert scored(labels, [burst])["sql_injection"].found == 0


def test_nothing_labelled_and_nothing_found_scores_one_everywhere():
    s = scored([], [])
    assert set(s) == set(LABELS)
    assert all(v.labelled == 0 and v.recall == 1.0 and v.precision == 1.0 for v in s.values())


def test_a_class_with_no_detections_has_a_precision_of_one_and_a_recall_of_zero():
    s = scored([label(1, "xss")], [])["xss"]
    assert (s.recall, s.precision) == (0.0, 1.0)


def test_pooling_adds_the_counts_before_dividing():
    first = scored(
        [label(n, "xss") for n in range(1, 11)], [finding(n, "xss") for n in range(10)]
    )  # 10/10
    second = scored([label(1, "xss"), label(2, "xss")], [finding(0, "xss")])  # 1/2
    both = bench.pool([first, second])["xss"]
    assert (both.labelled, both.found) == (12, 11)
    assert both.recall == pytest.approx(11 / 12)  # not the mean of 1.0 and 0.5


def test_scores_for_different_classes_cannot_be_added():
    with pytest.raises(AssertionError):
        _ = bench.ClassScore("xss") + bench.ClassScore("scanner")


def test_the_table_has_a_row_for_every_class_and_the_numbers():
    table = bench.format_table(scored([label(1, "xss")], [finding(0, "xss")]))
    lines = table.splitlines()
    assert len(lines) == 2 + len(LABELS)
    for name in LABELS:
        assert any(line.startswith(name) for line in lines)
    assert "recall" in lines[0] and "precision" in lines[0] and "cross-class" in lines[0]
    assert "1.000" in next(line for line in lines if line.startswith("xss"))


# --- the benchmark ---------------------------------------------------------------------


def test_every_attack_class_is_present_in_the_benchmark_data(benchmark_logs):
    scores = pooled(benchmark_logs)
    assert {label: s.labelled for label, s in scores.items() if s.labelled == 0} == {}
    assert min(s.labelled for s in scores.values()) >= 10


def test_recall_and_precision_are_at_least_95_percent_for_every_class(benchmark_logs):
    scores = pooled(benchmark_logs)
    print(
        "\nDetection benchmark: seeds 1 to 5, 3,000 lines each, 10% attacks\n"
        + bench.format_table(scores)
    )
    assert below_floor(scores) == {}


def test_no_benchmark_log_accuses_a_normal_visitor_even_one_at_a_time(benchmark_logs):
    for entries, labels in benchmark_logs:
        scores = bench.score(labels, detect(entries, RULES), RULES)
        assert {name: s.false_positives for name, s in scores.items() if s.false_positives} == {}


def test_cross_class_detections_are_reported_and_not_held_against_precision(benchmark_logs):
    scores = pooled(benchmark_logs)
    # A scanner asks for /phpmyadmin and attackers carry tool-like user agents, so some
    # detections of one class land on another class's attack. They are visible, and harmless.
    assert scores["scanner"].cross_class > 0
    assert scores["sensitive_file_probe"].cross_class > 0
    assert all(s.precision >= FLOOR for s in scores.values())


def test_the_demo_sample_log_also_meets_the_floors():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = [
        json.loads(row)
        for row in (ROOT / "data" / "samples" / "demo.labels.jsonl").read_text().splitlines()
    ]
    scores = bench.score(labels, detect(entries, RULES), RULES)
    print("\nDetection benchmark: data/samples/demo.log\n" + bench.format_table(scores))
    assert below_floor({k: v for k, v in scores.items() if v.labelled}) == {}
    assert sum(s.false_positives for s in scores.values()) == 0


@pytest.mark.parametrize(
    ("seed", "lines", "ratio"), [(6, 4000, 0.05), (7, 4000, 0.2), (8, 3000, 0.3), (9, 6000, 0.1)]
)
def test_the_floors_also_hold_on_logs_the_rules_were_never_tuned_against(
    generator, seed, lines, ratio
):
    entries, labels = generated(generator, seed, lines, ratio)
    scores = bench.score(labels, detect(entries, RULES), RULES)
    assert below_floor({k: v for k, v in scores.items() if v.labelled}) == {}


def test_the_benchmark_gives_the_same_numbers_every_time(benchmark_logs):
    first, second = pooled(benchmark_logs), pooled(benchmark_logs)
    assert first == second


def test_the_whole_benchmark_runs_in_a_few_seconds(generator):
    started = time.perf_counter()
    pooled([generated(generator, seed, 3000, 0.1) for seed in range(1, 6)])
    assert time.perf_counter() - started < 20.0


# --- the false-alarm guard -------------------------------------------------------------


def test_twenty_clean_logs_raise_no_detection_of_any_severity(clean_logs):
    for number, entries in enumerate(clean_logs):
        found = detect(entries, RULES)
        assert found == [], (
            f"clean log {number} raised {[(d.rule_id, d.evidence) for d in found[:3]]}"
        )


def test_the_clean_sample_log_raises_no_detection():
    assert detect(parse_file(ROOT / "data" / "samples" / "clean.log").entries, RULES) == []


def test_the_clean_logs_really_are_ordinary_traffic(clean_logs):
    entries = clean_logs[0]
    assert len(entries) == 2000
    assert any(e.status == 404 for e in entries)  # the usual few missing pages
    assert any(e.status == 401 for e in entries)  # the usual few failed logins
    assert any("select" in e.target for e in entries) or any(
        "report.pdf" in e.target for e in entries
    )


# --- the benchmark can fail: weakened and widened rules --------------------------------


def test_removing_every_sql_injection_rule_drops_its_recall_to_zero_and_only_its(benchmark_logs):
    scores = pooled(benchmark_logs, without(RULES, "sqli-"))
    assert scores["sql_injection"].recall == 0.0
    assert set(below_floor(scores)) == {"sql_injection"}


def test_removing_one_rule_is_noticed(benchmark_logs):
    scores = pooled(benchmark_logs, without(RULES, "xss-script-tag"))
    assert scores["xss"].recall < FLOOR
    assert "xss" in below_floor(scores)


# The generator's attacks only exercise some rules. Removing one of these lowers its class's
# recall, so the benchmark protects it. Listed by hand from measurements.
EXERCISED = {
    "sqli-union-select": "sql_injection",
    "sqli-tautology": "sql_injection",
    "sqli-quote-comment": "sql_injection",
    "sqli-time-delay": "sql_injection",
    "sqli-stacked-statement": "sql_injection",
    "xss-script-tag": "xss",
    "xss-event-handler-in-tag": "xss",
    "xss-script-uri": "xss",
    "cmdi-separator-command": "command_injection",
    "probe-env-file": "sensitive_file_probe",
    "probe-secret-file": "sensitive_file_probe",
    "probe-vcs-dir": "sensitive_file_probe",
    "probe-backup-archive": "sensitive_file_probe",
    "probe-diagnostics": "sensitive_file_probe",
}


@pytest.mark.parametrize(("rule_id", "label"), sorted(EXERCISED.items()))
def test_removing_a_rule_the_benchmark_exercises_lowers_its_recall(benchmark_logs, rule_id, label):
    scores = pooled(benchmark_logs, without(RULES, rule_id))
    assert scores[label].recall < 1.0, f"{rule_id} is not exercised by the benchmark any more"


def test_the_other_rules_are_not_exercised_by_the_benchmark_and_rely_on_their_own_cases(
    benchmark_logs,
):
    """Every generator payload is caught by another rule too (path traversal), or by one
    particular rule (command injection), or is not generated at all. Removing these changes no
    score, which is the benchmark's honest limit: their protection is rule_cases.toml. If the
    generator ever exercises one, this test fails and the rule moves to EXERCISED."""
    others = [r.id for r in RULES.signatures if r.id not in EXERCISED]
    assert len(others) == 9
    for rule_id in others:
        label = next(r.label for r in RULES.signatures if r.id == rule_id)
        scores = pooled(benchmark_logs, without(RULES, rule_id))
        assert scores[label].recall == 1.0, f"{rule_id} is now exercised: add it to EXERCISED"


@pytest.mark.parametrize(
    ("rule_id", "pattern", "label"),
    [
        ("naive-select", r"select", "sql_injection"),
        ("naive-script", r"script", "xss"),
        ("naive-passwd", r"passwd|password", "path_traversal"),
        ("naive-everything", r".", "xss"),
    ],
)
def test_a_naive_rule_that_is_too_broad_lowers_precision_and_is_noticed(
    benchmark_logs, rule_id, pattern, label
):
    scores = pooled(benchmark_logs, with_rule(RULES, rule_id, pattern, label))
    assert scores[label].false_positives > 0
    assert scores[label].precision < FLOOR
    assert label in below_floor(scores)


@pytest.mark.parametrize(
    ("rule_id", "pattern", "label"),
    [
        ("naive-select", r"select", "sql_injection"),
        ("naive-script", r"script", "xss"),
        ("everything", r".", "xss"),
    ],
)
def test_the_same_broad_rules_also_trip_the_clean_log_guard(clean_logs, rule_id, pattern, label):
    rules = with_rule(RULES, rule_id, pattern, label)
    assert sum(len(detect(entries, rules)) for entries in clean_logs) > 0


def test_a_brute_force_threshold_that_is_far_too_high_is_noticed(benchmark_logs):
    rules = replace(RULES, brute_force=BruteForceSettings(threshold=100))
    assert pooled(benchmark_logs, rules)["brute_force"].recall < FLOOR


def test_a_brute_force_threshold_of_one_accuses_normal_visitors_and_is_noticed(
    benchmark_logs, clean_logs
):
    rules = replace(RULES, brute_force=BruteForceSettings(threshold=1))
    assert pooled(benchmark_logs, rules)["brute_force"].precision < FLOOR
    assert sum(len(detect(entries, rules)) for entries in clean_logs) > 0


def test_a_scanner_threshold_that_is_far_too_high_is_noticed(benchmark_logs):
    rules = replace(RULES, scanner=ScannerSettings(threshold=500))
    assert pooled(benchmark_logs, rules)["scanner"].recall < FLOOR


def test_a_scanner_threshold_of_one_accuses_normal_visitors_and_is_noticed(
    benchmark_logs, clean_logs
):
    rules = replace(RULES, scanner=ScannerSettings(threshold=1))
    assert pooled(benchmark_logs, rules)["scanner"].precision < FLOOR
    assert sum(len(detect(entries, rules)) for entries in clean_logs) > 0


def test_a_scanner_tool_list_that_matches_ordinary_browsers_is_noticed(benchmark_logs):
    rules = replace(RULES, scanner=ScannerSettings(user_agents=("mozilla",)))
    assert pooled(benchmark_logs, rules)["scanner"].precision < FLOOR


# --- limits of what this benchmark can see ---------------------------------------------


def test_a_rule_that_is_too_broad_in_a_way_the_normal_traffic_never_exercises_goes_unseen(
    benchmark_logs, clean_logs
):
    """The generator's normal traffic has no /admin page, so a rule that fires on "admin" cannot
    be caught here. Near-miss cases for each rule (tests/detection/rule_cases.toml) cover what
    the synthetic traffic does not. This test records the limit so nobody relies on the
    benchmark for it."""
    rules = with_rule(RULES, "naive-admin", r"admin", "sensitive_file_probe")
    assert below_floor(pooled(benchmark_logs, rules)) == {}
    assert sum(len(detect(entries, rules)) for entries in clean_logs) == 0
    assert detect(
        [
            parse_line(
                '192.0.2.1 - - [01/Jun/2025:10:00:00 +0000] "GET /admin-guide HTTP/1.1" 200 5'
            )
        ],
        rules,
    )
