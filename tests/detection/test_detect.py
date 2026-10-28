"""Tests for detect(): every rule, de-duplicated and ordered."""

import importlib.util
import json
import random
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import loginsight.detection as detection_package
from loginsight.detection import detect
from loginsight.detection.behaviour import RULE_ID_BRUTE_FORCE, RULE_ID_SCANNER_BURST
from loginsight.detection.models import Detection, Severity, SignatureRule
from loginsight.detection.ruleset import BruteForceSettings, RuleSet, ScannerSettings, load_rules
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file, parse_line

UTC = timezone.utc
T0 = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"


def request(target="/ok", ip="203.0.113.5", seconds=0.0, status=200, method="GET", agent=BROWSER):
    path, _, query = target.partition("?")
    return LogEntry(
        ip=ip,
        time=T0 + timedelta(seconds=seconds),
        method=method,
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=status,
        size=0,
        user_agent=agent,
        request=f"{method} {target} HTTP/1.1",
    )


def rule(rule_id, pattern, severity, label="sql_injection"):
    return SignatureRule(
        id=rule_id, label=label, severity=severity, description="a test rule", pattern=pattern
    )


def custom(*signatures, **settings):
    return RuleSet(signatures=tuple(signatures), **settings)


def only(found, rule_id):
    return [d for d in found if d.rule_id == rule_id]


# --- the entry point ------------------------------------------------------------------


def test_detect_is_exported_from_the_detection_package():
    assert detection_package.detect is detect
    assert callable(detect)


def test_the_package_also_exports_the_types_a_caller_needs():
    for name in ("Detection", "Severity", "RuleSet", "load_rules", "SignatureRule"):
        assert hasattr(detection_package, name), name


def test_no_entries_gives_an_empty_list():
    assert detect([]) == []
    assert detect([], load_rules()) == []


def test_requests_that_match_nothing_give_nothing():
    assert detect([request("/home"), request("/products/12?sort=price"), request("/")]) == []


def test_the_default_rules_are_used_when_none_are_given():
    found = detect([request("/search?q=1 union select 2")])
    assert [d.rule_id for d in found] == ["sqli-union-select"]
    assert detect([request("/search?q=1 union select 2")]) == detect(
        [request("/search?q=1 union select 2")], load_rules()
    )


def test_a_custom_rule_set_replaces_the_defaults_completely():
    rules = custom(rule("only-rule", "zzz", Severity.LOW))
    assert detect([request("/search?q=1 union select 2")], rules) == []
    assert [d.rule_id for d in detect([request("/zzz")], rules)] == ["only-rule"]


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_entries_can_be_any_iterable_even_one_that_can_only_be_read_once(source):
    entries = [request("/a?q=1 union select 2", seconds=n) for n in range(3)]
    entries += [request("/login", method="POST", status=401, seconds=n) for n in range(12)]
    assert len(detect(source(entries))) == 4  # three signature hits and one burst


# --- overlapping signature rules ------------------------------------------------------


def test_one_request_matched_by_two_rules_gives_one_detection_with_the_higher_severity():
    # An SQL injection (high) on a phpMyAdmin path (low).
    found = detect([request("/phpmyadmin?id=1 union select 2")])
    assert len(found) == 1
    assert found[0].rule_id == "sqli-union-select"
    assert found[0].severity is Severity.HIGH
    assert found[0].also_matched == ("probe-admin-panel",)


def test_the_label_and_evidence_are_those_of_the_winning_rule():
    (found,) = detect([request("/wp-login.php?x=1 union select 2")])
    assert found.label == "sql_injection"
    assert found.evidence == "GET /wp-login.php?x=1 union select 2 HTTP/1.1"


def test_a_critical_rule_beats_a_high_one():
    (found,) = detect([request("/phpinfo.php?host=1;cat /etc/passwd")])
    assert found.severity is Severity.CRITICAL
    assert found.rule_id == "cmdi-separator-command"
    assert set(found.also_matched) == {"traversal-sensitive-file", "probe-diagnostics"}


def test_equal_severities_keep_the_rule_that_comes_first_in_the_file():
    rules = custom(
        rule("first-in-file", "zzz", Severity.HIGH, label="xss"),
        rule("second-in-file", "zzz", Severity.HIGH),
        rule("third-in-file", "zzz", Severity.HIGH, label="path_traversal"),
    )
    (found,) = detect([request("/zzz")], rules)
    assert found.rule_id == "first-in-file"
    assert found.also_matched == ("second-in-file", "third-in-file")


def test_a_higher_severity_later_in_the_file_still_wins_and_the_rest_keep_file_order():
    rules = custom(
        rule("low-one", "zzz", Severity.LOW),
        rule("high-one", "zzz", Severity.HIGH),
        rule("mid-one", "zzz", Severity.MEDIUM),
        rule("high-two", "zzz", Severity.HIGH),
    )
    (found,) = detect([request("/zzz")], rules)
    assert found.rule_id == "high-one"
    assert found.also_matched == ("low-one", "mid-one", "high-two")


def test_rules_that_do_not_fire_are_not_listed():
    rules = custom(
        rule("a", "zzz", Severity.HIGH),
        rule("b", "nope", Severity.LOW),
        rule("c", "zz", Severity.LOW),
    )
    (found,) = detect([request("/zzz")], rules)
    assert found.also_matched == ("c",)


def test_a_rule_never_lists_itself():
    rules = custom(rule("a", "zzz", Severity.HIGH), rule("b", "zzz", Severity.LOW))
    (found,) = detect([request("/zzz")], rules)
    assert found.rule_id not in found.also_matched


def test_different_requests_are_never_merged():
    entries = [request("/zzz", seconds=n) for n in range(5)]
    found = detect(entries, custom(rule("a", "zzz", Severity.HIGH), rule("b", "zzz", Severity.LOW)))
    assert [d.first_index for d in found] == [0, 1, 2, 3, 4]
    assert all(d.also_matched == ("b",) for d in found)


def test_a_request_that_matches_one_rule_has_nothing_in_also_matched():
    (found,) = detect([request("/search?q=1 union select 2")])
    assert found.also_matched == ()


def test_a_merged_detection_is_still_a_valid_detection():
    (found,) = detect([request("/phpmyadmin?id=1 union select 2")])
    assert isinstance(found, Detection)
    assert json.loads(json.dumps(found.to_dict()))["also_matched"] == ["probe-admin-panel"]


def test_the_number_of_signature_detections_equals_the_number_of_distinct_lines_matched():
    log = [
        request(t, seconds=n)
        for n, t in enumerate(
            [
                "/phpmyadmin?id=1 union select 2",
                "/home",
                "/.env",
                "/s?q=<script>alert(1)</script>",
                "/a?x=1;cat /etc/passwd",
            ]
        )
    ]
    found = detect(log)
    assert sorted(d.first_index for d in found) == [0, 2, 3, 4]


# --- behavioural detections are kept apart --------------------------------------------


def test_a_brute_force_burst_and_a_signature_hit_on_the_same_line_both_appear():
    entries = [request("/login", method="POST", status=401, seconds=n) for n in range(12)]
    entries[5] = request("/login?user=admin' or '1'='1", method="POST", status=401, seconds=5)
    found = detect(entries)
    assert sorted(d.rule_id for d in found) == [RULE_ID_BRUTE_FORCE, "sqli-tautology"]
    signature = only(found, "sqli-tautology")[0]
    assert signature.first_index == 5 and signature.also_matched == ()


def test_a_scan_that_hits_a_probe_path_keeps_the_probe_and_the_scan_separate():
    entries = [request(f"/missing{n}", status=404, seconds=n) for n in range(15)]
    entries[3] = request("/.env", status=404, seconds=3)
    found = detect(entries)
    assert RULE_ID_SCANNER_BURST in {d.rule_id for d in found}
    probe = only(found, "probe-env-file")[0]
    assert probe.first_index == 3 and probe.label == "sensitive_file_probe"
    assert only(found, RULE_ID_SCANNER_BURST)[0].label == "scanner"


def test_a_signature_detection_never_lists_a_behavioural_rule_and_the_reverse():
    entries = [request(f"/m{n}?q=1 union select 2", status=404, seconds=n) for n in range(20)]
    found = detect(entries)
    for d in found:
        if d.rule_id.startswith("behaviour-"):
            assert d.also_matched == ()
        else:
            assert not any(other.startswith("behaviour-") for other in d.also_matched)
    assert {d.rule_id for d in found} >= {"sqli-union-select", RULE_ID_SCANNER_BURST}


def test_the_behaviour_settings_come_from_the_rule_set():
    entries = [request("/login", method="POST", status=401, seconds=n) for n in range(3)]
    assert detect(entries) == []
    lenient = custom(brute_force=BruteForceSettings(threshold=3))
    assert [d.rule_id for d in detect(entries, lenient)] == [RULE_ID_BRUTE_FORCE]
    paths = [request(f"/m{n}", status=404, seconds=n) for n in range(3)]
    assert detect(paths) == []
    assert [d.rule_id for d in detect(paths, custom(scanner=ScannerSettings(threshold=3)))] == [
        RULE_ID_SCANNER_BURST
    ]


def test_a_known_scanning_tool_is_reported_too():
    found = detect([request("/anything", agent="sqlmap/1.7")])
    assert [(d.rule_id, d.severity) for d in found] == [("behaviour-scanner-tool", Severity.LOW)]


# --- severity -------------------------------------------------------------------------


def test_each_signature_rules_severity_comes_from_the_rules_file():
    for target, expected in [
        ("/s?q=<script>alert(1)</script>", Severity.MEDIUM),
        ("/s?q=1 union select 2", Severity.HIGH),
        ("/get?f=../../../x", Severity.HIGH),
        ("/run?h=1;cat /etc/hostname", Severity.CRITICAL),
        ("/wp-login.php", Severity.LOW),
    ]:
        assert {d.severity for d in detect([request(target)])} == {expected}, target


def test_a_burst_escalates_at_five_times_the_threshold_and_not_before():
    medium = [request("/login", method="POST", status=401, seconds=n / 10) for n in range(49)]
    high = [request("/login", method="POST", status=401, seconds=n / 10) for n in range(50)]
    assert detect(medium)[0].severity is Severity.MEDIUM
    assert detect(high)[0].severity is Severity.HIGH


# --- order ----------------------------------------------------------------------------


def mixed_log():
    entries = []
    entries.append(request("/wp-login.php", seconds=0))  # low
    entries.append(request("/s?q=<script>x</script>", seconds=1))  # medium
    entries.append(request("/run?h=1;cat /etc/hostname", seconds=2))  # critical
    entries.append(request("/home", seconds=3))
    entries.append(request("/s?q=1 union select 2", seconds=4))  # high
    entries.append(request("/phpmyadmin", seconds=5))  # low
    entries += [
        request("/login", method="POST", status=401, ip="198.51.100.1", seconds=10 + n)
        for n in range(12)
    ]
    entries.append(request("/x", agent="nikto", ip="198.51.100.2", seconds=30))  # low (tool)
    return entries


def test_the_result_is_ordered_from_critical_to_low():
    severities = [d.severity for d in detect(mixed_log())]
    assert severities == sorted(severities, reverse=True)
    assert severities[0] is Severity.CRITICAL and severities[-1] is Severity.LOW


def test_equal_severities_are_ordered_by_position_then_rule_id():
    found = detect(mixed_log())
    keys = [(-int(d.severity), d.first_index, d.rule_id) for d in found]
    assert keys == sorted(keys)
    assert [d.first_index for d in found if d.severity is Severity.LOW][:2] == [0, 5]


def test_the_result_is_exactly_the_same_every_time():
    entries = mixed_log()
    assert detect(entries) == detect(entries) == detect(list(entries))


def test_shuffled_input_gives_the_same_detections_apart_from_positions():
    entries = mixed_log()
    shuffled = list(entries)
    random.Random(3).shuffle(shuffled)

    def summary(found):
        return sorted(
            (d.rule_id, d.ip, d.count, d.time, d.evidence, d.severity, d.also_matched)
            for d in found
        )

    assert summary(detect(shuffled)) == summary(detect(entries))
    severities = [d.severity for d in detect(shuffled)]
    assert severities == sorted(severities, reverse=True)


def test_requests_at_the_same_instant_are_ordered_by_their_position():
    entries = [
        request("/s?q=1 union select 2", seconds=0, ip=f"203.0.113.{n}") for n in range(1, 6)
    ]
    assert [d.ip for d in detect(entries)] == [f"203.0.113.{n}" for n in range(1, 6)]


def test_the_input_is_not_modified():
    entries = mixed_log()
    before = [e.to_dict() for e in entries]
    detect(entries)
    assert [e.to_dict() for e in entries] == before


def test_every_detection_points_at_real_lines_and_serialises():
    entries = mixed_log()
    for d in detect(entries):
        assert 0 <= d.first_index <= d.last_index < len(entries)
        assert json.loads(json.dumps(d.to_dict()))["rule_id"] == d.rule_id


# --- the sample logs and generated logs -----------------------------------------------


def test_the_clean_sample_log_gives_nothing():
    assert detect(parse_file(ROOT / "data" / "samples" / "clean.log").entries) == []


def labelled(path):
    rows = [json.loads(row) for row in path.read_text().splitlines()]
    return {row["line"] - 1: row for row in rows}


def test_the_demo_log_gives_a_detection_for_every_labelled_attack_line_of_the_signature_classes():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    found = detect(entries)
    by_index = {}
    for d in found:
        by_index.setdefault(d.first_index, []).append(d)
    signature_lines = {i: row for i, row in labels.items() if row["kind"] == "signature"}
    assert len(signature_lines) >= 20
    for index, row in signature_lines.items():
        assert any(d.label == row["label"] for d in by_index.get(index, [])), (index, row)


def test_the_demo_log_finds_its_brute_force_burst_and_flags_no_normal_address():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    attackers = {row["ip"] for row in labels.values()}
    found = detect(entries)
    assert {row["ip"] for row in labels.values() if row["label"] == "brute_force"} <= {
        d.ip for d in found if d.label == "brute_force"
    }
    assert {d.ip for d in found} <= attackers


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("seed", "lines", "ratio"), [(42, 3000, 0.1), (1, 3000, 0.2), (7, 4000, 0.3)]
)
def test_a_generated_log_is_fully_covered_with_no_detection_on_a_normal_visitor(
    generator, seed, lines, ratio
):
    log, labels = generator.generate(seed=seed, lines=lines, attack_ratio=ratio)
    entries = [parse_line(line) for line in log]
    truth = {item["line"] - 1: item for item in labels}
    attackers = {item["ip"] for item in labels}
    found = detect(entries)
    assert {d.ip for d in found} <= attackers
    by_index = {}
    for d in found:
        by_index.setdefault(d.first_index, set()).add(d.label)
    missed = [
        (i, item["label"])
        for i, item in truth.items()
        if item["kind"] == "signature" and item["label"] not in by_index.get(i, ())
    ]
    assert missed == []
    behavioural = {item["ip"]: item["label"] for item in labels if item["kind"] == "behavioural"}
    found_behaviour = {(d.ip, d.label) for d in found if d.label in ("brute_force", "scanner")}
    assert {(ip, label) for ip, label in behavioural.items()} <= found_behaviour


@pytest.mark.parametrize("seed", range(8))
def test_generated_clean_logs_give_nothing(generator, seed):
    log, _ = generator.generate(seed=seed, lines=3000, attack_ratio=0)
    assert detect([parse_line(line) for line in log]) == []


def test_overlapping_rules_are_merged_on_a_big_generated_log(generator):
    log, _ = generator.generate(seed=42, lines=20_000, attack_ratio=0.2)
    found = detect([parse_line(line) for line in log])
    signature = [d for d in found if not d.rule_id.startswith("behaviour-")]
    lines = Counter(d.first_index for d in signature)
    assert max(lines.values()) == 1, "no request may have two signature detections"
    assert sum(1 for d in signature if d.also_matched) > 100  # and merging really happened


def test_twenty_thousand_generated_lines_finish_in_a_few_seconds(generator):
    log, _ = generator.generate(seed=42, lines=20_000, attack_ratio=0.1)
    entries = [parse_line(line) for line in log]
    started = time.perf_counter()
    found = detect(entries)
    assert time.perf_counter() - started < 5.0
    assert found
