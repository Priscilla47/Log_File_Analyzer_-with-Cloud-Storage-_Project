"""Tests for the detection data types: Severity, Detection and SignatureRule."""

import dataclasses
import importlib.util
import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.detection.models import (
    BEHAVIOURAL_LABELS,
    LABELS,
    MAX_EVIDENCE_LENGTH,
    SIGNATURE_LABELS,
    Detection,
    Severity,
    SignatureRule,
    shorten_evidence,
)

UTC = timezone.utc
WHEN = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_logs.py"


def make(**overrides):
    values = {
        "rule_id": "sqli-union-select",
        "label": "sql_injection",
        "severity": Severity.HIGH,
        "ip": "192.0.2.1",
        "time": WHEN,
        "first_index": 4,
        "last_index": 4,
        "count": 1,
        "evidence": "GET /?id=1 UNION SELECT 1 HTTP/1.1",
    }
    values.update(overrides)
    return Detection(**values)


def rule(**overrides):
    values = {
        "id": "sqli-union-select",
        "label": "sql_injection",
        "severity": Severity.HIGH,
        "description": "UNION SELECT used to read other tables",
        "pattern": r"union\s+select",
    }
    values.update(overrides)
    return SignatureRule(**values)


# --- Severity -------------------------------------------------------------------------


def test_severities_have_the_documented_numbers():
    assert [s.value for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)] == [
        1,
        2,
        3,
        4,
    ]
    assert [s.name for s in Severity] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_severities_compare():
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.HIGH >= Severity.HIGH
    assert max(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM) is Severity.CRITICAL


def test_severities_sort():
    shuffled = [Severity.HIGH, Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
    assert sorted(shuffled) == [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert sorted(shuffled, reverse=True)[0] is Severity.CRITICAL


@pytest.mark.parametrize("name", ["high", "High", "HIGH", "hIgH"])
def test_from_name_ignores_case(name):
    assert Severity.from_name(name) is Severity.HIGH


@pytest.mark.parametrize("severity", list(Severity))
def test_from_name_round_trips_every_severity(severity):
    assert Severity.from_name(severity.name) is severity
    assert Severity.from_name(str(severity)) is severity


@pytest.mark.parametrize("name", ["", "urgent", "hig", "highest", " high", "high ", "3", "none"])
def test_from_name_rejects_unknown_names(name):
    with pytest.raises(ValueError, match="severity"):
        Severity.from_name(name)


@pytest.mark.parametrize("value", [None, 3, 3.0, b"high", ["high"], Severity.HIGH])
def test_from_name_rejects_things_that_are_not_names(value):
    with pytest.raises(ValueError):
        Severity.from_name(value)


def test_the_error_for_an_unknown_name_lists_the_valid_ones():
    with pytest.raises(ValueError) as info:
        Severity.from_name("urgent")
    message = str(info.value)
    assert "urgent" in message
    assert all(name in message for name in ("low", "medium", "high", "critical"))


@pytest.mark.parametrize(
    ("severity", "text"),
    [
        (Severity.LOW, "low"),
        (Severity.MEDIUM, "medium"),
        (Severity.HIGH, "high"),
        (Severity.CRITICAL, "critical"),
    ],
)
def test_a_severity_prints_as_its_lower_case_name(severity, text):
    assert str(severity) == text
    assert f"{severity}" == text
    assert f"{severity}" == text
    assert f"{severity!s:>10}" == text.rjust(10)


# --- labels ---------------------------------------------------------------------------


def test_there_are_seven_labels_split_into_signature_and_behavioural():
    assert len(LABELS) == 7 == len(set(LABELS))
    assert set(SIGNATURE_LABELS) | set(BEHAVIOURAL_LABELS) == set(LABELS)
    assert not set(SIGNATURE_LABELS) & set(BEHAVIOURAL_LABELS)
    assert set(BEHAVIOURAL_LABELS) == {"brute_force", "scanner"}


def test_the_labels_match_the_generators_labels_exactly():
    spec = importlib.util.spec_from_file_location("generate_logs", SCRIPT)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert tuple(LABELS) == tuple(generator.ATTACK_LABELS)
    assert tuple(SIGNATURE_LABELS) == tuple(generator.SIGNATURE_LABELS)
    assert tuple(BEHAVIOURAL_LABELS) == tuple(generator.BEHAVIOURAL_LABELS)


def test_the_labels_are_immutable_tuples():
    assert isinstance(LABELS, tuple)
    assert isinstance(SIGNATURE_LABELS, tuple) and isinstance(BEHAVIOURAL_LABELS, tuple)


# --- Detection: creation --------------------------------------------------------------


def test_a_detection_keeps_its_fields_and_defaults_also_matched_to_empty():
    detection = make()
    assert detection.rule_id == "sqli-union-select"
    assert detection.label == "sql_injection"
    assert detection.severity is Severity.HIGH
    assert (detection.ip, detection.time) == ("192.0.2.1", WHEN)
    assert (detection.first_index, detection.last_index, detection.count) == (4, 4, 1)
    assert detection.also_matched == ()


def test_also_matched_is_kept():
    assert make(also_matched=("probe-env-file", "xss-script-tag")).also_matched == (
        "probe-env-file",
        "xss-script-tag",
    )


def test_a_burst_can_span_many_lines_with_fewer_involved():
    # 12 failed logins somewhere inside 40 lines of other traffic.
    detection = make(label="brute_force", first_index=10, last_index=49, count=12)
    assert detection.count == 12


@pytest.mark.parametrize("label", LABELS)
def test_every_label_is_accepted(label):
    assert make(label=label).label == label


def test_a_detection_is_immutable():
    detection = make()
    with pytest.raises(dataclasses.FrozenInstanceError):
        detection.count = 5  # type: ignore[misc]


def test_equal_detections_are_equal_and_can_go_in_a_set():
    assert make() == make()
    assert len({make(), make(), make(first_index=5, last_index=5)}) == 2


def test_keyword_arguments_are_required():
    with pytest.raises(TypeError):
        Detection("r", "sql_injection", Severity.LOW, "ip", WHEN, 0, 0, 1, "e")  # type: ignore[misc]


# --- Detection: validation ------------------------------------------------------------


@pytest.mark.parametrize("label", ["", "sqli", "SQL_INJECTION", "sql injection", "malware", None])
def test_an_unknown_label_is_rejected(label):
    with pytest.raises(ValueError, match="label"):
        make(label=label)


def test_the_error_for_an_unknown_label_names_it():
    with pytest.raises(ValueError, match="malware"):
        make(label="malware")


@pytest.mark.parametrize("count", [0, -1, -100])
def test_a_count_below_one_is_rejected(count):
    with pytest.raises(ValueError, match="count"):
        make(count=count)


def test_a_first_index_after_the_last_is_rejected():
    with pytest.raises(ValueError, match="first_index"):
        make(first_index=5, last_index=4)


@pytest.mark.parametrize("index", [-1, -50])
def test_a_negative_index_is_rejected(index):
    with pytest.raises(ValueError, match="index"):
        make(first_index=index, last_index=4)


def test_a_count_larger_than_the_lines_it_spans_is_rejected():
    # 3 lines cannot hold 4 involved lines.
    with pytest.raises(ValueError, match="count"):
        make(first_index=10, last_index=12, count=4)


def test_a_count_exactly_filling_the_span_is_fine():
    assert make(first_index=10, last_index=12, count=3).count == 3


@pytest.mark.parametrize("severity", [3, "high", None, 3.0])
def test_a_severity_that_is_not_a_severity_member_is_rejected(severity):
    with pytest.raises(TypeError, match="severity"):
        make(severity=severity)


@pytest.mark.parametrize("rule_id", ["", None])
def test_an_empty_rule_id_is_rejected(rule_id):
    with pytest.raises(ValueError, match="rule_id"):
        make(rule_id=rule_id)


def test_also_matched_must_be_a_tuple_of_ids():
    with pytest.raises(TypeError, match="also_matched"):
        make(also_matched=["probe-env-file"])
    with pytest.raises(TypeError, match="also_matched"):
        make(also_matched=("ok", 5))


def test_a_detection_does_not_list_its_own_rule_in_also_matched():
    with pytest.raises(ValueError, match="also_matched"):
        make(also_matched=("sqli-union-select",))


# --- Detection: to_dict ---------------------------------------------------------------


def test_to_dict_has_exactly_these_keys_in_this_order():
    assert list(make().to_dict()) == [
        "rule_id",
        "label",
        "severity",
        "ip",
        "time",
        "first_index",
        "last_index",
        "count",
        "evidence",
        "also_matched",
    ]


def test_to_dict_uses_plain_json_types():
    data = make(also_matched=("a-rule",)).to_dict()
    assert data["severity"] == "high"
    assert data["time"] == "2025-06-01T12:00:00+00:00"
    assert data["also_matched"] == ["a-rule"]
    assert type(data["severity"]) is str
    assert type(data["also_matched"]) is list
    assert type(data["first_index"]) is int


def test_to_dict_passes_json_dumps_and_survives_a_round_trip():
    original = make(also_matched=("probe-env-file",))
    assert json.loads(json.dumps(original.to_dict())) == original.to_dict()


def test_to_dict_keeps_the_time_zone_offset():
    when = datetime(2025, 6, 1, 10, 0, tzinfo=timezone(timedelta(hours=-7)))
    assert make(time=when).to_dict()["time"] == "2025-06-01T10:00:00-07:00"


def test_changing_the_dict_does_not_change_the_detection():
    detection = make(also_matched=("a-rule",))
    data = detection.to_dict()
    data["also_matched"].append("tampered")
    data["count"] = 99
    assert detection.also_matched == ("a-rule",)
    assert detection.count == 1


def test_evidence_with_awkward_characters_survives_json():
    evidence = 'GET /?q="><script>alert(1)</script>\\n HTTP/1.1 é 😀 \t'
    data = json.loads(json.dumps(make(evidence=evidence).to_dict()))
    assert data["evidence"] == evidence


# --- Detection: ordering --------------------------------------------------------------


def test_sorting_by_sort_key_puts_critical_first():
    low = make(severity=Severity.LOW, rule_id="a")
    critical = make(severity=Severity.CRITICAL, rule_id="b")
    medium = make(severity=Severity.MEDIUM, rule_id="c")
    high = make(severity=Severity.HIGH, rule_id="d")
    ordered = sorted([low, medium, critical, high], key=lambda d: d.sort_key)
    assert [d.severity for d in ordered] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_equal_severities_are_ordered_by_first_index_then_rule_id():
    entries = [
        make(rule_id="b", first_index=9, last_index=9),
        make(rule_id="z", first_index=2, last_index=2),
        make(rule_id="a", first_index=9, last_index=9),
    ]
    ordered = sorted(entries, key=lambda d: d.sort_key)
    assert [(d.first_index, d.rule_id) for d in ordered] == [(2, "z"), (9, "a"), (9, "b")]


def test_sorting_is_stable_for_equal_keys():
    first = make(evidence="first")
    second = make(evidence="second")
    third = make(evidence="third")
    assert first.sort_key == second.sort_key == third.sort_key
    ordered = sorted([second, third, first], key=lambda d: d.sort_key)
    assert [d.evidence for d in ordered] == ["second", "third", "first"]


def test_the_sort_key_does_not_depend_on_the_input_order():
    detections = [
        make(
            severity=random.Random(n).choice(list(Severity)),
            rule_id=f"r{n % 4}",
            first_index=n % 7,
            last_index=n % 7,
        )
        for n in range(40)
    ]
    expected = sorted(detections, key=lambda d: d.sort_key)
    rng = random.Random(3)
    for _ in range(5):
        shuffled = list(detections)
        rng.shuffle(shuffled)
        assert [d.sort_key for d in sorted(shuffled, key=lambda d: d.sort_key)] == [
            d.sort_key for d in expected
        ]


def test_sort_key_is_a_tuple_with_the_severity_negated():
    assert make(severity=Severity.CRITICAL, rule_id="r", first_index=3, last_index=3).sort_key == (
        -4,
        3,
        "r",
    )


# --- SignatureRule --------------------------------------------------------------------


def test_a_rule_keeps_its_fields_and_compiles_its_pattern():
    r = rule()
    assert (r.id, r.label, r.severity) == ("sqli-union-select", "sql_injection", Severity.HIGH)
    assert r.description.startswith("UNION SELECT")
    assert r.pattern == r"union\s+select"
    assert isinstance(r.compiled, re.Pattern)
    assert r.compiled.pattern == r.pattern


def test_the_pattern_is_compiled_ignoring_case():
    r = rule()
    assert r.compiled.flags & re.IGNORECASE
    assert r.compiled.search("1 UNION   SELECT password")
    assert r.compiled.search("1 union select password")
    assert r.compiled.search("1 UnIoN\tSeLeCt password")
    assert not r.compiled.search("a union of select friends")


def test_the_compiled_pattern_cannot_be_passed_in():
    with pytest.raises(TypeError):
        SignatureRule(
            id="x",
            label="xss",
            severity=Severity.LOW,
            description="d",
            pattern="a",
            compiled=re.compile("b"),  # type: ignore[call-arg]
        )


@pytest.mark.parametrize("pattern", ["(", "[a-", "*abc", "(?P<n", "a{2,1}", "\\"])
def test_an_invalid_regular_expression_raises_a_value_error_naming_the_rule(pattern):
    with pytest.raises(ValueError, match="my-broken-rule"):
        rule(id="my-broken-rule", pattern=pattern)


def test_the_error_for_a_bad_pattern_also_says_what_is_wrong():
    with pytest.raises(ValueError) as info:
        rule(id="my-broken-rule", pattern="(unclosed")
    assert "my-broken-rule" in str(info.value)
    assert "unclosed" in str(info.value) or "parenthesis" in str(info.value)


def test_an_empty_pattern_is_rejected_because_it_would_match_everything():
    with pytest.raises(ValueError, match="empty"):
        rule(pattern="")


@pytest.mark.parametrize("label", ["", "sqli", "malware", None])
def test_a_rule_with_an_unknown_label_is_rejected(label):
    with pytest.raises(ValueError, match="label"):
        rule(label=label)


def test_a_rule_error_names_the_rule_for_every_kind_of_mistake():
    with pytest.raises(ValueError, match="my-rule"):
        rule(id="my-rule", label="nope")
    with pytest.raises(TypeError, match="my-rule"):
        rule(id="my-rule", severity="high")


@pytest.mark.parametrize("severity", ["high", 3, None])
def test_a_rule_severity_must_be_a_severity_member(severity):
    with pytest.raises(TypeError, match="severity"):
        rule(severity=severity)


@pytest.mark.parametrize("rule_id", ["", None])
def test_a_rule_needs_an_id(rule_id):
    with pytest.raises(ValueError, match="id"):
        rule(id=rule_id)


def test_a_rule_is_immutable():
    r = rule()
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.pattern = "other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.compiled = re.compile("other")  # type: ignore[misc]


def test_rules_with_the_same_fields_are_equal():
    assert rule() == rule()
    assert rule() != rule(pattern=r"union\s+all")
    assert len({rule(), rule()}) == 1


def test_a_rule_pattern_can_use_regular_expression_features():
    r = rule(pattern=r"(?:\.\./|%2e%2e%2f){2,}")
    assert r.compiled.search("/a/../../etc")
    assert r.compiled.search("/a/%2E%2E%2F%2e%2e%2f")
    assert not r.compiled.search("/a/../b")


@pytest.mark.parametrize("label", LABELS)
def test_a_rule_can_be_created_for_every_label(label):
    assert rule(label=label).label == label


# --- evidence -------------------------------------------------------------------------


def test_evidence_shorter_than_the_limit_is_unchanged():
    assert shorten_evidence("GET / HTTP/1.1") == "GET / HTTP/1.1"
    assert shorten_evidence("") == ""


def test_the_evidence_limit_is_200_characters():
    assert MAX_EVIDENCE_LENGTH == 200


def test_evidence_at_the_limit_is_unchanged_and_one_over_is_cut():
    assert shorten_evidence("x" * 200) == "x" * 200
    assert shorten_evidence("x" * 201) == "x" * 200
    assert len(shorten_evidence("y" * 100_000)) == 200


def test_cutting_evidence_never_splits_a_character_in_half():
    text = "😀" * 300  # one character each, although four bytes in UTF-8
    assert shorten_evidence(text) == "😀" * 200
