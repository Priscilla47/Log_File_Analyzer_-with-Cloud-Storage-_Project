"""Tests for the SSRF, template injection and remote file inclusion rules.

The per-rule attack and near-miss cases live in ``rule_cases.toml`` (checked by
``test_rule_cases.py``). This file holds what is not per rule: the agreed labels and severities,
ordinary requests that no rule may fire on, the known gap, hostile input, and the sample logs.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginsight.detection import detect
from loginsight.detection.models import LABELS, Severity
from loginsight.detection.ruleset import load_rules
from loginsight.detection.signatures import detect_signatures
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "data" / "samples"
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)
RULES = load_rules()
BY_ID = {rule.id: rule for rule in RULES.signatures}

NEW_RULES = {
    "ssrf-cloud-metadata": ("ssrf", Severity.HIGH),
    "ssti-arithmetic-probe": ("template_injection", Severity.MEDIUM),
    "ssti-engine-internals": ("template_injection", Severity.HIGH),
    "rfi-script-on-address": ("file_inclusion", Severity.HIGH),
}


def entry_for(target, status=200):
    path, _, query = target.partition("?")
    return LogEntry(
        ip="203.0.113.7",
        time=WHEN,
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=status,
        size=0,
        request=f"GET {target} HTTP/1.1",
    )


def fired(target):
    return {d.rule_id for d in detect_signatures([entry_for(target)], RULES)}


class TestTheRules:
    @pytest.mark.parametrize(("rule_id", "expected"), sorted(NEW_RULES.items()))
    def test_each_rule_has_the_agreed_label_and_severity(self, rule_id, expected):
        assert (BY_ID[rule_id].label, BY_ID[rule_id].severity) == expected

    def test_the_three_labels_exist_and_are_signature_labels(self):
        from loginsight.detection.models import BEHAVIOURAL_LABELS, SIGNATURE_LABELS

        for label in ("ssrf", "template_injection", "file_inclusion"):
            assert label in LABELS and label in SIGNATURE_LABELS and label not in BEHAVIOURAL_LABELS

    def test_every_rule_has_a_real_description_and_a_short_pattern(self):
        for rule_id in NEW_RULES:
            rule = BY_ID[rule_id]
            assert len(rule.description) > 40 and len(rule.pattern) <= 500


class TestTheExamplesFromTheIssue:
    @pytest.mark.parametrize(
        ("target", "rule_id"),
        [
            ("/?url=http://169.254.169.254/latest/meta-data/", "ssrf-cloud-metadata"),
            ("/?name={{7*7}}", "ssti-arithmetic-probe"),
            ("/?page=http://203.0.113.66/shell.txt", "rfi-script-on-address"),
        ],
    )
    def test_each_is_detected(self, target, rule_id):
        assert rule_id in fired(target)

    @pytest.mark.parametrize(
        "target",
        [
            "/?to=https%3A%2F%2Fexample.com%2Fhome",
            "/login?next=%2Faccount%2Fsettings",
            "/redirect?url=https://example.com/docs/page.html",
            "/redirect?url=http://203.0.113.5/",
            "/go?url=/pricing",
            "/view?page=about",
        ],
    )
    def test_the_benign_redirects_used_in_the_audit_are_not(self, target):
        assert fired(target) == set()


# Ordinary requests with the words and shapes the rules look for.
HARMLESS = [
    "/product?id={{item.id}}",
    "/product/{{slug}}",
    "/greet?name={{ user.name }}",
    "/greet?name=${price}",
    "/greet?name={{config}}",
    "/calc?expression=7*7",
    "/calc?e=3+4",
    "/search?q=7*7",
    "/search?q=%7B1%2C2%7D",
    "/search?q=100.100.100.2000",
    "/search?q=169.254.169.2540",
    "/docs/instance-metadata",
    "/blog/google-internal-tools",
    "/download?file=readme.txt",
    "/img?src=https://cdn.example.com/a.php",
    "/login?next=https://partner.example/login.php",
    "/api/ips?address=203.0.113.5&file=notes.txt",
    "/docs/__init__.py",
    "/docs/python/class-methods",
    "/search?q=java+lang+runtime",
]


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_none_of_the_new_rules(target):
    assert fired(target) & set(NEW_RULES) == set()


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_no_rule_at_all(target):
    assert fired(target) == set()


def test_there_are_plenty_of_harmless_examples():
    assert len(HARMLESS) >= 20 and len(set(HARMLESS)) == len(HARMLESS)


class TestEncodingAndCase:
    @pytest.mark.parametrize(
        ("target", "rule_id"),
        [
            ("/f?u=http%253A%252F%252F169.254.169.254%252Flatest", "ssrf-cloud-metadata"),
            ("/f?u=HTTP://METADATA.GOOGLE.INTERNAL/x", "ssrf-cloud-metadata"),
            ("/g?n=%7b%7b7*7%7d%7d", "ssti-arithmetic-probe"),
            ("/g?n=%257B%257B7*7%257D%257D", "ssti-arithmetic-probe"),
            ("/g?n={{7%2a7}}", "ssti-arithmetic-probe"),
            ("/g?n={{''.__CLASS__.__MRO__}}", "ssti-engine-internals"),
            ("/i.php?page=HTTP%3A%2F%2F203.0.113.66%2Fshell.TXT", "rfi-script-on-address"),
            ("/i.php?page=http://203.0.113.66/shell.php%00", "rfi-script-on-address"),
        ],
    )
    def test_the_usual_disguises_are_undone_first(self, target, rule_id):
        assert rule_id in fired(target)


class TestKnownGap:
    def test_a_plus_cannot_be_told_from_a_space_so_addition_is_not_caught(self):
        # after decoding, "+" and a space look the same, so {{7+7}} reads as {{7 7}}.
        # If this starts to be caught, move it to rule_cases.toml and update the rules comment.
        assert "ssti-arithmetic-probe" not in fired("/g?n={{7%2B7}}")
        assert "ssti-arithmetic-probe" not in fired("/g?n={{7+7}}")

    def test_the_other_operators_are_caught(self):
        for operator in ("*", "/", "-"):
            assert "ssti-arithmetic-probe" in fired(f"/g?n={{{{7{operator}7}}}}")


class TestSeverityInTheReport:
    def test_a_metadata_request_is_reported_with_its_own_label(self):
        found = detect([entry_for("/f?u=http://169.254.169.254/latest/meta-data/")], RULES)
        assert [(d.label, d.severity) for d in found] == [("ssrf", Severity.HIGH)]

    def test_the_more_serious_template_rule_wins_and_the_other_is_listed(self):
        target = "/g?n={{7*7}}{{''.__class__.__mro__}}"
        found = detect([entry_for(target)], RULES)
        assert [d.rule_id for d in found] == ["ssti-engine-internals"]
        assert found[0].also_matched == ("ssti-arithmetic-probe",)


HOSTILE = [
    "{{" * 1000,
    "{{" + "7*" * 1000,
    "{{" + " " * 1900,
    "${" * 1000,
    "{%" * 1000,
    "{{" + "a" * 2000,
    "{{" + "__" * 1000,
    "{{" + "}" * 2000,
    "http://" * 280,
    "=http://1.1.1.1/" * 120,
    "http://" + "1." * 1000,
    "http://1.1.1.1/" + "a" * 2000,
    "http://1.1.1.1/" + "a." * 1000,
    "169.254." * 250,
    "169.254.169." * 160,
    "100.100.100." * 160,
    "fd00:ec2:" * 220,
    "metadata." * 220,
    "include=" * 250,
    "?&=" * 600,
]


@pytest.mark.parametrize("text", HOSTILE, ids=[f"hostile-{n}" for n in range(len(HOSTILE))])
def test_hostile_input_is_matched_against_every_rule_quickly(text):
    started = time.process_time()
    fired("/p?" + text)
    assert time.process_time() - started < 0.25


def test_all_the_hostile_inputs_together_stay_well_under_a_second():
    started = time.process_time()
    for text in HOSTILE:
        fired("/p?" + text)
    assert time.process_time() - started < 1.0


def labelled(path):
    return {
        json.loads(row)["line"] - 1: json.loads(row)["label"]
        for row in path.read_text().splitlines()
    }


class TestTheSampleLogs:
    def test_the_demo_log_finds_every_labelled_line_of_the_new_classes_as_its_own_class(self):
        entries = parse_file(SAMPLES / "demo.log").entries
        labels = labelled(SAMPLES / "demo.labels.jsonl")
        by_line = {}
        for detection in detect_signatures(entries, RULES):
            by_line.setdefault(detection.first_index, set()).add(detection.label)
        wanted = {
            line: label
            for line, label in labels.items()
            if label in ("ssrf", "template_injection", "file_inclusion")
        }
        assert len(wanted) == 9
        assert {
            line: label for line, label in wanted.items() if label not in by_line.get(line, ())
        } == {}

    def test_no_unlabelled_line_of_the_demo_log_fires_a_new_rule(self):
        entries = parse_file(SAMPLES / "demo.log").entries
        labels = labelled(SAMPLES / "demo.labels.jsonl")
        extra = [
            d.first_index
            for d in detect_signatures(entries, RULES)
            if d.rule_id in NEW_RULES and d.first_index not in labels
        ]
        assert extra == []

    def test_the_clean_log_raises_nothing_with_the_new_rules(self):
        entries = parse_file(SAMPLES / "clean.log").entries
        assert [d for d in detect_signatures(entries, RULES) if d.rule_id in NEW_RULES] == []
