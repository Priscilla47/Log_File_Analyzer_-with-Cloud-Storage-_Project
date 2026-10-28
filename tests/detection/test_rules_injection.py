"""Tests for the default SQL injection, XSS, path traversal and command injection rules.

The per-rule attack and near-miss cases live in ``rule_cases.toml`` and are checked by
``test_rule_cases.py``. This file holds what is not per rule: the agreed severities, harmless
requests that no rule may fire on, known gaps, and the labelled sample logs.
"""

import importlib.util
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from loginsight.detection.models import Severity
from loginsight.detection.ruleset import load_rules
from loginsight.detection.signatures import detect_signatures, normalise
from loginsight.parsing.parser import parse_file, parse_line

ROOT = Path(__file__).resolve().parents[2]
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)
RULES = {rule.id: rule for rule in load_rules().signatures}
CLASSES = {
    "sql_injection": ("sqli-", Severity.HIGH, 3),
    "xss": ("xss-", Severity.MEDIUM, 2),
    "path_traversal": ("traversal-", Severity.HIGH, 2),
    "command_injection": ("cmdi-", Severity.CRITICAL, 2),
}

# --- known gaps -----------------------------------------------------------------------

# Attacks written in a way the rules cannot see. They are pinned as expected failures, so if a
# later change fixes one, the test fails and the entry moves to rule_cases.toml.
KNOWN_GAPS = [
    ("sqli-union-select", "/i?id=1 uni/**/on select 1"),
    ("traversal-dotdot", "/g?f=..%c0%af..%c0%afetc/passwd"),
    ("xss-script-tag", "/s?q=%u003cscript%u003e"),
    ("sqli-tautology", "/i?id=1 or true"),
]

# --- harmless requests: no rule may fire ----------------------------------------------

HARMLESS = [
    # the look-alikes the issue asks for
    "/search?q=select+shoes",
    "/search?q=drop+shipping+rates",
    "/search?q=union+jack+flag",
    "/download?file=report.pdf",
    "/download?file=annual-report-2025.pdf",
    "/blog/how-to-use-script-tags-in-email",
    "/docs/etc-hosts-explained",
    "/products?sort=price&order=desc",
    "/search?q=cat+food",
    "/help?topic=password-reset",
    "/v1;x",
    "/search?q=o'brien",
    # quotes and apostrophes in ordinary text
    "/search?q=rock'n'roll",
    "/search?q=it's+a+trap",
    "/search?q=men's+shoes",
    "/search?q=kids'+toys",
    "/search?q=don't+stop",
    '/search?q="red"+or+"blue"',
    "/search?q=what's+new+--+week+3",
    # query strings with several parameters and path parameters
    "/products/12?ref=home&utm_source=a&utm_medium=b",
    "/page;jsessionid=ABC123",
    "/docs/api/v2/users;type=json",
    "/a?x=1&&y=2",
    "/p?utm=a&&b=c",
    "/a?x=1;y=2",
    "/p?x=1;2;3",
    "/a?x=1&id=5",
    "/a?x=1&&id=5",
    "/a;id=5",
    "/p?x=1&or=2",
    "/p?and=1&or=2",
    "/a?tags=red|blue|green",
    "/api?ids=1,2,3&fields=a|b",
    "/profile?online=1&onload=yes",
    "/page?onclick=1",
    "/api?x=1&onerror=0",
    # words that are also commands, keywords and handlers
    "/search?q=how+to+kill+a+process+in+linux",
    "/search?q=id+card",
    "/search?q=sh+script",
    "/search?q=ls+command",
    "/search?q=etc+hosts",
    "/search?q=sleep+well",
    "/search?q=sleep+8+hours",
    "/search?q=benchmark+results",
    "/search?q=information+schema+design",
    "/search?q=cmd+line+tools",
    "/search?q=dev+tcp",
    "/search?q=nc+cable",
    "/search?q=bash+scripting+tutorial",
    "/search?q=php+tutorial",
    "/search?q=data+science",
    "/search?q=file+upload+guide",
    "/search?q=zip+code",
    "/search?q=select+your+size",
    "/search?q=union+of+soviet+republics",
    "/search?q=drop+down+menu",
    "/search?q=drop+table+tennis",
    "/search?q=black+and+white",
    "/search?q=salt+and+pepper",
    "/search?q=online+shop",
    "/blog/sql-injection-explained",
    "/blog/using-env-files",
    "/docs/select-statement",
    # paths, dots and punctuation
    "/files/report-2025.pdf",
    "/img/photo.jpg?w=100&h=100",
    "/api/items?page=2&limit=20",
    "/news/2025/10/27/market-update",
    "/path/with.dots/file.name.ext",
    "/a..b/c",
    "/v1.2..3/x",
    "/download?file=my..report.pdf",
    "/search?q=wait...",
    "/search?q=loading...",
    "/bin/shop",
    "/products/bin/shoes",
    "/p?path=/home/user/docs",
    "/p?file=/var/www/html/index.html",
    "/p?next=/account/orders",
    "/p?ref=https://example.test/a?b=c",
    # markup and operators that are not attacks
    "/search?q=%3Cb%3Ebold%3C/b%3E",
    "/p?html=%3Cp%3Ehello%3C/p%3E",
    "/search?q=a<b",
    "/search?q=5>3",
    "/p?q=a%3Cb%26%26c%3Ed",
    "/calc?expr=2*3=6",
    "/search?q=a=b",
    "/search?q=1+or+2",
    "/search?q=javascript:+the+good+parts",
    "/p?q=C%2B%2B+tutorial",
    "/p?q=100%25+cotton",
    "/p?q=%E4%BD%A0%E5%A5%BD",
    # query languages and JSON in the URL
    '/api?filter={"or":[{"a":1}],"and":[{"b":2}]}',
    "/api?$filter=Name eq 'Bob' and Age gt 30",
    "/api?q=name='Bob'",
    "/api?sort=-created,+name",
    "/cal?d=2025-10-27&t=10:30",
    "/cart?item=cat&item=dog",
    # plain pages
    "/",
    "/home",
    "/login",
    "/api/users/42",
    "/static/app.css",
    "/favicon.ico",
    "/robots.txt",
    "/img/a.jpg",
]

# Each rule also has its own near misses: requests that share its words but are not attacks.


def matches(rule_id, target):
    return bool(RULES[rule_id].compiled.search(normalise(target)))


def fired(target):
    text = normalise(target)
    return sorted(rule_id for rule_id, rule in RULES.items() if rule.compiled.search(text))


# --- the rule set itself --------------------------------------------------------------


@pytest.mark.parametrize(("label", "expected"), list(CLASSES.items()))
def test_each_class_has_enough_rules_with_the_agreed_severity(label, expected):
    prefix, severity, minimum = expected
    rules = [rule for rule in RULES.values() if rule.id.startswith(prefix)]
    assert len(rules) >= minimum
    assert all(rule.label == label for rule in rules)
    assert all(rule.severity is severity for rule in rules)


def test_rule_ids_are_unique_and_descriptions_say_something():
    ids = [rule.id for rule in load_rules().signatures]
    assert len(ids) == len(set(ids))
    assert all(len(rule.description) > 20 for rule in RULES.values())


# --- harmless requests are left alone -------------------------------------------------


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_no_rule(target):
    assert fired(target) == []


@pytest.mark.parametrize("target", HARMLESS[:30])
def test_harmless_requests_stay_quiet_when_url_encoded_too(target):
    assert fired(quote(target, safe="")) == []


def test_there_are_plenty_of_harmless_examples():
    assert len(HARMLESS) >= 90


# --- known gaps -----------------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "target"), KNOWN_GAPS)
@pytest.mark.xfail(strict=True, reason="known gap: needs decoding or parsing beyond the spec")
def test_known_gap_is_not_caught_yet(rule_id, target):
    assert matches(rule_id, target)


# --- the labelled sample logs ---------------------------------------------------------


def labelled(path):
    return {
        json.loads(row)["line"] - 1: json.loads(row)["label"]
        for row in path.read_text().splitlines()
    }


def test_the_clean_sample_log_raises_nothing():
    entries = parse_file(ROOT / "data" / "samples" / "clean.log").entries
    assert detect_signatures(entries, load_rules()) == []


def test_the_demo_log_flags_no_unlabelled_line():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    found = detect_signatures(entries, load_rules())
    assert found, "the demo log has attacks, so something must be found"
    assert [d.first_index for d in found if d.first_index not in labels] == []


def test_the_demo_log_finds_every_labelled_line_of_these_four_classes_as_its_own_class():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    by_line = {}
    for detection in detect_signatures(entries, load_rules()):
        by_line.setdefault(detection.first_index, set()).add(detection.label)
    wanted = {line: label for line, label in labels.items() if label in CLASSES}
    assert len(wanted) >= 20
    assert {
        line: label for line, label in wanted.items() if label not in by_line.get(line, ())
    } == {}


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_generated_attack_logs_are_found_class_by_class_with_no_false_alarm(generator, seed):
    lines, labels = generator.generate(seed=seed, lines=3000, attack_ratio=0.1)
    entries = [parse_line(line) for line in lines]
    truth = {item["line"] - 1: item["label"] for item in labels}
    detected = {}
    for detection in detect_signatures(entries, load_rules()):
        detected.setdefault(detection.first_index, set()).add(detection.label)
    missed = [
        (line, label)
        for line, label in truth.items()
        if label in CLASSES and label not in detected.get(line, ())
    ]
    false_alarms = [line for line in detected if line not in truth]
    assert missed == []
    assert false_alarms == []
    assert Counter(truth.values())["sql_injection"] > 0


@pytest.mark.parametrize("seed", range(10))
def test_generated_clean_logs_raise_nothing(generator, seed):
    lines, _ = generator.generate(seed=seed, lines=2000, attack_ratio=0)
    entries = [parse_line(line) for line in lines]
    assert detect_signatures(entries, load_rules()) == []


# --- hostile input --------------------------------------------------------------------

HOSTILE = [
    "'" + " '" * 1000,
    "'" + "/**/" * 500,
    "'" + ")" * 2000,
    "' or " * 400,
    "union" + "/**/" * 500,
    "union " * 340,
    "<a " * 680,
    "<a " + "x" * 2040,
    ".." * 1000,
    "../" * 680,
    "..;" * 680,
    ";" * 2000,
    "|" * 2000,
    "`" * 2000,
    "$(" * 1000,
    "&&" * 1000,
    "/" * 2000,
    "/etc/" * 400,
    "/proc/self/" * 180,
    "nc " + "-a " * 680,
    "bash " * 400,
    "cmd " * 500,
    "%" * 2000,
    "'<;|`$(../" * 220,
]


@pytest.mark.parametrize("text", HOSTILE, ids=[f"hostile-{n}" for n in range(len(HOSTILE))])
def test_hostile_input_is_matched_against_every_rule_quickly(text):
    started = time.perf_counter()
    fired("/p?" + text)
    assert time.perf_counter() - started < 0.25


def test_all_the_hostile_inputs_together_stay_well_under_a_second():
    started = time.perf_counter()
    for text in HOSTILE:
        fired("/p?" + text)
    assert time.perf_counter() - started < 1.0
