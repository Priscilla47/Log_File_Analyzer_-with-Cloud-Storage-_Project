"""Tests for request normalisation and the signature engine."""

import importlib.util
import random
import string
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginsight.detection.models import Detection, Severity, SignatureRule
from loginsight.detection.ruleset import RuleSet, load_rules, parse_rules
from loginsight.detection.signatures import (
    MAX_DECODE_PASSES,
    MAX_TARGET_LENGTH,
    detect_signatures,
    normalise,
)
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file, parse_line

UTC = timezone.utc
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]


def entry(path="/", query="", ip="192.0.2.1", user_agent="Mozilla/5.0", referer=None, method="GET"):
    target = f"{path}?{query}" if query else path
    return LogEntry(
        ip=ip,
        time=WHEN,
        method=method,
        path=path,
        query=query,
        protocol="HTTP/1.1" if method else "",
        status=200,
        size=0,
        referer=referer,
        user_agent=user_agent,
        request=f"{method} {target} HTTP/1.1" if method else "-",
    )


def rule(
    rule_id="test-rule", pattern="union select", label="sql_injection", severity=Severity.HIGH
):
    return SignatureRule(
        id=rule_id, label=label, severity=severity, description="a test rule", pattern=pattern
    )


# --- normalise: each step -------------------------------------------------------------


def test_the_example_from_the_issue():
    assert normalise("/a%2e%2e%2fb") == "/a../b"


def test_plain_text_is_only_lower_cased():
    assert normalise("/Products/ABC?Sort=Price") == "/products/abc?sort=price"


def test_empty_text_stays_empty():
    assert normalise("") == ""


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%2e", "."),
        ("%2E", "."),
        ("%41%42", "ab"),
        ("%c3%a9", "é"),
        ("%f0%9f%98%80", "😀"),
        ("%20", " "),
        ("%3cscript%3e", "<script>"),
        ("%27%20or%20%271%27%3d%271", "' or '1'='1"),
    ],
)
def test_percent_escapes_are_decoded_as_utf8(raw, expected):
    assert normalise(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%252e", "."),  # twice encoded
        ("%25252e", "."),  # three times
        ("%25252e%25252e", ".."),
        ("%252e%252e%252f", "../"),
    ],
)
def test_up_to_three_layers_of_encoding_are_removed(raw, expected):
    assert MAX_DECODE_PASSES == 3
    assert normalise(raw) == expected


def test_a_fourth_layer_is_left_encoded():
    assert normalise("%2525252e") == "%2e"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%zz", "%zz"),
        ("%", "%"),
        ("%4", "%4"),
        ("a%", "a%"),
        ("100%", "100%"),
        ("%g1", "%g1"),
        ("%%41%", "%a%"),
        ("50%off", "50%off"),
    ],
)
def test_invalid_escapes_are_left_alone(raw, expected):
    assert normalise(raw) == expected


def test_a_valid_escape_next_to_an_invalid_one_is_still_decoded():
    assert normalise("%41%zz%42") == "a%zzb"


@pytest.mark.parametrize("raw", ["%ff", "%e9", "%c0%ae"])
def test_bytes_that_are_not_valid_utf8_become_replacement_characters_without_an_error(raw):
    assert "�" in normalise(raw)


def test_a_plus_becomes_a_space():
    assert normalise("/search?q=union+select") == "/search?q=union select"


def test_an_encoded_plus_also_ends_up_as_a_space():
    # %2B is decoded to "+" first, and every "+" then becomes a space.
    assert normalise("a%2bb") == "a b"


def test_nul_characters_are_removed_so_they_cannot_split_a_keyword():
    assert normalise("un%00ion sel%00ect") == "union select"
    assert normalise("a\x00b") == "ab"


@pytest.mark.parametrize(
    "raw", ["a  b", "a\tb", "a\n\nb", "a%0d%0ab", "a \t\n b", "a\u00a0b", "a%09%09b"]
)
def test_runs_of_whitespace_become_one_space(raw):
    assert normalise(raw) == "a b"


def test_whitespace_at_the_ends_is_kept_as_a_single_space():
    assert normalise("  a  ") == " a "


def test_the_result_is_lower_case():
    assert normalise("UnIoN SeLeCt") == "union select"
    assert normalise("%55%4e%49%4f%4e") == "union"


def test_text_beyond_the_limit_is_cut_before_decoding():
    assert MAX_TARGET_LENGTH == 2048
    assert normalise("a" * 5000) == "a" * 2048


def test_the_cut_happens_before_decoding_so_a_split_escape_is_left_alone():
    text = "a" * 2046 + "%2e"  # the limit falls in the middle of the escape
    assert normalise(text) == "a" * 2046 + "%2"


def test_an_escape_that_fits_exactly_is_decoded():
    assert normalise("a" * 2045 + "%2e") == "a" * 2045 + "."


def test_decoding_never_makes_the_text_longer():
    assert len(normalise("%41" * 5000)) <= 2048


# --- normalise: never fails -----------------------------------------------------------


def test_random_text_never_raises_and_always_satisfies_the_promises():
    rng = random.Random(7)
    alphabet = string.printable + "%%%%25+\x00\u00a0é😀�"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        result = normalise(text)
        assert len(result) <= MAX_TARGET_LENGTH
        assert "\x00" not in result
        assert "+" not in result  # every plus, even one that was encoded, becomes a space
        assert "  " not in result and "\t" not in result and "\n" not in result
        assert result == result.lower()
        assert result == normalise(text)  # deterministic


@pytest.mark.parametrize(
    "text",
    [
        "%" * 100_000,
        "%25" * 100_000,
        "<" * 100_000,
        "'" * 100_000,
        ".." * 100_000,
        "%2e%2e/" * 50_000,
        " " * 100_000,
        "\x00" * 100_000,
    ],
)
def test_hostile_text_is_normalised_quickly(text):
    started = time.perf_counter()
    result = normalise(text)
    assert time.perf_counter() - started < 0.5
    assert len(result) <= MAX_TARGET_LENGTH


# --- detect_signatures: matching ------------------------------------------------------


def test_a_matching_request_gives_one_detection_with_all_the_fields():
    entries = [entry("/ok"), entry("/search", "q=1 union select 2", ip="203.0.113.7")]
    (detection,) = detect_signatures(entries, [rule()])
    assert isinstance(detection, Detection)
    assert detection.rule_id == "test-rule"
    assert detection.label == "sql_injection"
    assert detection.severity is Severity.HIGH
    assert detection.ip == "203.0.113.7"
    assert detection.time == WHEN
    assert (detection.first_index, detection.last_index, detection.count) == (1, 1, 1)
    assert detection.evidence == "GET /search?q=1 union select 2 HTTP/1.1"
    assert detection.also_matched == ()


@pytest.mark.parametrize(
    "query",
    [
        "q=1 union select 2",
        "q=1 UNION SELECT 2",
        "q=1+union+select+2",
        "q=1%20union%20select%202",
        "q=1%20UNION%20SELECT%202",
        "q=1%2520union%2520select%25202",
        "q=1+un%00ion+sel%00ect+2",
        "q=1%0aunion%09select%0d2",
        "q=1   union     select 2",
    ],
)
def test_the_same_attack_is_found_however_it_is_written(query):
    assert len(detect_signatures([entry("/p", query)], [rule()])) == 1


@pytest.mark.parametrize(
    "query",
    ["q=union", "q=select", "q=onion select", "q=union.select", "q=union-select", "q=1", ""],
)
def test_requests_that_do_not_match_give_nothing(query):
    assert detect_signatures([entry("/p", query)], [rule()]) == []


def test_the_path_is_matched_as_well_as_the_query():
    assert len(detect_signatures([entry("/union%20select", "")], [rule()])) == 1


def test_a_pattern_can_see_where_the_path_ends_and_the_query_begins():
    only_query = rule(pattern=r"\?.*admin")
    assert len(detect_signatures([entry("/a", "x=admin")], [only_query])) == 1
    assert detect_signatures([entry("/admin", "")], [only_query]) == []


def test_only_the_path_and_query_are_matched_not_the_user_agent_or_referer():
    entries = [
        entry("/ok", user_agent="union select", referer="http://x.test/?q=union+select"),
        entry("/ok", user_agent="1 union select 2"),
    ]
    assert detect_signatures(entries, [rule()]) == []


def test_the_request_method_and_protocol_are_not_matched():
    assert detect_signatures([entry("/ok", method="UNION SELECT")], [rule()]) == []


def test_a_malformed_request_with_no_target_matches_nothing():
    assert detect_signatures([entry("", "", method="")], [rule(pattern=".")]) == []


def test_several_rules_on_one_line_give_several_detections_in_rule_order():
    rules = [
        rule("b-rule", "union"),
        rule("a-rule", "select", label="xss", severity=Severity.LOW),
        rule("never", "zzz"),
    ]
    found = detect_signatures([entry("/p", "q=union select")], rules)
    assert [d.rule_id for d in found] == ["b-rule", "a-rule"]
    assert [d.label for d in found] == ["sql_injection", "xss"]
    assert all(d.also_matched == () for d in found)


def test_detections_come_in_entry_order_then_rule_order():
    entries = [entry("/p", "q=union select"), entry("/ok"), entry("/p", "q=union select")]
    found = detect_signatures(entries, [rule("one", "union"), rule("two", "select")])
    assert [(d.first_index, d.rule_id) for d in found] == [
        (0, "one"),
        (0, "two"),
        (2, "one"),
        (2, "two"),
    ]


def test_detections_follow_the_input_order_not_the_order_of_addresses_or_times():
    late = LogEntry(**{**entry("/p", "union select", ip="203.0.113.9").to_dict(), "time": WHEN})
    entries = [
        entry("/p", "union select", ip="203.0.113.9"),
        entry("/p", "union select", ip="192.0.2.1"),
        entry("/p", "union select", ip="198.51.100.5"),
        late,
    ]
    found = detect_signatures(entries, [rule()])
    assert [d.first_index for d in found] == [0, 1, 2, 3]
    assert [d.ip for d in found] == ["203.0.113.9", "192.0.2.1", "198.51.100.5", "203.0.113.9"]


def test_the_index_is_the_position_in_the_input_whatever_matched_before():
    entries = [entry("/ok")] * 5 + [entry("/p", "union select")]
    assert detect_signatures(entries, [rule()])[0].first_index == 5


def test_each_detection_carries_the_ip_and_time_of_its_own_request():
    other_time = datetime(2025, 6, 1, 13, 30, tzinfo=UTC)
    first = entry("/p", "union select", ip="192.0.2.1")
    second = LogEntry(**{**first.to_dict(), "ip": "198.51.100.9", "time": other_time})
    found = detect_signatures([first, second], [rule()])
    assert [(d.ip, d.time) for d in found] == [("192.0.2.1", WHEN), ("198.51.100.9", other_time)]


def test_the_evidence_is_the_raw_request_cut_to_200_characters():
    long_query = "union select " + "x" * 500
    (detection,) = detect_signatures([entry("/p", long_query)], [rule()])
    assert len(detection.evidence) == 200
    assert detection.evidence.startswith("GET /p?union select xxx")


def test_the_evidence_is_the_request_as_logged_not_the_normalised_text():
    (detection,) = detect_signatures([entry("/p", "q=UNION%20SELECT")], [rule()])
    assert detection.evidence == "GET /p?q=UNION%20SELECT HTTP/1.1"


def test_a_detection_inherits_the_label_and_severity_of_its_rule():
    for label, severity in (("xss", Severity.LOW), ("command_injection", Severity.CRITICAL)):
        (detection,) = detect_signatures(
            [entry("/p", "a")], [rule(pattern="a", label=label, severity=severity)]
        )
        assert (detection.label, detection.severity) == (label, severity)


# --- detect_signatures: inputs --------------------------------------------------------


def test_no_entries_gives_an_empty_list():
    assert detect_signatures([], [rule()]) == []


def test_no_rules_gives_an_empty_list():
    assert detect_signatures([entry("/p", "union select")], []) == []
    assert detect_signatures([entry("/p", "union select")], RuleSet()) == []


def test_a_ruleset_a_list_a_tuple_and_a_generator_of_rules_all_work():
    entries = [entry("/p", "union select")]
    ruleset = RuleSet(signatures=(rule(),))
    expected = detect_signatures(entries, [rule()])
    assert len(expected) == 1
    assert detect_signatures(entries, ruleset) == expected
    assert detect_signatures(entries, (rule(),)) == expected
    assert detect_signatures(entries, (r for r in [rule()])) == expected


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_entries_can_be_any_iterable(source):
    entries = [entry("/ok"), entry("/p", "union select")]
    assert len(detect_signatures(source(entries), [rule()])) == 1


def test_a_loaded_rules_file_can_be_used_directly():
    rules = parse_rules(
        "[[signature]]\nid = 'x-rule'\nlabel = 'xss'\nseverity = 'low'\n"
        "description = 'd'\npattern = '<script'\n"
    )
    found = detect_signatures([entry("/p", "q=%3Cscript%3E")], rules)
    assert [d.rule_id for d in found] == ["x-rule"]


def test_the_input_is_not_modified():
    entries = [entry("/p", "q=UNION%20SELECT")]
    before = [e.to_dict() for e in entries]
    detect_signatures(entries, [rule()])
    assert [e.to_dict() for e in entries] == before


def test_the_same_input_always_gives_the_same_result():
    entries = [entry("/p", "union select"), entry("/q", "UNION+SELECT")]
    rules = [rule("a", "union"), rule("b", "select")]
    assert detect_signatures(entries, rules) == detect_signatures(entries, rules)


# --- detect_signatures: limits and hostile input --------------------------------------


def test_an_attack_well_inside_the_first_2048_characters_is_found():
    assert len(detect_signatures([entry("/p", "a" * 1000 + "union select")], [rule()])) == 1


def test_an_attack_that_ends_exactly_at_the_limit_is_found():
    prefix = "a" * (MAX_TARGET_LENGTH - len("/p?") - len("union select"))
    assert len(detect_signatures([entry("/p", prefix + "union select")], [rule()])) == 1


def test_an_attack_that_starts_after_the_limit_is_not_seen_a_documented_limit():
    assert detect_signatures([entry("/p", "a" * 2100 + "union select")], [rule()]) == []


def test_a_huge_request_is_handled_quickly():
    started = time.perf_counter()
    found = detect_signatures([entry("/p", "union select " + "x" * 100_000)], [rule()])
    assert len(found) == 1
    assert time.perf_counter() - started < 0.5


@pytest.mark.parametrize(
    "junk", ["%" * 2048, "<" * 2048, "'" * 2048, "../" * 700, "%2e%2e%2f" * 220]
)
def test_adversarial_requests_finish_in_well_under_a_second_with_the_default_rules(junk):
    rules = load_rules()
    started = time.perf_counter()
    for _ in range(20):
        detect_signatures([entry("/p", junk)], rules)
    assert time.perf_counter() - started < 1.0


def test_the_default_rules_run_on_a_realistic_log():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    started = time.perf_counter()
    found = detect_signatures(entries, load_rules())
    assert time.perf_counter() - started < 1.0
    assert all(isinstance(d, Detection) for d in found)


# --- speed (run with: pytest -m slow -s) ----------------------------------------------

LINES = 100_000
MIN_LINES_PER_SECOND = 5_000


@pytest.mark.slow
def test_signature_detection_speed_on_100_000_generated_lines():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    lines, _ = generator.generate(seed=42, lines=LINES)
    entries = [parse_line(line) for line in lines]
    rules = load_rules()

    started = time.perf_counter()
    found = detect_signatures(entries, rules)
    elapsed = time.perf_counter() - started

    throughput = LINES / elapsed
    print(
        f"\nscanned {LINES:,} lines with {len(rules.signatures)} rule(s): {throughput:,.0f} lines/s"
    )
    assert len(entries) == LINES
    assert isinstance(found, list)
    assert throughput >= MIN_LINES_PER_SECOND
