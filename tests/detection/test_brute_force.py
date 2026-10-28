"""Tests for brute-force login detection."""

import importlib.util
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.detection.behaviour import (
    ESCALATION_FACTOR,
    RULE_ID_BRUTE_FORCE,
    burst_severity,
    detect_brute_force,
)
from loginsight.detection.models import Detection, Severity
from loginsight.detection.ruleset import BruteForceSettings, RuleSet, load_rules
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file, parse_line

UTC = timezone.utc
T0 = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = BruteForceSettings()  # threshold 10, window 120 s, /login /signin /wp-login.php


def request(ip="203.0.113.5", seconds=0.0, path="/login", status=401, method="POST", when=None):
    """One request. ``seconds`` after T0 unless ``when`` is given."""
    return LogEntry(
        ip=ip,
        time=when if when is not None else T0 + timedelta(seconds=seconds),
        method=method,
        path=path,
        query="",
        protocol="HTTP/1.1",
        status=status,
        size=0,
        request=f"{method} {path} HTTP/1.1",
    )


def failures(count, spacing=1.0, start=0.0, **kwargs):
    return [request(seconds=start + n * spacing, **kwargs) for n in range(count)]


def detect(entries, **settings):
    return detect_brute_force(entries, BruteForceSettings(**settings) if settings else None)


# --- the threshold --------------------------------------------------------------------


def test_exactly_the_threshold_within_the_window_is_detected():
    (found,) = detect_brute_force(failures(10, spacing=1))
    assert found.count == 10


def test_one_failure_fewer_than_the_threshold_is_not_detected():
    assert detect_brute_force(failures(9, spacing=1)) == []


@pytest.mark.parametrize("threshold", [1, 2, 3, 5, 10, 25])
def test_the_threshold_is_respected_for_any_value(threshold):
    assert len(detect(failures(threshold), threshold=threshold)) == 1
    if threshold > 1:
        assert detect(failures(threshold - 1), threshold=threshold) == []


def test_the_window_includes_its_last_second():
    # 10 failures spanning exactly 120 s, 120/9 apart: the window is inclusive.
    assert len(detect_brute_force(failures(10, spacing=120 / 9))) == 1


def test_one_second_over_the_window_is_not_enough():
    assert detect_brute_force(failures(10, spacing=121 / 9)) == []


def test_ten_failures_thirty_seconds_apart_are_not_a_brute_force():
    assert detect_brute_force(failures(10, spacing=30)) == []


def test_slow_failures_never_add_up_however_many_there_are():
    assert detect_brute_force(failures(500, spacing=30)) == []


def test_a_burst_inside_a_long_slow_trickle_is_the_whole_run():
    slow = failures(5, spacing=60)  # 0 to 240 s: too slow on its own
    fast = failures(10, spacing=1, start=270)  # then a dense burst, 30 s after the last slow one
    (found,) = detect_brute_force(slow + fast)
    assert found.count == 15
    assert found.time == T0


def test_a_fraction_of_a_second_is_kept():
    assert len(detect(failures(10, spacing=0.0001))) == 1


def test_failures_in_the_same_second_all_count():
    entries = [request(seconds=0) for _ in range(10)]
    assert detect_brute_force(entries)[0].count == 10


# --- what counts as a failed login ----------------------------------------------------


@pytest.mark.parametrize("status", [401, 403])
def test_401_and_403_are_failures(status):
    assert len(detect_brute_force(failures(10, status=status))) == 1


@pytest.mark.parametrize(
    "status", [200, 201, 204, 301, 302, 303, 304, 400, 404, 405, 429, 500, 503, 0, 600]
)
def test_other_statuses_are_not_failures(status):
    assert detect_brute_force(failures(30, status=status)) == []


@pytest.mark.parametrize("path", ["/login", "/signin", "/wp-login.php"])
def test_each_default_login_path_counts(path):
    assert len(detect_brute_force(failures(10, path=path))) == 1


@pytest.mark.parametrize(
    "path", ["/", "/home", "/api/items", "/logout", "/login/help", "/Login", "/log-in", "/admin"]
)
def test_other_paths_do_not_count(path):
    assert detect_brute_force(failures(30, path=path)) == []


def test_the_query_string_is_not_part_of_the_path():
    entries = [
        LogEntry(**{**request(seconds=n).to_dict(), "query": f"next=/home&attempt={n}"})
        for n in range(10)
    ]
    assert len(detect_brute_force(entries)) == 1


def test_the_method_does_not_matter():
    assert len(detect_brute_force(failures(10, method="GET"))) == 1
    assert len(detect_brute_force(failures(10, method="PUT"))) == 1


def test_failures_on_different_login_paths_from_one_address_add_up():
    entries = [
        request(seconds=n, path=p) for n, p in enumerate(["/login", "/signin", "/wp-login.php"] * 4)
    ]
    (found,) = detect_brute_force(entries)
    assert found.count == 12


def test_successful_logins_between_failures_do_not_break_or_count():
    entries = []
    for n in range(10):
        entries.append(request(seconds=n * 2, status=401))
        entries.append(request(seconds=n * 2 + 1, status=302))
    (found,) = detect_brute_force(entries)
    assert (found.count, found.first_index, found.last_index) == (10, 0, 18)


def test_a_malformed_request_with_no_path_is_never_a_failure():
    entries = [
        LogEntry(**{**request(seconds=n).to_dict(), "method": "", "path": "", "request": "-"})
        for n in range(30)
    ]
    assert detect_brute_force(entries) == []


# --- addresses ------------------------------------------------------------------------


def test_two_addresses_with_six_failures_each_give_nothing():
    entries = failures(6, ip="203.0.113.1") + failures(6, ip="203.0.113.2")
    assert detect_brute_force(entries) == []


def test_interleaved_addresses_are_separated():
    entries = []
    for n in range(10):
        entries.append(request(ip="203.0.113.1", seconds=n))
        entries.append(request(ip="203.0.113.2", seconds=n + 0.5))
    found = detect_brute_force(entries)
    assert sorted(d.ip for d in found) == ["203.0.113.1", "203.0.113.2"]
    assert all(d.count == 10 for d in found)


def test_one_attacker_among_noisy_neighbours():
    entries = (
        failures(4, ip="203.0.113.1")
        + failures(12, ip="203.0.113.9")
        + failures(4, ip="203.0.113.2")
    )
    (found,) = detect_brute_force(entries)
    assert found.ip == "203.0.113.9"


def test_ipv6_addresses_are_grouped_as_given():
    assert len(detect_brute_force(failures(10, ip="2001:db8::7"))) == 1


# --- bursts ---------------------------------------------------------------------------


def test_two_bursts_from_one_address_separated_by_a_long_gap_give_two_detections():
    entries = failures(12, spacing=1, start=0) + failures(11, spacing=1, start=3600)
    first, second = detect_brute_force(entries)
    assert (first.count, second.count) == (12, 11)
    assert first.time == T0 and second.time == T0 + timedelta(seconds=3600)
    assert first.last_index < second.first_index


def test_a_gap_of_exactly_one_window_keeps_the_burst_together():
    entries = failures(10, spacing=1, start=0) + failures(10, spacing=1, start=9 + 120)
    (found,) = detect_brute_force(entries)
    assert found.count == 20


def test_two_halves_of_a_burst_are_not_enough_when_no_window_holds_enough_of_them():
    # 6 failures, then 6 more exactly one window later: one run, but never 10 in 120 s.
    entries = failures(6, spacing=1, start=0) + failures(6, spacing=1, start=5 + 120)
    assert detect_brute_force(entries) == []


def test_a_gap_just_over_one_window_splits_the_burst():
    entries = failures(10, spacing=1, start=0) + failures(10, spacing=1, start=9 + 120.5)
    assert len(detect_brute_force(entries)) == 2


def test_a_second_burst_too_small_to_count_is_not_reported_on_its_own():
    entries = failures(12, spacing=1, start=0) + failures(4, spacing=1, start=3600)
    (found,) = detect_brute_force(entries)
    assert found.count == 12


def test_three_bursts():
    entries = []
    for base in (0, 1000, 5000):
        entries += failures(10, spacing=1, start=base)
    assert [d.count for d in detect_brute_force(entries)] == [10, 10, 10]


# --- the detection --------------------------------------------------------------------


def test_the_detection_has_all_its_fields():
    entries = failures(12, spacing=94 / 11, ip="198.51.100.4")  # 12 failures over 94 s
    (found,) = detect_brute_force(entries)
    assert isinstance(found, Detection)
    assert found.rule_id == RULE_ID_BRUTE_FORCE == "behaviour-brute-force"
    assert found.label == "brute_force"
    assert found.ip == "198.51.100.4"
    assert found.time == T0
    assert (found.first_index, found.last_index, found.count) == (0, 11, 12)
    assert found.evidence == "12 failed logins in 94 s (first: POST /login)"
    assert found.also_matched == ()


def test_the_evidence_names_the_first_request():
    entries = failures(10, path="/wp-login.php", method="GET")
    assert (
        detect_brute_force(entries)[0].evidence
        == "10 failed logins in 9 s (first: GET /wp-login.php)"
    )


def test_the_evidence_seconds_are_whole_seconds_rounded_down():
    assert detect_brute_force(failures(10, spacing=0.99))[0].evidence.startswith(
        "10 failed logins in 8 s"
    )


def test_a_single_failure_is_worded_in_the_singular():
    (found,) = detect(failures(1), threshold=1)
    assert found.evidence == "1 failed login in 0 s (first: POST /login)"


def test_the_indexes_are_positions_in_the_list_given_with_other_traffic_between():
    entries = [request(path="/home", status=200, seconds=-5)]
    for n in range(10):
        entries.append(request(seconds=n))
        entries.append(request(path="/home", status=200, seconds=n + 0.5))
    (found,) = detect_brute_force(entries)
    assert (found.first_index, found.last_index, found.count) == (1, 19, 10)


def test_the_detection_is_valid_so_it_survives_its_own_checks_and_to_dict():
    (found,) = detect_brute_force(failures(10))
    assert json.loads(json.dumps(found.to_dict()))["rule_id"] == "behaviour-brute-force"


def test_the_time_is_the_first_failures_own_time_zone():
    seven_behind = timezone(timedelta(hours=-7))
    entries = [
        request(seconds=n, when=datetime(2025, 6, 1, 5, 0, n, tzinfo=seven_behind))
        for n in range(10)
    ]
    (found,) = detect_brute_force(entries)
    assert found.time == datetime(2025, 6, 1, 5, 0, 0, tzinfo=seven_behind)
    assert found.time.utcoffset() == timedelta(hours=-7)


# --- severity -------------------------------------------------------------------------


def test_a_burst_just_over_the_threshold_is_medium():
    assert detect_brute_force(failures(10))[0].severity is Severity.MEDIUM


def test_five_times_the_threshold_is_high():
    assert ESCALATION_FACTOR == 5
    assert detect_brute_force(failures(49, spacing=1))[0].severity is Severity.MEDIUM
    assert detect_brute_force(failures(50, spacing=1))[0].severity is Severity.HIGH
    assert detect_brute_force(failures(500, spacing=0.1))[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    ("count", "threshold", "expected"),
    [
        (10, 10, Severity.MEDIUM),
        (49, 10, Severity.MEDIUM),
        (50, 10, Severity.HIGH),
        (3, 3, Severity.MEDIUM),
        (15, 3, Severity.HIGH),
        (14, 3, Severity.MEDIUM),
        (5, 1, Severity.HIGH),
        (4, 1, Severity.MEDIUM),
    ],
)
def test_the_severity_function(count, threshold, expected):
    assert burst_severity(count, threshold) is expected


def test_the_severity_follows_the_configured_threshold():
    assert detect(failures(15), threshold=3)[0].severity is Severity.HIGH


# --- order, time zones, input handling ------------------------------------------------


def test_shuffled_input_gives_the_same_detections_apart_from_positions():
    ordered = failures(12, spacing=2) + failures(11, spacing=2, start=900, ip="203.0.113.9")
    shuffled = list(ordered)
    random.Random(4).shuffle(shuffled)

    def summary(found):
        return sorted((d.ip, d.count, d.time, d.evidence, d.severity) for d in found)

    assert len(detect_brute_force(shuffled)) == 2
    assert summary(detect_brute_force(shuffled)) == summary(detect_brute_force(ordered))


def test_shuffled_input_still_has_valid_indexes_even_though_the_first_failure_may_come_last():
    entries = failures(10)
    entries.reverse()  # the earliest failure is now the last entry
    (found,) = detect_brute_force(entries)
    assert found.time == T0
    assert (found.first_index, found.last_index, found.count) == (0, 9, 10)


def test_entries_in_other_time_zones_give_the_same_result_as_utc():
    zones = [timezone(timedelta(hours=h)) for h in (-7, 0, 2, 5.5)]
    utc = [request(seconds=n) for n in range(12)]
    mixed = [
        request(seconds=n, when=(T0 + timedelta(seconds=n)).astimezone(zones[n % 4]))
        for n in range(12)
    ]
    a, b = detect_brute_force(utc)[0], detect_brute_force(mixed)[0]
    assert (a.count, a.evidence, a.first_index, a.last_index) == (
        b.count,
        b.evidence,
        b.first_index,
        b.last_index,
    )
    assert a.time == b.time


def test_a_timestamp_without_a_time_zone_is_taken_to_be_utc():
    naive = [request(when=datetime(2025, 6, 1, 12, 0, n)) for n in range(10)]
    assert len(detect_brute_force(naive)) == 1


def test_a_timestamp_that_cannot_be_converted_is_a_value_error():
    far = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    with pytest.raises(ValueError, match="out of range"):
        detect_brute_force(failures(9) + [request(when=far)])


def test_equal_timestamps_keep_the_input_order():
    entries = [request(seconds=0) for _ in range(10)]
    (found,) = detect_brute_force(entries)
    assert (found.first_index, found.last_index) == (0, 9)


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_any_iterable_of_entries_works(source):
    assert len(detect_brute_force(source(failures(10)))) == 1


def test_no_entries_gives_nothing():
    assert detect_brute_force([]) == []


def test_the_input_is_not_modified():
    entries = failures(10)
    entries.reverse()
    before = [e.to_dict() for e in entries]
    detect_brute_force(entries)
    assert [e.to_dict() for e in entries] == before


def test_the_same_input_always_gives_the_same_result():
    entries = failures(12) + failures(11, ip="203.0.113.9", start=500)
    assert detect_brute_force(entries) == detect_brute_force(entries)


def test_detections_are_ordered_by_position_then_address():
    entries = failures(10, ip="203.0.113.9", start=100) + failures(10, ip="203.0.113.1", start=0)
    assert [d.ip for d in detect_brute_force(entries)] == ["203.0.113.9", "203.0.113.1"]
    both = failures(10, ip="203.0.113.9") + failures(10, ip="203.0.113.1")
    assert [d.first_index for d in detect_brute_force(both)] == [0, 10]


# --- settings -------------------------------------------------------------------------


def test_no_settings_means_the_defaults():
    assert detect_brute_force(failures(10)) == detect_brute_force(failures(10), DEFAULTS)


def test_a_lower_threshold_catches_a_smaller_burst():
    assert detect_brute_force(failures(3)) == []
    assert len(detect(failures(3), threshold=3)) == 1


def test_a_shorter_window_needs_a_faster_burst():
    assert len(detect_brute_force(failures(10, spacing=5))) == 1
    assert detect(failures(10, spacing=5), window_seconds=30) == []


def test_a_longer_window_catches_a_slower_burst():
    assert detect_brute_force(failures(10, spacing=30)) == []
    assert len(detect(failures(10, spacing=30), window_seconds=300)) == 1


def test_another_login_path_can_be_configured_and_the_defaults_then_stop_counting():
    entries = failures(10, path="/auth/sign-in")
    assert detect_brute_force(entries) == []
    assert len(detect(entries, login_paths=("/auth/sign-in",))) == 1
    assert detect(failures(10, path="/login"), login_paths=("/auth/sign-in",)) == []


def test_a_rule_set_can_supply_the_settings():
    rules = load_rules()
    assert len(detect_brute_force(failures(10), rules.brute_force)) == 1
    custom = RuleSet(brute_force=BruteForceSettings(threshold=2))
    assert len(detect_brute_force(failures(2), custom.brute_force)) == 1


# --- hostile and large input ----------------------------------------------------------


def test_a_hundred_thousand_failures_from_one_address_are_handled_quickly():
    entries = failures(100_000, spacing=0.01)
    started = time.perf_counter()
    (found,) = detect_brute_force(entries)
    assert time.perf_counter() - started < 3.0
    assert found.count == 100_000
    assert found.severity is Severity.HIGH


def test_many_addresses_with_few_failures_each_are_handled_quickly():
    entries = [request(ip=f"10.{n // 250}.{n % 250}.1", seconds=n % 50) for n in range(50_000)]
    started = time.perf_counter()
    assert detect_brute_force(entries) == []
    assert time.perf_counter() - started < 2.0


# --- generated logs -------------------------------------------------------------------


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("seed", "lines", "ratio"), [(42, 2000, 0.1), (1, 3000, 0.1), (7, 3000, 0.3), (99, 5000, 0.2)]
)
def test_every_labelled_brute_force_address_is_found_and_no_other(generator, seed, lines, ratio):
    log, labels = generator.generate(seed=seed, lines=lines, attack_ratio=ratio)
    entries = [parse_line(line) for line in log]
    labelled = {item["ip"] for item in labels if item["label"] == "brute_force"}
    assert labelled, "the generated log must contain a brute-force burst"
    found = detect_brute_force(entries)
    assert {d.ip for d in found} == labelled


def test_each_labelled_burst_is_one_detection_with_the_labelled_lines(generator):
    log, labels = generator.generate(seed=42, lines=2000, attack_ratio=0.1)
    entries = [parse_line(line) for line in log]
    truth = {}
    for item in labels:
        if item["label"] == "brute_force":
            truth.setdefault(item["ip"], []).append(item["line"] - 1)
    found = {d.ip: d for d in detect_brute_force(entries)}
    assert set(found) == set(truth)
    for ip, lines in truth.items():
        assert found[ip].count == len(lines)
        assert (found[ip].first_index, found[ip].last_index) == (min(lines), max(lines))


@pytest.mark.parametrize("seed", range(10))
def test_generated_clean_logs_have_no_brute_force(generator, seed):
    log, _ = generator.generate(seed=seed, lines=3000, attack_ratio=0)
    assert detect_brute_force([parse_line(line) for line in log]) == []


def test_the_clean_and_demo_sample_logs():
    assert detect_brute_force(parse_file(ROOT / "data" / "samples" / "clean.log").entries) == []
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = [
        json.loads(row)
        for row in (ROOT / "data" / "samples" / "demo.labels.jsonl").read_text().splitlines()
    ]
    labelled = {item["ip"] for item in labels if item["label"] == "brute_force"}
    assert {d.ip for d in detect_brute_force(entries)} == labelled
