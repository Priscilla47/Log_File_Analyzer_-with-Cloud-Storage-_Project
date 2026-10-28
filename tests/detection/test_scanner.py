"""Tests for scanner detection: bursts of distinct missing pages, and known scanning tools."""

import importlib.util
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.detection.behaviour import (
    RULE_ID_SCANNER_BURST,
    RULE_ID_SCANNER_TOOL,
    detect_scanners,
)
from loginsight.detection.models import Detection, Severity
from loginsight.detection.ruleset import ScannerSettings, load_rules
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file, parse_line

UTC = timezone.utc
T0 = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
DEFAULTS = ScannerSettings()  # 15 distinct 404 paths in 60 s, eight known tools


def request(
    ip="203.0.113.5",
    seconds=0.0,
    path="/missing",
    status=404,
    agent=BROWSER,
    method="GET",
    query="",
    when=None,
):
    target = f"{path}?{query}" if query else path
    return LogEntry(
        ip=ip,
        time=when if when is not None else T0 + timedelta(seconds=seconds),
        method=method,
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=status,
        size=0,
        user_agent=agent,
        request=f"{method} {target} HTTP/1.1",
    )


def misses(count, spacing=1.0, start=0.0, prefix="/p", **kwargs):
    """``count`` requests for ``count`` different missing paths."""
    return [
        request(seconds=start + n * spacing, path=f"{prefix}{n}", **kwargs) for n in range(count)
    ]


def burst(found):
    return [d for d in found if d.rule_id == RULE_ID_SCANNER_BURST]


def tool(found):
    return [d for d in found if d.rule_id == RULE_ID_SCANNER_TOOL]


def detect(entries, **settings):
    return detect_scanners(entries, ScannerSettings(**settings) if settings else None)


# --- the burst rule: the threshold ----------------------------------------------------


def test_exactly_the_threshold_of_distinct_missing_paths_is_detected():
    (found,) = detect_scanners(misses(15, spacing=1))
    assert found.rule_id == RULE_ID_SCANNER_BURST


def test_one_path_fewer_than_the_threshold_is_not_detected():
    assert detect_scanners(misses(14, spacing=1)) == []


@pytest.mark.parametrize("threshold", [1, 2, 5, 15, 40])
def test_the_threshold_is_respected_for_any_value(threshold):
    assert len(detect(misses(threshold), threshold=threshold)) == 1
    if threshold > 1:
        assert detect(misses(threshold - 1), threshold=threshold) == []


def test_the_window_includes_its_last_second():
    assert len(burst(detect_scanners(misses(15, spacing=60 / 14)))) == 1


def test_one_second_over_the_window_is_not_enough():
    assert detect_scanners(misses(15, spacing=61 / 14)) == []


def test_fifteen_paths_ten_seconds_apart_are_too_slow():
    assert detect_scanners(misses(15, spacing=10)) == []


def test_a_slow_trickle_never_adds_up_however_long_it_is():
    assert detect_scanners(misses(400, spacing=10)) == []


def test_a_dense_window_that_starts_in_the_middle_of_a_run_is_found():
    # Threshold 3, window 60 s: only the paths at 50, 90 and 100 fit in one window.
    entries = [request(seconds=s, path=f"/p{s}") for s in (0, 50, 90, 100)]
    (found,) = detect(entries, threshold=3, window_seconds=60)
    assert found.count == 4


def test_distinct_paths_in_separate_runs_do_not_add_up():
    # /a and /b are close together, /c comes 90 s later: a new run, so never 3 in one run.
    entries = [request(seconds=s, path=p) for s, p in [(0, "/a"), (10, "/b"), (100, "/c")]]
    assert detect(entries, threshold=3, window_seconds=60) == []


def test_a_path_seen_again_inside_the_window_counts_once_even_after_the_window_slides():
    # /a at 0 and 50, /b at 55, /c at 100: the window [50, 110] holds /a, /b, /c.
    entries = [
        request(seconds=s, path=p) for s, p in [(0, "/a"), (50, "/a"), (55, "/b"), (100, "/c")]
    ]
    (found,) = detect(entries, threshold=3, window_seconds=60)
    assert found.count == 4


# --- the burst rule: distinct paths ---------------------------------------------------


def test_the_same_missing_path_a_hundred_times_is_not_a_scan():
    assert detect_scanners([request(seconds=n * 0.1, path="/old-link") for n in range(100)]) == []


def test_repeats_do_not_help_a_burst_that_is_one_path_short():
    entries = misses(14, spacing=0.5) + [
        request(seconds=7 + n * 0.1, path="/p0") for n in range(80)
    ]
    assert detect_scanners(entries) == []


def test_repeats_are_counted_as_lines_once_a_burst_is_found():
    entries = misses(15, spacing=1) + [request(seconds=15, path="/p0")] * 5
    (found,) = detect_scanners(entries)
    assert found.count == 20
    assert found.evidence.startswith("15 distinct missing paths")


def test_the_query_string_is_not_part_of_the_path():
    same = [request(seconds=n, path="/search", query=f"q={n}") for n in range(40)]
    assert detect_scanners(same) == []
    different = [request(seconds=n, path=f"/search{n}", query="q=1") for n in range(15)]
    assert len(detect_scanners(different)) == 1


def test_paths_that_differ_only_in_case_are_different_paths():
    entries = [request(seconds=n, path="/Admin" if n % 2 else "/admin") for n in range(40)]
    assert detect_scanners(entries) == []
    assert detect(entries, threshold=2) != []


def test_a_404_for_a_malformed_request_with_no_path_is_ignored():
    entries = [
        LogEntry(**{**request(seconds=n).to_dict(), "method": "", "path": "", "request": "-"})
        for n in range(40)
    ]
    assert detect_scanners(entries) == []


# --- the burst rule: what counts ------------------------------------------------------


def test_only_status_404_counts():
    for status in (200, 301, 302, 304, 400, 401, 403, 410, 500, 503, 0):
        assert burst(detect_scanners(misses(30, status=status))) == [], status


def test_successful_pages_between_missing_ones_are_ignored_and_do_not_break_the_run():
    entries = []
    for n in range(15):
        entries.append(request(seconds=n * 2, path=f"/missing{n}"))
        entries.append(request(seconds=n * 2 + 1, path="/home", status=200))
    (found,) = detect_scanners(entries)
    assert (found.count, found.first_index, found.last_index) == (15, 0, 28)


def test_the_method_does_not_matter():
    assert len(detect_scanners(misses(15, method="POST"))) == 1
    assert len(detect_scanners(misses(15, method="HEAD"))) == 1


# --- the burst rule: addresses and bursts ---------------------------------------------


def test_missing_pages_from_different_addresses_are_not_combined():
    entries = misses(8, ip="203.0.113.1") + misses(8, ip="203.0.113.2", prefix="/q")
    assert detect_scanners(entries) == []


def test_two_addresses_each_scanning_give_two_detections():
    entries = []
    for n in range(15):
        entries.append(request(ip="203.0.113.1", seconds=n, path=f"/a{n}"))
        entries.append(request(ip="203.0.113.2", seconds=n + 0.5, path=f"/b{n}"))
    assert sorted(d.ip for d in detect_scanners(entries)) == ["203.0.113.1", "203.0.113.2"]


def test_one_scanner_among_ordinary_visitors_with_a_few_misses():
    entries = (
        misses(3, ip="203.0.113.1") + misses(20, ip="203.0.113.9") + misses(3, ip="203.0.113.2")
    )
    (found,) = detect_scanners(entries)
    assert found.ip == "203.0.113.9"


def test_two_scans_from_one_address_with_a_long_gap_give_two_detections():
    entries = misses(16, spacing=1, start=0) + misses(15, spacing=1, start=3600, prefix="/z")
    first, second = burst(detect_scanners(entries))
    assert (first.count, second.count) == (16, 15)
    assert second.time == T0 + timedelta(seconds=3600)


def test_a_gap_of_exactly_one_window_keeps_the_scan_together():
    entries = misses(15, spacing=1, start=0) + misses(15, spacing=1, start=14 + 60, prefix="/z")
    (found,) = burst(detect_scanners(entries))
    assert found.count == 30


def test_a_gap_just_over_one_window_splits_it():
    entries = misses(15, spacing=1, start=0) + misses(15, spacing=1, start=14 + 60.5, prefix="/z")
    assert len(burst(detect_scanners(entries))) == 2


def test_the_same_paths_requested_again_after_a_long_gap_are_a_new_scan():
    entries = misses(15, start=0) + misses(15, start=1000)  # the very same 15 paths twice
    assert len(burst(detect_scanners(entries))) == 2


# --- the burst detection --------------------------------------------------------------


def test_the_burst_detection_has_all_its_fields():
    entries = misses(47, spacing=52 / 46, ip="198.51.100.9", prefix="/x")
    (found,) = detect_scanners(entries)
    assert isinstance(found, Detection)
    assert found.rule_id == "behaviour-scanner-burst"
    assert found.label == "scanner"
    assert found.ip == "198.51.100.9"
    assert found.time == T0
    assert (found.first_index, found.last_index, found.count) == (0, 46, 47)
    assert found.evidence == "47 distinct missing paths in 52 s (first: GET /x0)"
    assert found.also_matched == ()


def test_the_evidence_names_the_first_request_with_its_method():
    entries = misses(15, method="HEAD", prefix="/admin")
    assert (
        detect_scanners(entries)[0].evidence
        == "15 distinct missing paths in 14 s (first: HEAD /admin0)"
    )


def test_the_burst_severity_is_medium_and_high_at_five_times_the_threshold():
    assert detect_scanners(misses(15))[0].severity is Severity.MEDIUM
    assert detect_scanners(misses(74, spacing=0.5))[0].severity is Severity.MEDIUM
    assert detect_scanners(misses(75, spacing=0.5))[0].severity is Severity.HIGH


def test_the_severity_depends_on_distinct_paths_not_on_repeats():
    entries = misses(15, spacing=0.5) + [
        request(seconds=8 + n * 0.01, path="/p0") for n in range(200)
    ]
    (found,) = detect_scanners(entries)
    assert found.count == 215 and found.severity is Severity.MEDIUM


def test_the_severity_follows_the_configured_threshold():
    assert detect(misses(15), threshold=3)[0].severity is Severity.HIGH


def test_the_indexes_are_positions_in_the_list_given():
    entries = [request(path="/home", status=200, seconds=-9)]
    for n in range(15):
        entries.append(request(seconds=n, path=f"/m{n}"))
        entries.append(request(seconds=n + 0.5, path="/home", status=200))
    (found,) = detect_scanners(entries)
    assert (found.first_index, found.last_index) == (1, 29)


def test_the_time_is_the_first_requests_own_time_zone():
    seven_behind = timezone(timedelta(hours=-7))
    entries = [
        request(path=f"/p{n}", when=datetime(2025, 6, 1, 5, 0, n, tzinfo=seven_behind))
        for n in range(15)
    ]
    (found,) = detect_scanners(entries)
    assert found.time.utcoffset() == timedelta(hours=-7)
    assert found.time == datetime(2025, 6, 1, 5, 0, 0, tzinfo=seven_behind)


def test_the_detections_pass_their_own_checks_and_serialise():
    for found in detect_scanners(misses(15) + [request(agent="sqlmap/1.7", status=200)]):
        assert json.loads(json.dumps(found.to_dict()))["label"] == "scanner"


# --- the tool rule --------------------------------------------------------------------


def test_a_known_scanner_user_agent_gives_one_detection_with_the_request_count():
    entries = [
        request(seconds=n, path=f"/p{n}", status=200, agent="sqlmap/1.7.2#stable")
        for n in range(12)
    ]
    (found,) = detect_scanners(entries)
    assert found.rule_id == "behaviour-scanner-tool"
    assert found.label == "scanner"
    assert found.severity is Severity.LOW
    assert found.count == 12
    assert (found.first_index, found.last_index) == (0, 11)
    assert found.time == T0
    assert found.evidence == "12 requests with the 'sqlmap' user agent (first: GET /p0 HTTP/1.1)"


def test_one_request_is_worded_in_the_singular():
    (found,) = detect_scanners([request(status=200, agent="Nikto/2.1.6")])
    assert found.evidence == "1 request with the 'nikto' user agent (first: GET /missing HTTP/1.1)"


@pytest.mark.parametrize(
    "tool_name", ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wfuzz", "nuclei"]
)
def test_every_default_tool_is_recognised(tool_name):
    found = tool(detect_scanners([request(status=200, agent=f"{tool_name}/1.0")]))
    assert [d.evidence.split("'")[1] for d in found] == [tool_name]


@pytest.mark.parametrize(
    "agent",
    [
        "SQLMAP/1.7",
        "SqlMap",
        "Mozilla/5.0 (compatible; Nikto/2.1.6)",
        "xx-sqlmap-xx",
        "NMAP Scripting Engine",
    ],
)
def test_the_match_ignores_case_and_looks_anywhere_in_the_user_agent(agent):
    assert len(tool(detect_scanners([request(status=200, agent=agent)]))) == 1


@pytest.mark.parametrize(
    "agent",
    [
        BROWSER,
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148 Safari/604.1",
        "curl/8.5.0",
        "python-requests/2.31.0",
        "Wget/1.21",
        "",
        "-",
    ],
)
def test_ordinary_user_agents_never_match(agent):
    assert tool(detect_scanners([request(status=200, agent=agent)])) == []


def test_a_missing_user_agent_never_matches():
    assert detect_scanners([request(status=200, agent=None)]) == []


def test_it_does_not_matter_what_the_response_was():
    for status in (200, 301, 401, 404, 500):
        assert len(tool(detect_scanners([request(status=status, agent="nikto")]))) == 1


def test_two_addresses_with_the_same_tool_give_two_detections():
    entries = [request(ip="203.0.113.1", agent="nikto"), request(ip="203.0.113.2", agent="nikto")]
    assert sorted(d.ip for d in tool(detect_scanners(entries))) == ["203.0.113.1", "203.0.113.2"]


def test_one_address_with_two_tools_gives_two_detections():
    entries = [
        request(seconds=0, agent="sqlmap"),
        request(seconds=1, agent="nikto"),
        request(seconds=2, agent="sqlmap"),
    ]
    found = tool(detect_scanners(entries))
    assert sorted((d.evidence.split("'")[1], d.count) for d in found) == [
        ("nikto", 1),
        ("sqlmap", 2),
    ]


def test_a_user_agent_naming_two_tools_is_counted_once_for_the_first_in_the_settings_order():
    found = tool(detect_scanners([request(agent="nikto sqlmap")]))
    assert len(found) == 1
    assert found[0].evidence.split("'")[1] == "sqlmap"  # sqlmap comes first in the defaults


def test_the_tool_detection_is_at_the_first_request_even_when_the_input_is_shuffled():
    entries = [request(seconds=s, agent="nikto", path=f"/p{s}") for s in (30, 10, 20)]
    (found,) = tool(detect_scanners(entries))
    assert found.time == T0 + timedelta(seconds=10)
    assert found.evidence.endswith("(first: GET /p10 HTTP/1.1)")
    assert (found.first_index, found.last_index, found.count) == (0, 2, 3)


def test_a_long_request_in_the_evidence_is_cut_to_200_characters():
    (found,) = detect_scanners([request(status=200, agent="nikto", path="/" + "a" * 500)])
    quoted = found.evidence.split("(first: ", 1)[1]
    assert quoted.endswith(")")
    assert len(quoted) == 200 + 1  # 200 characters of the request, then the closing bracket
    assert quoted.startswith("GET /aaaa")


def test_the_list_of_tools_comes_from_the_settings():
    assert tool(detect([request(agent="evilbot/1.0")])) == []
    assert len(tool(detect([request(agent="evilbot/1.0")], user_agents=("evilbot",)))) == 1
    assert tool(detect([request(agent="sqlmap")], user_agents=("evilbot",))) == []


def test_an_empty_tool_list_switches_the_tool_rule_off():
    assert detect([request(agent="sqlmap")], user_agents=()) == []


def test_an_empty_text_in_the_tool_list_is_ignored_not_a_match_for_everything():
    assert detect([request(agent=BROWSER)], user_agents=("",)) == []
    assert detect([request(agent=BROWSER)], user_agents=("", "nikto")) == []


# --- both rules together --------------------------------------------------------------


def test_a_scanner_that_is_a_known_tool_and_a_burst_gets_both_detections_in_order():
    entries = misses(20, agent="nikto/2.1.6")
    found = detect_scanners(entries)
    assert [d.rule_id for d in found] == [RULE_ID_SCANNER_BURST, RULE_ID_SCANNER_TOOL]
    assert found[0].severity is Severity.MEDIUM and found[1].severity is Severity.LOW


def test_detections_are_ordered_by_position_then_address_then_rule():
    entries = [request(ip="203.0.113.9", agent="nikto", path="/a", status=200)] + misses(
        15, ip="203.0.113.1"
    )
    assert [(d.first_index, d.ip, d.rule_id) for d in detect_scanners(entries)] == [
        (0, "203.0.113.9", RULE_ID_SCANNER_TOOL),
        (1, "203.0.113.1", RULE_ID_SCANNER_BURST),
    ]


def test_detections_follow_position_even_when_an_address_was_seen_earlier():
    early = [request(ip="203.0.113.1", path="/only-one")]
    entries = (
        early
        + misses(15, ip="203.0.113.2", start=1000)
        + misses(15, ip="203.0.113.1", start=2000, prefix="/z")
    )
    assert [d.ip for d in detect_scanners(entries)] == ["203.0.113.2", "203.0.113.1"]


# --- order, time zones, input handling ------------------------------------------------


def test_shuffled_input_gives_the_same_detections_apart_from_positions():
    ordered = misses(20, spacing=1) + misses(
        18, spacing=1, start=900, ip="203.0.113.9", prefix="/q"
    )
    shuffled = list(ordered)
    random.Random(4).shuffle(shuffled)

    def summary(found):
        return sorted((d.rule_id, d.ip, d.count, d.time, d.evidence, d.severity) for d in found)

    assert len(detect_scanners(shuffled)) == 2
    assert summary(detect_scanners(shuffled)) == summary(detect_scanners(ordered))


def test_the_earliest_request_may_come_last_and_the_indexes_stay_valid():
    entries = misses(15)
    entries.reverse()
    (found,) = detect_scanners(entries)
    assert (found.first_index, found.last_index, found.time) == (0, 14, T0)
    assert found.evidence.endswith("(first: GET /p0)")


def test_entries_in_other_time_zones_give_the_same_result_as_utc():
    zones = [timezone(timedelta(hours=h)) for h in (-7, 0, 2, 5.5)]
    utc = misses(20)
    mixed = [
        request(path=f"/p{n}", when=(T0 + timedelta(seconds=n)).astimezone(zones[n % 4]))
        for n in range(20)
    ]
    a, b = detect_scanners(utc)[0], detect_scanners(mixed)[0]
    assert (a.count, a.evidence, a.time) == (b.count, b.evidence, b.time)


def test_naive_and_aware_timestamps_can_be_mixed_and_naive_ones_count_as_utc():
    entries = []
    for n in range(15):
        when = datetime(2025, 6, 1, 12, 0, n)
        entries.append(
            request(path=f"/p{n}", when=when if n % 2 == 0 else when.replace(tzinfo=UTC))
        )
    (found,) = detect_scanners(entries)
    assert found.count == 15


def test_a_timestamp_that_cannot_be_converted_is_a_value_error():
    far = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    with pytest.raises(ValueError, match="out of range"):
        detect_scanners(misses(5) + [request(when=far)])


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_any_iterable_of_entries_works(source):
    assert len(detect_scanners(source(misses(15)))) == 1


def test_no_entries_gives_nothing():
    assert detect_scanners([]) == []


def test_the_input_is_not_modified_and_the_result_is_repeatable():
    entries = misses(20, agent="nikto")
    entries.reverse()
    before = [e.to_dict() for e in entries]
    first = detect_scanners(entries)
    assert [e.to_dict() for e in entries] == before
    assert detect_scanners(entries) == first


def test_no_settings_means_the_defaults():
    assert detect_scanners(misses(15)) == detect_scanners(misses(15), DEFAULTS)


def test_a_shorter_window_needs_a_faster_scan_and_a_longer_one_forgives_a_slower_one():
    assert len(detect_scanners(misses(15, spacing=2))) == 1
    assert detect(misses(15, spacing=2), window_seconds=10) == []
    assert detect_scanners(misses(15, spacing=10)) == []
    assert len(detect(misses(15, spacing=10), window_seconds=300)) == 1


def test_the_rules_file_settings_are_accepted():
    rules = load_rules()
    assert len(detect_scanners(misses(15), rules.scanner)) == 1


# --- large and hostile input ----------------------------------------------------------


def test_a_hundred_thousand_distinct_missing_paths_from_one_address_are_handled_quickly():
    entries = misses(100_000, spacing=0.01, prefix="/x")
    started = time.perf_counter()
    (found,) = burst(detect_scanners(entries))
    assert time.perf_counter() - started < 3.0
    assert found.count == 100_000 and found.severity is Severity.HIGH


def test_a_hundred_thousand_requests_for_one_path_are_handled_quickly():
    entries = [request(seconds=n * 0.01, path="/old") for n in range(100_000)]
    started = time.perf_counter()
    assert detect_scanners(entries) == []
    assert time.perf_counter() - started < 3.0


def test_many_addresses_with_a_few_misses_each_are_handled_quickly():
    entries = [
        request(ip=f"10.{n // 250}.{n % 250}.1", seconds=n % 50, path=f"/p{n}")
        for n in range(50_000)
    ]
    started = time.perf_counter()
    assert detect_scanners(entries) == []
    assert time.perf_counter() - started < 2.0


def test_a_huge_user_agent_is_handled_quickly():
    started = time.perf_counter()
    assert detect_scanners([request(status=200, agent="a" * 1_000_000 + "nikto")])
    assert time.perf_counter() - started < 1.0


# --- generated logs -------------------------------------------------------------------


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SEEDS = [(42, 3000, 0.2), (1, 3000, 0.2), (7, 3000, 0.3), (99, 5000, 0.2)]


@pytest.mark.parametrize(("seed", "lines", "ratio"), SEEDS)
def test_every_labelled_scanner_address_is_found_by_the_burst_rule_and_no_other(
    generator, seed, lines, ratio
):
    log, labels = generator.generate(seed=seed, lines=lines, attack_ratio=ratio)
    entries = [parse_line(line) for line in log]
    labelled = {item["ip"] for item in labels if item["label"] == "scanner"}
    assert labelled, "the generated log must contain a scanner burst"
    assert {d.ip for d in burst(detect_scanners(entries))} == labelled


def test_each_labelled_scan_is_one_detection_with_the_labelled_lines(generator):
    log, labels = generator.generate(seed=42, lines=3000, attack_ratio=0.2)
    entries = [parse_line(line) for line in log]
    truth = {}
    for item in labels:
        if item["label"] == "scanner":
            truth.setdefault(item["ip"], []).append(item["line"] - 1)
    found = {d.ip: d for d in burst(detect_scanners(entries))}
    assert set(found) == set(truth)
    for ip, lines in truth.items():
        assert found[ip].count == len(lines)
        assert (found[ip].first_index, found[ip].last_index) == (min(lines), max(lines))
        assert f"{len(lines)} distinct missing paths" in found[ip].evidence


@pytest.mark.parametrize(("seed", "lines", "ratio"), SEEDS)
def test_known_tools_are_only_ever_seen_on_attacker_addresses(generator, seed, lines, ratio):
    log, labels = generator.generate(seed=seed, lines=lines, attack_ratio=ratio)
    entries = [parse_line(line) for line in log]
    attackers = {item["ip"] for item in labels}
    found = tool(detect_scanners(entries))
    assert found, "attackers sometimes use sqlmap or nikto, so there should be tool detections"
    assert {d.ip for d in found} <= attackers


@pytest.mark.parametrize("seed", range(10))
def test_generated_clean_logs_raise_no_scanner_detection(generator, seed):
    log, _ = generator.generate(seed=seed, lines=3000, attack_ratio=0)
    assert detect_scanners([parse_line(line) for line in log]) == []


def test_normal_traffic_has_its_usual_few_missing_pages_and_none_is_a_scan(generator):
    log, _ = generator.generate(seed=3, lines=20_000, attack_ratio=0)
    entries = [parse_line(line) for line in log]
    not_found = sum(e.status == 404 for e in entries)
    assert 0.005 < not_found / len(entries) < 0.03
    assert detect_scanners(entries) == []


def test_the_clean_and_demo_sample_logs():
    assert detect_scanners(parse_file(ROOT / "data" / "samples" / "clean.log").entries) == []
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = [
        json.loads(row)
        for row in (ROOT / "data" / "samples" / "demo.labels.jsonl").read_text().splitlines()
    ]
    attackers = {item["ip"] for item in labels}
    assert {d.ip for d in detect_scanners(entries)} <= attackers
