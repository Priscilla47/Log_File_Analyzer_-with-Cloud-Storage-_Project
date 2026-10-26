"""Tests for summarize(). Expected values are worked out by hand from the fixtures."""

import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.analysis.summary import Summary, summarize
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file

UTC = timezone.utc
NOON = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "access_sample.log"
CLASS_KEYS = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]


def make(ip="A", path="/", status=200, size=0, method="GET", when=NOON, query=""):
    return LogEntry(
        ip=ip,
        time=when,
        method=method,
        path=path,
        query=query,
        protocol="HTTP/1.1" if method else "",
        status=status,
        size=size,
        request=f"{method} {path}" if method else "-",
    )


# 10 requests, worked out by hand:
#   IPs      A=4  B=3  C=2  D=1                      -> 4 unique
#   Paths    /home=5  /login=3  /about=1  /missing=1  (the query string is not part of a path)
#   Status   200=5  304=1  401=2  404=1  500=1
#   Classes  2xx=5  3xx=1  4xx=3  5xx=1
#   Methods  GET=8  POST=2
#   Bytes    100 + 200 + 300 + 0 + 50 + 0 + 0 + 25 + 0 + 5 = 680
#   Times    2025-06-01 12:00 to 12:09
MAIN = [
    make("A", "/home", 200, 100, when=NOON),
    make("A", "/home", 200, 200, when=NOON + timedelta(minutes=1)),
    make("B", "/home", 200, 300, when=NOON + timedelta(minutes=2)),
    make("B", "/login", 401, 0, "POST", NOON + timedelta(minutes=3)),
    make("A", "/home", 304, 50, when=NOON + timedelta(minutes=4)),
    make("C", "/login", 401, 0, "POST", NOON + timedelta(minutes=5)),
    make("B", "/about", 200, 0, when=NOON + timedelta(minutes=6)),
    make("A", "/missing", 404, 25, when=NOON + timedelta(minutes=7)),
    make("C", "/home", 200, 0, when=NOON + timedelta(minutes=8)),
    make("D", "/login", 500, 5, when=NOON + timedelta(minutes=9)),
]


@pytest.fixture
def main():
    return summarize(MAIN)


# --- the main fixture -----------------------------------------------------------------


def test_totals(main):
    assert main.total_requests == 10
    assert main.unique_ips == 4
    assert main.total_bytes == 680


def test_top_ips_are_ordered_by_count(main):
    assert main.top_ips == [("A", 4), ("B", 3), ("C", 2), ("D", 1)]


def test_top_paths_are_ordered_by_count(main):
    assert main.top_paths == [("/home", 5), ("/login", 3), ("/about", 1), ("/missing", 1)]


def test_status_classes(main):
    assert main.status_classes == {"1xx": 0, "2xx": 5, "3xx": 1, "4xx": 3, "5xx": 1, "other": 0}


def test_status_codes_are_exact_and_sorted_by_code(main):
    assert main.status_codes == {200: 5, 304: 1, 401: 2, 404: 1, 500: 1}
    assert list(main.status_codes) == [200, 304, 401, 404, 500]


def test_methods(main):
    assert main.methods == {"GET": 8, "POST": 2}


def test_error_rate_is_the_share_of_4xx_and_5xx(main):
    assert main.error_rate == pytest.approx(0.4)


def test_first_and_last_time(main):
    assert main.first_time == NOON
    assert main.last_time == NOON + timedelta(minutes=9)


def test_every_count_adds_up(main):
    assert sum(main.status_classes.values()) == main.total_requests
    assert sum(main.status_codes.values()) == main.total_requests
    assert sum(main.methods.values()) == main.total_requests


# --- the real sample log --------------------------------------------------------------


def test_sample_log():
    summary = summarize(parse_file(SAMPLE).entries)
    assert summary.total_requests == 5
    assert summary.unique_ips == 4
    assert summary.top_ips[0] == ("192.168.1.1", 2)
    assert summary.status_classes == {"1xx": 0, "2xx": 3, "3xx": 0, "4xx": 2, "5xx": 0, "other": 0}
    assert summary.status_codes == {200: 3, 401: 1, 404: 1}


def test_totals_agree_with_the_existing_analyzer_on_the_sample_log():
    from loginsight.analysis.analyzer import analyze_entries

    entries = parse_file(SAMPLE).entries
    _, stats = analyze_entries([e.to_dict() for e in entries])
    summary = summarize(entries)
    assert summary.total_requests == stats["total_requests"]
    assert summary.unique_ips == stats["unique_ips"]
    assert dict(summary.top_ips) == stats["most_common_ips"]
    assert dict(summary.top_paths) == stats["most_requested_paths"]
    assert summary.status_codes == stats["status_code_counts"]
    assert round(summary.total_bytes / 1024 / 1024, 2) == stats["total_data_transferred_MB"]


# --- empty and tiny input -------------------------------------------------------------


def test_empty_input_gives_zeros_empty_lists_and_no_times():
    summary = summarize([])
    assert summary.total_requests == 0
    assert summary.unique_ips == 0
    assert summary.top_ips == []
    assert summary.top_paths == []
    assert summary.status_codes == {}
    assert summary.methods == {}
    assert summary.total_bytes == 0
    assert summary.error_rate == 0.0
    assert summary.first_time is None
    assert summary.last_time is None
    assert list(summary.status_classes) == CLASS_KEYS
    assert set(summary.status_classes.values()) == {0}


def test_a_single_entry():
    summary = summarize([make("A", "/x", 404, 7)])
    assert summary.total_requests == 1
    assert summary.error_rate == 1.0
    assert summary.first_time == summary.last_time == NOON


@pytest.mark.parametrize("source", [list, tuple, iter])
def test_any_iterable_of_entries_is_accepted(source):
    assert summarize(source(MAIN)) == summarize(MAIN)


# --- ordering and ties ----------------------------------------------------------------


def test_ties_are_broken_by_the_value_ascending():
    entries = [make(ip, "/" + ip) for ip in ["zed", "alpha", "mid", "alpha", "zed", "mid"]]
    summary = summarize(entries)
    assert summary.top_ips == [("alpha", 2), ("mid", 2), ("zed", 2)]
    assert summary.top_paths == [("/alpha", 2), ("/mid", 2), ("/zed", 2)]


def test_the_result_does_not_depend_on_the_input_order():
    shuffled = list(MAIN)
    random.Random(7).shuffle(shuffled)
    assert summarize(shuffled) == summarize(MAIN)


def test_two_runs_give_identical_output():
    assert summarize(MAIN).to_dict() == summarize(MAIN).to_dict()


def test_methods_are_ordered_by_count_then_name():
    entries = [make(method=m) for m in ["PUT", "GET", "POST", "GET", "DELETE", "POST"]]
    assert list(summarize(entries).methods) == ["GET", "POST", "DELETE", "PUT"]


# --- top_n ----------------------------------------------------------------------------


def test_top_n_cuts_the_lists():
    entries = [make(f"ip{n}", f"/p{n}") for n in range(1, 8) for _ in range(8 - n)]
    summary = summarize(entries, top_n=3)
    assert [ip for ip, _ in summary.top_ips] == ["ip1", "ip2", "ip3"]
    assert [path for path, _ in summary.top_paths] == ["/p1", "/p2", "/p3"]
    assert summary.unique_ips == 7


def test_the_default_top_n_is_ten():
    entries = [make(f"ip{n:02d}", f"/p{n:02d}") for n in range(15)]
    summary = summarize(entries)
    assert len(summary.top_ips) == len(summary.top_paths) == 10


def test_top_n_larger_than_the_data_returns_everything():
    assert len(summarize(MAIN, top_n=1000).top_ips) == 4


def test_top_n_zero_gives_empty_lists_but_keeps_the_totals():
    summary = summarize(MAIN, top_n=0)
    assert summary.top_ips == [] and summary.top_paths == []
    assert summary.unique_ips == 4


def test_a_negative_top_n_is_rejected():
    with pytest.raises(ValueError):
        summarize(MAIN, top_n=-1)


# --- paths ----------------------------------------------------------------------------


def test_the_query_string_is_not_part_of_a_path():
    entries = [
        make(path="/search", query="q=a"),
        make(path="/search", query="q=b"),
        make(path="/search", query=""),
    ]
    assert summarize(entries).top_paths == [("/search", 3)]


def test_a_malformed_request_has_an_empty_path_and_is_counted_as_such():
    summary = summarize([make(method="", path="", status=408), make(path="/a")])
    assert ("", 1) in summary.top_paths


# --- status classes -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (0, "other"),
        (99, "other"),
        (100, "1xx"),
        (199, "1xx"),
        (200, "2xx"),
        (299, "2xx"),
        (300, "3xx"),
        (399, "3xx"),
        (400, "4xx"),
        (499, "4xx"),
        (500, "5xx"),
        (599, "5xx"),
        (600, "other"),
        (999, "other"),
    ],
)
def test_status_class_boundaries(status, expected):
    classes = summarize([make(status=status)]).status_classes
    assert classes[expected] == 1
    assert sum(classes.values()) == 1


def test_status_classes_always_have_all_six_keys_in_order():
    assert list(summarize([make(status=200)]).status_classes) == CLASS_KEYS
    assert list(summarize([]).status_classes) == CLASS_KEYS


def test_status_zero_and_odd_codes_are_not_errors():
    # "other" statuses are neither successes nor errors for the error rate.
    assert summarize([make(status=0), make(status=600), make(status=200)]).error_rate == 0.0


def test_error_rate_counts_exactly_4xx_and_5xx():
    entries = [make(status=s) for s in (399, 400, 499, 500, 599, 600)]
    assert summarize(entries).error_rate == pytest.approx(4 / 6)


# --- methods and bytes ----------------------------------------------------------------


def test_a_malformed_request_is_counted_under_none_in_brackets():
    summary = summarize([make(method=""), make(method=""), make(method="GET")])
    assert summary.methods == {"(none)": 2, "GET": 1}


def test_zero_byte_responses_add_nothing():
    assert summarize([make(size=0), make(size=0)]).total_bytes == 0


def test_bytes_are_an_exact_integer_for_large_sums():
    assert summarize([make(size=2**40), make(size=1)]).total_bytes == 2**40 + 1


# --- times ----------------------------------------------------------------------------


def test_first_and_last_time_ignore_the_input_order():
    early, late = NOON, NOON + timedelta(days=2)
    summary = summarize([make(when=late), make(when=early), make(when=NOON + timedelta(days=1))])
    assert (summary.first_time, summary.last_time) == (early, late)


def test_times_with_different_offsets_are_compared_as_instants():
    seven_behind = timezone(timedelta(hours=-7))
    first = datetime(2025, 6, 1, 10, 0, tzinfo=seven_behind)  # 17:00 UTC
    second = datetime(2025, 6, 1, 17, 30, tzinfo=UTC)  # 17:30 UTC
    third = datetime(2025, 6, 1, 19, 15, tzinfo=timezone(timedelta(hours=2)))  # 17:15 UTC
    summary = summarize([make(when=second), make(when=first), make(when=third)])
    assert summary.first_time == first
    assert summary.last_time == second


# --- output ---------------------------------------------------------------------------


def test_summary_is_immutable(main):
    with pytest.raises(AttributeError):
        main.total_requests = 0  # type: ignore[misc]


def test_summary_is_a_summary(main):
    assert isinstance(main, Summary)


def test_to_dict_can_be_written_as_json_and_read_back(main):
    data = json.loads(json.dumps(main.to_dict()))
    assert data["total_requests"] == 10
    assert data["unique_ips"] == 4
    assert data["top_ips"][0] == {"ip": "A", "requests": 4}
    assert data["top_paths"][0] == {"path": "/home", "requests": 5}
    assert data["status_classes"]["4xx"] == 3
    assert data["status_codes"] == {"200": 5, "304": 1, "401": 2, "404": 1, "500": 1}
    assert data["methods"] == {"GET": 8, "POST": 2}
    assert data["total_bytes"] == 680
    assert data["error_rate"] == pytest.approx(0.4)
    assert data["first_time"] == "2025-06-01T12:00:00+00:00"
    assert data["last_time"] == "2025-06-01T12:09:00+00:00"


def test_to_dict_keeps_the_offset_of_the_timestamps():
    when = datetime(2025, 6, 1, 10, 0, tzinfo=timezone(timedelta(hours=-7)))
    assert summarize([make(when=when)]).to_dict()["first_time"] == "2025-06-01T10:00:00-07:00"


def test_to_dict_of_an_empty_summary_has_null_times_and_can_be_written_as_json():
    data = json.loads(json.dumps(summarize([]).to_dict()))
    assert data["first_time"] is None and data["last_time"] is None
    assert data["top_ips"] == [] and data["total_requests"] == 0


def test_to_dict_has_exactly_these_keys(main):
    assert set(main.to_dict()) == {
        "total_requests",
        "unique_ips",
        "top_ips",
        "top_paths",
        "status_classes",
        "status_codes",
        "methods",
        "total_bytes",
        "error_rate",
        "first_time",
        "last_time",
    }


def test_the_input_is_not_modified():
    entries = list(MAIN)
    summarize(entries)
    assert entries == MAIN


# --- speed ----------------------------------------------------------------------------


def test_100_000_entries_are_summarised_in_well_under_a_second():
    rng = random.Random(1)
    entries = [
        make(f"192.0.2.{rng.randint(1, 250)}", f"/p/{rng.randint(1, 500)}", rng.choice([200, 404]))
        for _ in range(100_000)
    ]
    started = time.perf_counter()
    summary = summarize(entries)
    elapsed = time.perf_counter() - started
    assert summary.total_requests == 100_000
    assert elapsed < 1.0
