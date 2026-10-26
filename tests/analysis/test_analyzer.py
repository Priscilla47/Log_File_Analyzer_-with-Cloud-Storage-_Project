"""Tests for ``analyze_entries``.

The first half pins the original behaviour on plain dicts, with every expected value worked
out by hand from ``MAIN`` (see the comments). The second half covers empty input and
``LogEntry`` input.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.analysis.analyzer import analyze_entries
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file

MIB = 1024 * 1024
HALF_MIB = 512 * 1024
NOON = datetime(2025, 6, 1, 12, 0, 0)


def entry(ip, path, status, size):
    return {"ip": ip, "time": NOON, "path": path, "status": status, "size": size}


# 8 requests. Worked out by hand:
#   IPs:     A=4, B=2, C=1, D=1                      -> 4 unique
#   Paths:   /home=5, /about=1, /admin=1, /login=1
#   Status:  200=4, 404=2, 401=1, 304=1
#   Bytes:   3 x 1 MiB + 2 x 0.5 MiB = 4 MiB exactly -> 4.0
MAIN = [
    entry("A", "/home", 200, MIB),
    entry("A", "/home", 200, MIB),
    entry("A", "/about", 200, HALF_MIB),
    entry("B", "/home", 404, 0),
    entry("B", "/admin", 404, 0),
    entry("C", "/home", 200, MIB),
    entry("D", "/login", 401, HALF_MIB),
    entry("A", "/home", 304, 0),
]


@pytest.fixture
def main_result():
    return analyze_entries(MAIN)


def test_total_requests_counts_every_entry(main_result):
    _, stats = main_result
    assert stats["total_requests"] == 8


def test_unique_ips(main_result):
    _, stats = main_result
    assert stats["unique_ips"] == 4


def test_most_common_ips_counts_and_descending_order(main_result):
    _, stats = main_result
    ips = stats["most_common_ips"]
    assert ips["A"] == 4
    assert ips["B"] == 2
    values = list(ips.values())
    assert values == sorted(values, reverse=True)
    assert list(ips)[:2] == ["A", "B"]


def test_most_requested_paths_counts_and_order(main_result):
    _, stats = main_result
    paths = stats["most_requested_paths"]
    assert paths["/home"] == 5
    assert list(paths)[0] == "/home"
    assert sum(paths.values()) == 8


def test_status_code_counts(main_result):
    _, stats = main_result
    assert stats["status_code_counts"] == {200: 4, 404: 2, 401: 1, 304: 1}


def test_data_transferred_in_mb_is_exact_for_whole_mebibytes(main_result):
    _, stats = main_result
    assert stats["total_data_transferred_MB"] == 4.0


def test_data_transferred_is_rounded_to_two_decimals():
    # 1,500,000 bytes / 1,048,576 = 1.4305... -> 1.43
    _, stats = analyze_entries([entry("A", "/", 200, 1_500_000)])
    assert stats["total_data_transferred_MB"] == 1.43


def test_zero_sized_responses_do_not_break_the_sum():
    _, stats = analyze_entries([entry("A", "/", 304, 0), entry("A", "/", 304, 0)])
    assert stats["total_data_transferred_MB"] == 0.0


def test_only_top_five_ips_and_paths_are_returned():
    # ip1 has 7 requests, ip2 has 6, ... ip7 has 1: counts are all different, so no ties.
    entries = []
    for rank in range(1, 8):
        for _ in range(8 - rank):
            entries.append(entry(f"ip{rank}", f"/p{rank}", 200, 1))
    _, stats = analyze_entries(entries)
    assert list(stats["most_common_ips"]) == ["ip1", "ip2", "ip3", "ip4", "ip5"]
    assert list(stats["most_requested_paths"]) == ["/p1", "/p2", "/p3", "/p4", "/p5"]
    assert stats["unique_ips"] == 7


def test_dataframe_has_one_row_per_entry_in_input_order(main_result):
    df, _ = main_result
    assert len(df) == 8
    assert df["ip"].tolist() == [e["ip"] for e in MAIN]
    assert df["status"].tolist() == [e["status"] for e in MAIN]


def test_dataframe_columns_match_the_input_keys(main_result):
    df, _ = main_result
    assert list(df.columns) == ["ip", "time", "path", "status", "size"]


def test_stats_has_exactly_the_documented_keys(main_result):
    _, stats = main_result
    assert set(stats) == {
        "total_requests",
        "unique_ips",
        "most_common_ips",
        "most_requested_paths",
        "status_code_counts",
        "total_data_transferred_MB",
    }


def test_single_entry():
    _, stats = analyze_entries([entry("A", "/", 200, MIB)])
    assert stats["total_requests"] == 1
    assert stats["unique_ips"] == 1
    assert stats["total_data_transferred_MB"] == 1.0


def test_input_list_is_not_modified():
    entries = [dict(e) for e in MAIN]
    analyze_entries(entries)
    assert entries == MAIN


# --- empty input ----------------------------------------------------------------------

LOG_ENTRY_FIELDS = [
    "ip",
    "time",
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "size",
    "referer",
    "user_agent",
    "request",
]

EMPTY_STATS = {
    "total_requests": 0,
    "unique_ips": 0,
    "most_common_ips": {},
    "most_requested_paths": {},
    "status_code_counts": {},
    "total_data_transferred_MB": 0.0,
}


def test_empty_input_gives_zero_stats_and_does_not_raise():
    _, stats = analyze_entries([])
    assert stats == EMPTY_STATS


def test_empty_input_gives_an_empty_dataframe_with_the_log_entry_columns():
    df, _ = analyze_entries([])
    assert len(df) == 0
    assert list(df.columns) == LOG_ENTRY_FIELDS


def test_empty_stats_can_be_written_as_json():
    _, stats = analyze_entries([])
    assert json.loads(json.dumps(stats)) == EMPTY_STATS


def test_empty_tuple_and_generator_are_accepted_too():
    assert analyze_entries(())[1] == EMPTY_STATS
    assert analyze_entries(e for e in [])[1] == EMPTY_STATS


# --- LogEntry input -------------------------------------------------------------------

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "access_sample.log"
UTC = timezone.utc


def log_entry(ip="192.0.2.1", path="/", status=200, size=0, when=None):
    return LogEntry(
        ip=ip,
        time=when or datetime(2025, 6, 1, 12, 0, tzinfo=UTC),
        method="GET",
        path=path,
        query="",
        protocol="HTTP/1.1",
        status=status,
        size=size,
        request=f"GET {path} HTTP/1.1",
    )


def test_log_entries_give_the_same_stats_as_the_same_data_as_dicts():
    entries = [log_entry(e["ip"], e["path"], e["status"], e["size"]) for e in MAIN]
    assert analyze_entries(entries)[1] == analyze_entries(MAIN)[1]


def test_the_dataframe_for_log_entries_has_the_log_entry_columns_in_order():
    df, _ = analyze_entries([log_entry()])
    assert list(df.columns) == LOG_ENTRY_FIELDS


def test_dataframe_rows_follow_the_input_order_for_log_entries():
    entries = [log_entry(ip=f"192.0.2.{n}", status=200 + n) for n in range(1, 6)]
    df, _ = analyze_entries(entries)
    assert df["ip"].tolist() == [e.ip for e in entries]
    assert df["status"].tolist() == [e.status for e in entries]


def test_the_real_sample_log_gives_the_expected_stats():
    _, stats = analyze_entries(parse_file(SAMPLE).entries)
    assert stats["total_requests"] == 5
    assert stats["unique_ips"] == 4
    assert stats["most_common_ips"]["192.168.1.1"] == 2
    assert stats["status_code_counts"] == {200: 3, 401: 1, 404: 1}


def test_the_time_column_stays_a_datetime_when_offsets_differ():
    # Mixed offsets would otherwise give an object column, and df["time"].dt would fail.
    entries = [
        log_entry(when=datetime(2025, 6, 1, 10, tzinfo=timezone(timedelta(hours=-7)))),
        log_entry(when=datetime(2025, 6, 1, 17, tzinfo=UTC)),
        log_entry(when=datetime(2025, 6, 1, 19, tzinfo=timezone(timedelta(hours=2)))),
    ]
    df, _ = analyze_entries(entries)
    assert str(df["time"].dtype).startswith("datetime64")
    assert df["time"].dt.hour.tolist() == [17, 17, 17]


def test_a_list_mixing_log_entries_and_dicts_is_accepted():
    mixed = [log_entry(ip="192.0.2.1", path="/a", size=10), entry("192.0.2.2", "/b", 404, 20)]
    df, stats = analyze_entries(mixed)
    assert df["ip"].tolist() == ["192.0.2.1", "192.0.2.2"]
    assert stats["total_requests"] == 2
    assert stats["status_code_counts"] == {200: 1, 404: 1}


def test_a_generator_of_log_entries_is_handled_like_a_list():
    when = datetime(2025, 6, 1, 10, tzinfo=timezone(timedelta(hours=-7)))
    entries = [log_entry(when=when), log_entry(when=when + timedelta(hours=1))]
    from_list = analyze_entries(entries)
    from_generator = analyze_entries(e for e in entries)
    assert from_generator[1] == from_list[1]
    assert from_generator[0]["time"].tolist() == from_list[0]["time"].tolist()
    assert str(from_generator[0]["time"].dtype) == str(from_list[0]["time"].dtype)


def test_log_entries_are_not_modified():
    entries = [log_entry(path="/a"), log_entry(path="/b")]
    before = [e.to_dict() for e in entries]
    analyze_entries(entries)
    assert [e.to_dict() for e in entries] == before


def test_dict_and_log_entry_input_can_not_be_confused_with_empty_input():
    assert analyze_entries([log_entry()])[1]["total_requests"] == 1
    assert analyze_entries([entry("A", "/", 200, 1)])[1]["total_requests"] == 1


# --- plain Python values --------------------------------------------------------------


@pytest.mark.parametrize(
    "entries", [[], MAIN, [log_entry(size=5)]], ids=["empty", "dicts", "entries"]
)
def test_stats_contain_only_plain_python_values(entries):
    _, stats = analyze_entries(entries)
    assert type(stats["total_requests"]) is int
    assert type(stats["unique_ips"]) is int
    assert type(stats["total_data_transferred_MB"]) is float
    for name in ("most_common_ips", "most_requested_paths", "status_code_counts"):
        for key, value in stats[name].items():
            assert type(key) in (str, int)
            assert type(value) is int


@pytest.mark.parametrize(
    "entries", [[], MAIN, [log_entry(size=5)]], ids=["empty", "dicts", "entries"]
)
def test_stats_can_be_written_as_json(entries):
    _, stats = analyze_entries(entries)
    assert json.loads(json.dumps(stats)) == {
        key: ({str(k): v for k, v in value.items()} if isinstance(value, dict) else value)
        for key, value in stats.items()
    }
