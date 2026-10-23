"""Characterization tests for the prototype analyzer.

These pin what ``analyze_entries`` does TODAY so that the refactor planned for next week
shows up as deliberate, visible differences. Known bugs are marked ``xfail(strict=True)``.

All expected values below are worked out by hand from ``MAIN`` (see the comments).
"""

from datetime import datetime

import pytest

from loginsight.analysis.analyzer import analyze_entries

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


@pytest.mark.xfail(strict=True, raises=KeyError, reason="known bug: empty input, fixed later")
def test_empty_input_should_not_raise():
    # Today an empty list raises KeyError('ip') because the DataFrame has no columns.
    analyze_entries([])
