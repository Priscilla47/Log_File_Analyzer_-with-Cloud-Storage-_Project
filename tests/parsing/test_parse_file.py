"""Tests for parse_file and the parse statistics it returns."""

import random
from pathlib import Path

import pytest

from loginsight.parsing.models import LogEntry, ParseIssue, ParseResult, ParseStats
from loginsight.parsing.parser import (
    MAX_ERROR_LINE_LENGTH,
    MAX_FIRST_ERRORS,
    parse_file,
)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "access_sample.log"


def good(status="200", request="GET /home HTTP/1.1", when="01/Jun/2025:10:00:00 -0700"):
    return f'192.0.2.1 - - [{when}] "{request}" {status} 1024'


def write(tmp_path, text, name="test.log"):
    path = tmp_path / name
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


# --- result shape ---------------------------------------------------------------------


def test_sample_log_is_read_in_order_with_clean_stats():
    result = parse_file(SAMPLE)
    assert isinstance(result, ParseResult)
    assert [e.ip for e in result.entries] == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.1",
        "192.168.1.4",
    ]
    assert all(isinstance(e, LogEntry) for e in result.entries)
    stats = result.stats
    assert (stats.total_lines, stats.parsed, stats.skipped) == (5, 5, 0)
    assert stats.skipped_by_reason == {}
    assert stats.first_errors == []
    assert stats.success_rate == 1.0


def test_string_and_path_arguments_both_work(tmp_path):
    path = write(tmp_path, good() + "\n")
    assert len(parse_file(str(path)).entries) == 1
    assert len(parse_file(path).entries) == 1


# --- counting -------------------------------------------------------------------------


def test_eight_good_and_two_junk_lines(tmp_path):
    lines = [good(status=str(200 + i)) for i in range(8)]
    lines.insert(3, "junk one")
    lines.insert(7, "junk two")
    stats = parse_file(write(tmp_path, "\n".join(lines) + "\n")).stats
    assert stats.total_lines == 10
    assert stats.parsed == 8
    assert stats.skipped == 2
    assert stats.success_rate == 0.8


def test_skipped_by_reason_splits_the_reasons(tmp_path):
    text = "\n".join(
        [
            good(),
            "junk",
            "more junk",
            good(when="99/Foo/2025:10:00:00 +0000"),
            '192.0.2.1 - - [01/Jun/2025:10:00:00 -0700] "GET / HTTP/1.1" 200 12x',
            "x" * 9000,
        ]
    )
    stats = parse_file(write(tmp_path, text)).stats
    assert stats.skipped_by_reason == {
        "no_match": 2,
        "bad_timestamp": 1,
        "bad_size": 1,
        "line_too_long": 1,
    }
    assert stats.skipped == 5


def test_lines_with_a_malformed_request_are_parsed_not_skipped(tmp_path):
    text = good() + "\n" + good(request="-", status="408") + "\n"
    result = parse_file(write(tmp_path, text))
    assert [e.status for e in result.entries] == [200, 408]
    assert result.stats.skipped == 0


def test_blank_lines_are_not_counted(tmp_path):
    stats = parse_file(write(tmp_path, f"\n{good()}\n   \n\t\n{good()}\n\n")).stats
    assert (stats.total_lines, stats.parsed, stats.skipped) == (2, 2, 0)


def test_empty_file(tmp_path):
    result = parse_file(write(tmp_path, ""))
    assert result.entries == []
    stats = result.stats
    assert (stats.total_lines, stats.parsed, stats.skipped) == (0, 0, 0)
    assert stats.success_rate == 1.0
    assert stats.first_errors == []


def test_file_of_only_junk_has_zero_success_rate(tmp_path):
    stats = parse_file(write(tmp_path, "a\nb\nc\n")).stats
    assert stats.success_rate == 0.0
    assert stats.parsed == 0


# --- first_errors ---------------------------------------------------------------------


def test_first_errors_report_one_based_line_numbers_after_blank_lines(tmp_path):
    text = f"\n\n{good()}\n\nbad line\n{good()}\nanother bad\n"
    errors = parse_file(write(tmp_path, text)).stats.first_errors
    assert errors == [
        ParseIssue(line_number=5, reason="no_match", line="bad line"),
        ParseIssue(line_number=7, reason="no_match", line="another bad"),
    ]


def test_first_errors_are_capped_at_ten(tmp_path):
    text = "\n".join(f"junk {i}" for i in range(25)) + "\n"
    stats = parse_file(write(tmp_path, text)).stats
    assert MAX_FIRST_ERRORS == 10
    assert stats.skipped == 25
    assert len(stats.first_errors) == 10
    assert [e.line_number for e in stats.first_errors] == list(range(1, 11))


def test_first_errors_carry_the_reason_of_each_line(tmp_path):
    text = f"junk\n{good(when='99/Foo/2025:10:00:00 +0000')}\n"
    reasons = [e.reason for e in parse_file(write(tmp_path, text)).stats.first_errors]
    assert reasons == ["no_match", "bad_timestamp"]


def test_first_errors_truncate_long_lines_to_200_characters(tmp_path):
    stats = parse_file(write(tmp_path, "x" * 5000 + "\n")).stats
    assert MAX_ERROR_LINE_LENGTH == 200
    assert stats.first_errors[0].line == "x" * 200


def test_first_errors_do_not_keep_line_endings(tmp_path):
    stats = parse_file(write(tmp_path, b"junk\r\n")).stats
    assert stats.first_errors[0].line == "junk"


# --- encoding and line endings --------------------------------------------------------


def test_invalid_utf8_does_not_raise_and_the_line_is_still_read(tmp_path):
    raw = b'1.1.1.1 - - [01/Jun/2025:10:00:00 -0700] "GET /\xff HTTP/1.1" 200 5\n'
    result = parse_file(write(tmp_path, raw))
    assert len(result.entries) == 1
    assert result.entries[0].path == "/�"
    assert result.stats.skipped == 0


def test_a_fully_binary_file_is_all_skipped_without_raising(tmp_path):
    stats = parse_file(write(tmp_path, bytes(range(256)) * 4)).stats
    assert stats.parsed == 0
    assert stats.skipped == stats.total_lines


def test_windows_line_endings(tmp_path):
    text = good() + "\r\n" + good(status="404") + "\r\n"
    result = parse_file(write(tmp_path, text))
    assert [e.status for e in result.entries] == [200, 404]
    assert result.stats.skipped == 0


def test_missing_final_newline(tmp_path):
    result = parse_file(write(tmp_path, good()))
    assert len(result.entries) == 1


# --- errors that are not parse errors -------------------------------------------------


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "missing.log")


def test_directory_raises(tmp_path):
    with pytest.raises(IsADirectoryError):
        parse_file(tmp_path)


# --- invariants -----------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(5))
def test_parsed_plus_skipped_equals_total_on_generated_files(tmp_path, seed):
    rng = random.Random(seed)
    pool = [good(), good(status="404"), "junk", "", "   ", good(when="99/Foo/2025:1:1:1 +0")]
    text = "\n".join(rng.choice(pool) for _ in range(rng.randint(0, 60)))
    result = parse_file(write(tmp_path, text, name=f"gen{seed}.log"))
    stats = result.stats
    assert stats.parsed + stats.skipped == stats.total_lines
    assert stats.parsed == len(result.entries)
    assert sum(stats.skipped_by_reason.values()) == stats.skipped
    assert len(stats.first_errors) == min(stats.skipped, MAX_FIRST_ERRORS)
    assert 0.0 <= stats.success_rate <= 1.0


def test_stats_are_immutable(tmp_path):
    stats = parse_file(write(tmp_path, good())).stats
    assert isinstance(stats, ParseStats)
    with pytest.raises(AttributeError):
        stats.parsed = 99  # type: ignore[misc]
