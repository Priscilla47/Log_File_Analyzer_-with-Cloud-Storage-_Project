"""Tests for the tolerant Common and Combined log format parser."""

import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import MAX_LINE_LENGTH, LogParseError, parse_file, parse_line

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "access_sample.log"

UTC = timezone.utc


def line(
    request="GET /home HTTP/1.1",
    status="200",
    size="1024",
    ip="192.0.2.1",
    when="01/Jun/2025:10:00:00 -0700",
    extra="",
):
    return f'{ip} - - [{when}] "{request}" {status} {size}{extra}'


def combined(referer='"http://example.test/"', agent='"Mozilla/5.0"', **kwargs):
    return line(extra=f" {referer} {agent}", **kwargs)


def reason_of(text):
    with pytest.raises(LogParseError) as info:
        parse_line(text)
    return info.value.reason


# --- valid lines ----------------------------------------------------------------------


def test_common_line_gives_a_log_entry_with_all_fields():
    entry = parse_line(line())
    assert isinstance(entry, LogEntry)
    assert entry.ip == "192.0.2.1"
    assert entry.time == datetime(2025, 6, 1, 17, 0, 0, tzinfo=UTC)
    assert entry.method == "GET"
    assert entry.path == "/home"
    assert entry.query == ""
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.size == 1024
    assert entry.request == "GET /home HTTP/1.1"


def test_common_line_has_no_referer_or_user_agent():
    entry = parse_line(line())
    assert entry.referer is None
    assert entry.user_agent is None


def test_combined_line_fills_referer_and_user_agent():
    entry = parse_line(combined())
    assert entry.referer == "http://example.test/"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.status == 200


@pytest.mark.parametrize(
    ("referer", "agent"),
    [('"-"', '"UA"'), ('"http://r/"', '"-"'), ('"-"', '"-"')],
)
def test_dash_referer_or_user_agent_becomes_none(referer, agent):
    entry = parse_line(combined(referer=referer, agent=agent))
    assert entry.referer == (None if referer == '"-"' else "http://r/")
    assert entry.user_agent == (None if agent == '"-"' else "UA")


def test_dash_size_becomes_zero():
    assert parse_line(line(status="304", size="-")).size == 0


def test_zero_size_is_zero():
    assert parse_line(line(size="0")).size == 0


@pytest.mark.parametrize("ip", ["192.0.2.1", "203.0.113.250", "::1", "2001:db8::7"])
def test_ipv4_and_ipv6_clients(ip):
    assert parse_line(line(ip=ip)).ip == ip


def test_post_method():
    entry = parse_line(line(request="POST /login HTTP/1.1", status="401", size="512"))
    assert (entry.method, entry.path, entry.status) == ("POST", "/login", 401)


def test_lowercase_method_is_accepted():
    assert parse_line(line(request="get /x HTTP/1.1")).method == "get"


def test_http2_protocol_token():
    assert parse_line(line(request="GET / HTTP/2.0")).protocol == "HTTP/2.0"


# --- query string ---------------------------------------------------------------------


def test_query_is_split_from_the_path_and_not_decoded():
    entry = parse_line(line(request="GET /s?q=a%20b HTTP/1.1"))
    assert entry.path == "/s"
    assert entry.query == "q=a%20b"
    assert entry.target == "/s?q=a%20b"


def test_query_with_several_question_marks_keeps_the_rest():
    entry = parse_line(line(request="GET /s?a=1?b=2 HTTP/1.1"))
    assert (entry.path, entry.query) == ("/s", "a=1?b=2")


def test_empty_query_after_question_mark():
    entry = parse_line(line(request="GET /s? HTTP/1.1"))
    assert (entry.path, entry.query) == ("/s", "")


# --- timestamps -----------------------------------------------------------------------


def test_timezone_offset_is_kept():
    entry = parse_line(line(when="01/Jun/2025:10:00:00 -0700"))
    assert entry.time.utcoffset() == timedelta(hours=-7)
    assert entry.time.hour == 10


def test_positive_half_hour_offset():
    entry = parse_line(line(when="01/Jun/2025:10:00:00 +0530"))
    assert entry.time.utcoffset() == timedelta(hours=5, minutes=30)


def test_timestamp_without_timezone_is_assumed_utc():
    entry = parse_line(line(when="01/Jun/2025:10:00:00"))
    assert entry.time == datetime(2025, 6, 1, 10, 0, 0, tzinfo=UTC)


# --- malformed request lines are kept -------------------------------------------------


def test_dash_request_is_kept_with_empty_request_fields():
    entry = parse_line(line(request="-", status="408", size="0"))
    assert entry.status == 408
    assert (entry.method, entry.path, entry.query, entry.protocol) == ("", "", "", "")
    assert entry.request == "-"


def test_two_token_request_has_no_protocol():
    entry = parse_line(line(request="GET /", status="400", size="0"))
    assert (entry.method, entry.path, entry.protocol) == ("GET", "/", "")


def test_space_in_path_is_kept_inside_the_path():
    entry = parse_line(line(request="GET /a b HTTP/1.1"))
    assert (entry.method, entry.path, entry.protocol) == ("GET", "/a b", "HTTP/1.1")


def test_space_in_path_without_protocol():
    entry = parse_line(line(request="GET /a b"))
    assert (entry.path, entry.protocol) == ("/a b", "")


def test_method_only_request():
    entry = parse_line(line(request="GET", status="400", size="0"))
    assert (entry.method, entry.path, entry.protocol) == ("GET", "", "")


def test_extra_spaces_after_the_method_are_ignored():
    assert parse_line(line(request="GET  /x HTTP/1.1")).path == "/x"


def test_escaped_binary_garbage_request_is_kept():
    garbage = r"\x16\x03\x01\x00\x75\x01\x00"
    entry = parse_line(line(request=garbage, status="400", size="0"))
    assert entry.method == ""
    assert entry.path == ""
    assert entry.request == garbage


def test_request_starting_with_a_number_is_not_treated_as_a_method():
    entry = parse_line(line(request="123 /x HTTP/1.1"))
    assert (entry.method, entry.path) == ("", "")
    assert entry.request == "123 /x HTTP/1.1"


# --- escaped quotes -------------------------------------------------------------------


def test_escaped_quote_inside_the_request_is_parsed_not_skipped():
    entry = parse_line(line(request=r"GET /?q=\"x HTTP/1.1"))
    assert entry.path == "/"
    assert entry.query == r"q=\"x"
    assert entry.request == r"GET /?q=\"x HTTP/1.1"


def test_escaped_quote_inside_the_user_agent_is_parsed():
    entry = parse_line(combined(agent=r'"Mozilla \"quoted\" 5.0"'))
    assert entry.user_agent == r"Mozilla \"quoted\" 5.0"


# --- whitespace and line endings ------------------------------------------------------


@pytest.mark.parametrize("ending", ["", "\n", "\r\n", "   ", "  \n"])
def test_trailing_whitespace_and_line_endings_are_tolerated(ending):
    assert parse_line(line() + ending).status == 200


# --- errors ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "not a log line",
        "192.0.2.1 only an ip",
        '192.0.2.1 - - [01/Jun/2025:10:00:00 +0000] "GET / HTTP/1.1"',
        line() + ' "only-one-quoted-field"',
        line() + " 0.012",
    ],
)
def test_text_that_is_not_a_log_line_is_no_match(text):
    assert reason_of(text) == "no_match"


@pytest.mark.parametrize("status", ["2000", "20", "abc", "٢٠٠"])
def test_status_must_be_exactly_three_ascii_digits(status):
    assert reason_of(line(status=status)) == "no_match"


@pytest.mark.parametrize(
    "when",
    ["99/Foo/2025:10:00:00 +0000", "32/Jun/2025:10:00:00 +0000", "01/Jun/2025:25:00:00 +0000"],
)
def test_impossible_timestamp_is_bad_timestamp(when):
    assert reason_of(line(when=when)) == "bad_timestamp"


@pytest.mark.parametrize("size", ["12x", "abc", "1.5", "-5", "²"])
def test_size_that_is_not_a_number_or_dash_is_bad_size(size):
    assert reason_of(line(size=size)) == "bad_size"


def _line_of_length(length):
    padding = length - len(line(request="GET / HTTP/1.1"))
    return line(request="GET /" + "a" * padding + " HTTP/1.1")


def test_line_at_the_length_limit_is_parsed():
    text = _line_of_length(MAX_LINE_LENGTH)
    assert len(text) == MAX_LINE_LENGTH
    assert parse_line(text).status == 200


def test_line_over_the_length_limit_is_rejected():
    text = _line_of_length(MAX_LINE_LENGTH + 1)
    assert reason_of(text) == "line_too_long"


def test_max_line_length_is_8192():
    assert MAX_LINE_LENGTH == 8192


def test_log_parse_error_is_a_value_error_with_a_reason():
    with pytest.raises(ValueError) as info:
        parse_line("garbage")
    assert isinstance(info.value, LogParseError)
    assert info.value.reason == "no_match"
    assert "no_match" in str(info.value)


# --- robustness -----------------------------------------------------------------------


PIECES = [
    "192.0.2.1", " - - ", "[", "]", '"', '\\"', "\\", "GET", "POST", " ", "/", "?", "200",
    "-", "01/Jun/2025:10:00:00 +0000", "HTTP/1.1", "é", "\x00", "\t", "%", "'", ";", "<", ">",
]  # fmt: skip


def test_no_input_ever_raises_anything_but_log_parse_error():
    rng = random.Random(1234)
    for _ in range(3000):
        text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 30)))
        try:
            result = parse_line(text)
        except LogParseError:
            continue
        assert isinstance(result, LogEntry)


def test_adversarial_line_is_rejected_quickly():
    # Many quotes and backslashes just under the limit must not cause catastrophic backtracking.
    text = '1.1.1.1 - - [01/Jun/2025:10:00:00 +0000] "' + ('\\"' * 4000) + " 200"
    started = time.perf_counter()
    with pytest.raises(LogParseError):
        parse_line(text)
    assert time.perf_counter() - started < 1.0


# --- parse_file -----------------------------------------------------------------------


def test_parse_file_reads_the_sample_log_in_order():
    entries = parse_file(SAMPLE)
    assert [e.ip for e in entries] == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.1",
        "192.168.1.4",
    ]
    assert [e.status for e in entries] == [200, 401, 200, 404, 200]
    assert all(isinstance(e, LogEntry) for e in entries)


def test_parse_file_skips_unreadable_lines_and_ignores_blank_ones(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(f"{line()}\nthis is junk\n\n{line(status='404')}\nmore junk\n")
    assert [e.status for e in parse_file(path)] == [200, 404]


def test_parse_file_keeps_lines_with_a_malformed_request(tmp_path):
    path = tmp_path / "odd.log"
    path.write_text(f"{line()}\n{line(request='-', status='408', size='0')}\n")
    entries = parse_file(path)
    assert [e.status for e in entries] == [200, 408]


def test_parse_file_skips_lines_with_a_bad_timestamp_without_stopping(tmp_path):
    path = tmp_path / "dates.log"
    path.write_text(f"{line()}\n{line(when='99/Foo/2025:10:00:00 +0000')}\n{line(status='404')}\n")
    assert [e.status for e in parse_file(path)] == [200, 404]


def test_parse_file_on_an_empty_file(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("")
    assert parse_file(path) == []


def test_parse_file_on_a_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "missing.log")


def test_parse_file_accepts_a_string_path(tmp_path):
    path = tmp_path / "one.log"
    path.write_text(line() + "\n")
    assert len(parse_file(str(path))) == 1


def test_parse_file_handles_a_missing_final_newline(tmp_path):
    path = tmp_path / "nonewline.log"
    path.write_text(line())
    assert len(parse_file(path)) == 1


def test_parse_file_handles_windows_line_endings(tmp_path):
    path = tmp_path / "crlf.log"
    path.write_bytes((line() + "\r\n" + line(status="404") + "\r\n").encode())
    assert [e.status for e in parse_file(path)] == [200, 404]


def test_parse_file_raises_on_invalid_utf8(tmp_path):
    # Still the case after this change. Fixed in #8 (open with errors="replace"); when that
    # lands this test fails and should be replaced by one asserting the line is read.
    path = tmp_path / "binary.log"
    path.write_bytes(b'1.1.1.1 - - [01/Jun/2025:10:00:00 -0700] "GET /\xff HTTP/1.1" 200 5\n')
    with pytest.raises(UnicodeDecodeError):
        parse_file(path)
