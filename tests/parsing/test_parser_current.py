"""Characterization tests for the prototype parser.

These pin what the parser does TODAY, so that the rewrite planned in #7 shows up as
deliberate, visible differences. Known bugs are marked ``xfail(strict=True)``: once a bug
is fixed the test fails loudly, which forces the marker to be removed.
"""

from datetime import datetime
from pathlib import Path

import pytest

from loginsight.parsing.parser import parse_file, parse_line

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "access_sample.log"

VALID = '192.168.1.1 - - [01/Jun/2025:10:00:00 -0700] "GET /home HTTP/1.1" 200 1024'
COMBINED = (
    '1.2.3.4 - - [01/Jun/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 5 '
    '"http://example.test/" "Mozilla/5.0"'
)


def line(request="GET /home HTTP/1.1", status=200, size="1024", ip="192.168.1.1",
         when="01/Jun/2025:10:00:00 -0700"):
    return f'{ip} - - [{when}] "{request}" {status} {size}'


# --- parse_line: lines that work today -------------------------------------------------


def test_valid_line_gives_expected_fields():
    entry = parse_line(VALID)
    assert entry["ip"] == "192.168.1.1"
    assert entry["time"] == datetime(2025, 6, 1, 10, 0, 0)
    assert entry["request"] == "GET /home HTTP/1.1"
    assert entry["method"] == "GET"
    assert entry["path"] == "/home"
    assert entry["status"] == 200
    assert entry["size"] == 1024


def test_status_and_size_are_integers():
    entry = parse_line(VALID)
    assert type(entry["status"]) is int
    assert type(entry["size"]) is int


def test_dash_size_becomes_zero():
    assert parse_line(line(status=304, size="-"))["size"] == 0


def test_query_string_stays_inside_path():
    # Current behaviour: the query is NOT split from the path. #7 changes this on purpose.
    entry = parse_line(line(request="GET /s?q=a%20b HTTP/1.1"))
    assert entry["path"] == "/s?q=a%20b"


def test_post_method_is_parsed():
    entry = parse_line(line(request="POST /login HTTP/1.1", status=401, size="512"))
    assert (entry["method"], entry["path"], entry["status"]) == ("POST", "/login", 401)


def test_combined_line_parses_but_extra_fields_are_ignored():
    entry = parse_line(COMBINED)
    assert entry is not None
    assert entry["status"] == 200
    # Referer and user agent are not exposed today.
    assert set(entry) == {"ip", "time", "request", "status", "size", "method", "path"}


def test_ipv6_client_address_is_parsed():
    assert parse_line(line(ip="::1"))["ip"] == "::1"


def test_timezone_offset_is_dropped():
    # Current behaviour: the timestamp is naive and the -0700 offset is thrown away.
    entry = parse_line(VALID)
    assert entry["time"].tzinfo is None
    assert entry["time"].hour == 10


# --- parse_line: lines that do not match -----------------------------------------------


@pytest.mark.parametrize("text", ["not a log line", "", "   ", "192.168.1.1 only an ip"])
def test_non_matching_text_returns_none(text):
    assert parse_line(text) is None


# --- parse_line: known crashes (bugs fixed in #7) --------------------------------------

KNOWN_CRASHES = [
    pytest.param(line(request="-", status=408, size="0"), id="request-is-a-dash"),
    pytest.param(line(request="GET /", status=400, size="0"), id="two-token-request"),
    pytest.param(line(request="GET /a b HTTP/1.1"), id="space-in-path"),
    pytest.param(line(when="99/Foo/2025:10:00:00 +0000"), id="impossible-date"),
]


@pytest.mark.parametrize("text", KNOWN_CRASHES)
@pytest.mark.xfail(strict=True, raises=ValueError, reason="known bug, fixed in #7")
def test_known_crash_inputs_should_not_raise(text):
    parse_line(text)


# --- parse_file ------------------------------------------------------------------------


def test_parse_file_reads_the_sample_log_in_order():
    entries = parse_file(SAMPLE)
    assert [e["ip"] for e in entries] == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.1",
        "192.168.1.4",
    ]
    assert [e["status"] for e in entries] == [200, 401, 200, 404, 200]


def test_parse_file_silently_skips_junk_lines(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(f"{VALID}\nthis is junk\n\n{line(status=404)}\nmore junk\n")
    entries = parse_file(path)
    assert [e["status"] for e in entries] == [200, 404]


def test_parse_file_on_empty_file_returns_empty_list(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("")
    assert parse_file(path) == []


def test_parse_file_on_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "does-not-exist.log")


def test_parse_file_accepts_a_string_path(tmp_path):
    path = tmp_path / "one.log"
    path.write_text(VALID + "\n")
    assert len(parse_file(str(path))) == 1


def test_parse_file_handles_missing_final_newline(tmp_path):
    path = tmp_path / "nonewline.log"
    path.write_text(VALID)
    assert len(parse_file(path)) == 1


def test_parse_file_crashes_on_a_bad_line_instead_of_skipping_it(tmp_path):
    # Current behaviour: one malformed request line aborts the whole file.
    path = tmp_path / "bad.log"
    path.write_text(f"{VALID}\n{line(request='-', status=408, size='0')}\n")
    with pytest.raises(ValueError):
        parse_file(path)


def test_parse_file_raises_on_invalid_utf8(tmp_path):
    # Observed by running it: an invalid byte raises UnicodeDecodeError. Not in the original
    # list of known crashes. Planned fix: open with errors="replace" (#8). When fixed,
    # this test fails and should be replaced by one asserting the line is read.
    path = tmp_path / "binary.log"
    path.write_bytes(b'1.1.1.1 - - [01/Jun/2025:10:00:00 -0700] "GET /\xff HTTP/1.1" 200 5\n')
    with pytest.raises(UnicodeDecodeError):
        parse_file(path)
