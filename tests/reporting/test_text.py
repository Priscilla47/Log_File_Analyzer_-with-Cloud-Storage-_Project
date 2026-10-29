"""Tests for the plain-text views printed by the command line."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.detection import Severity, detect
from loginsight.parsing.models import LogEntry, ParseIssue, ParseResult, ParseStats
from loginsight.parsing.parser import parse_file
from loginsight.reporting.report import build_report
from loginsight.reporting.text import VIEWS, printable, render_text

GOLDEN = Path(__file__).parent / "golden"
T0 = datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc)


def entry(**changes) -> LogEntry:
    fields = dict(
        ip="203.0.113.1", time=T0, method="GET", path="/", query="", protocol="HTTP/1.1",
        status=200, size=10, request="GET / HTTP/1.1",
    )  # fmt: skip
    return LogEntry(**{**fields, **changes})


def report_of(entries, *, skipped=0, issues=(), source="access.log", detections=None, **options):
    entries = list(entries)
    stats = ParseStats(
        total_lines=len(entries) + skipped, parsed=len(entries), skipped=skipped,
        skipped_by_reason={"no_match": skipped} if skipped else {}, first_errors=list(issues),
    )  # fmt: skip
    result = ParseResult(entries=entries, stats=stats)
    found = detect(entries) if detections is None else detections
    return build_report(result, found, source_name=source, **options)


@pytest.fixture(scope="module")
def tiny():
    result = parse_file(GOLDEN / "tiny.log")
    return build_report(result, detect(result.entries), source_name="tiny.log")


class TestPrintable:
    def test_plain_text_is_unchanged(self):
        assert printable("GET /index.html?a=b HTTP/1.1") == "GET /index.html?a=b HTTP/1.1"
        assert printable("café ✓") == "café ✓"
        assert printable("") == ""

    @pytest.mark.parametrize(
        ("text", "shown"),
        [
            ("\x1b[31mred", "\\x1b[31mred"),
            ("a\nb", "a\\x0ab"),
            ("a\rb", "a\\x0db"),
            ("a\tb", "a\\x09b"),
            ("nul\x00", "nul\\x00"),
            ("\x7f", "\\x7f"),
            ("\x9b31m", "\\x9b31m"),  # the one-character terminal escape
            (" ", "\\u2028"),
            ("\U000e0001", "\\U000e0001"),
        ],
    )
    def test_control_characters_become_visible_escapes(self, text, shown):
        assert printable(text) == shown


class TestViews:
    def test_unknown_view_is_rejected(self, tiny):
        with pytest.raises(ValueError, match="view"):
            render_text(tiny, "summary")

    def test_views_constant(self):
        assert VIEWS == ("analyze", "detect")

    @pytest.mark.parametrize("view", VIEWS)
    def test_ends_with_one_newline(self, tiny, view):
        text = render_text(tiny, view)
        assert text.endswith("\n") and not text.endswith("\n\n")

    @pytest.mark.parametrize("view", VIEWS)
    def test_both_views_show_the_parse_statistics(self, tiny, view):
        text = render_text(tiny, view)
        assert "File: tiny.log" in text
        assert "Lines: 5 read, 4 parsed, 1 skipped (80.0% parsed)" in text
        assert "Skipped lines: no_match: 1" in text

    @pytest.mark.parametrize("view", VIEWS)
    def test_no_skipped_line_note_when_nothing_was_skipped(self, view):
        assert "Skipped lines" not in render_text(report_of([entry()]), view)

    @pytest.mark.parametrize("view", VIEWS)
    def test_the_file_name_is_shown_without_folders(self, view):
        text = render_text(report_of([entry()], source="/home/secret/logs/x.log"), view)
        assert "File: x.log" in text and "secret" not in text


class TestAnalyzeView:
    def test_content(self, tiny):
        text = render_text(tiny, "analyze")
        assert "Requests:     4" in text
        assert "Unique IPs:   2" in text
        assert "Data sent:    2.4 KiB" in text
        assert "Error rate:   50.0% (4xx and 5xx)" in text
        assert "First:        2026-10-10T10:00:01+00:00" in text
        assert "Last:         2026-10-10T11:05:40+00:00" in text
        assert "Status:       2xx 2, 4xx 1, 5xx 1" in text
        assert "Methods:      GET 4" in text
        assert "Top IP addresses\n  198.51.100.7  2\n  203.0.113.5   2\n" in text
        assert "Top paths" in text and "  /index.html  1" in text
        assert "Traffic per hour: 2 periods, the busiest started at 2026-10-10T10:00:00" in text
        assert "with 2 requests" in text
        assert "Detections: 1 (list them with `loginsight detect`)" in text

    def test_does_not_list_the_detections(self, tiny):
        assert "sqli-union-select" not in render_text(tiny, "analyze")

    def test_empty_input_says_so(self):
        text = render_text(report_of([]), "analyze")
        assert text.endswith("No requests found.\n")
        assert "Summary" not in text

    def test_one_period_is_singular(self):
        assert "1 period, the busiest" in render_text(report_of([entry()]), "analyze")

    def test_top_limits_the_lists(self):
        entries = [entry(path=f"/p{i}") for i in range(6)]
        text = render_text(report_of(entries, top_n=2), "analyze")
        assert text.count("  /p") == 2

    def test_bucket_is_named(self):
        assert "Traffic per minute:" in render_text(
            report_of([entry()], bucket="minute"), "analyze"
        )

    def test_hostile_text_is_shown_as_escapes(self):
        entries = [entry(path="/\x1b[2Jx", ip="\x1b]0;pwned\x07")]
        text = render_text(report_of(entries), "analyze")
        assert "\x1b" not in text and "\x07" not in text
        assert "/\\x1b[2Jx" in text

    def test_the_longest_name_sets_the_column_width(self):
        entries = [entry(path="/a"), entry(path="/a"), entry(path="/a-much-longer-path")]
        text = render_text(report_of(entries), "analyze")
        assert "  /a                   2\n  /a-much-longer-path  1\n" in text


class TestDetectView:
    def test_table(self, tiny):
        lines = render_text(tiny, "detect").splitlines()
        assert lines[4] == "Detections: 1"
        header, row = lines[5], lines[6]
        assert header.split()[:6] == ["SEVERITY", "RULE", "IP", "TIME", "COUNT", "EVIDENCE"]
        assert row.split()[:5] == [
            "high", "sqli-union-select", "198.51.100.7", "2026-10-10T11:05:30+00:00", "1",
        ]  # fmt: skip
        assert row.endswith("GET /search?q=1'+UNION+SELECT+password+FROM+users-- HTTP/1.1")
        # the columns line up
        assert header.index("RULE") == row.index("sqli-union-select")
        assert header.index("EVIDENCE") == row.index("GET /search")

    def test_no_detections(self):
        text = render_text(report_of([entry()]), "detect")
        assert text.endswith("\n\nNo detections found.\n")
        assert "SEVERITY" not in text

    def test_severity_order_is_kept(self):
        entries = [
            entry(path="/.env", request="GET /.env HTTP/1.1"),
            entry(path="/a", query="c=;id", request="GET /a?c=;id HTTP/1.1"),
        ]
        text = render_text(report_of(entries), "detect")
        severities = [line.split()[0] for line in text.splitlines()[5:]]
        order = [Severity.from_name(name) for name in severities]
        assert order == sorted(order, reverse=True) and len(order) >= 1

    def test_columns_widen_for_long_values(self):
        entries = [entry(ip="2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", path="/.env",
                         request="GET /.env HTTP/1.1")]  # fmt: skip
        lines = render_text(report_of(entries), "detect").splitlines()
        assert lines[-2].index("EVIDENCE") == lines[-1].index("GET /.env")

    def test_hostile_evidence_is_shown_as_escapes(self):
        request = "GET /.env\x1b[31m HTTP/1.1"
        text = render_text(report_of([entry(path="/.env", request=request)]), "detect")
        assert "\x1b" not in text
        assert "GET /.env\\x1b[31m HTTP/1.1" in text

    def test_no_wall_clock(self, tiny):
        assert render_text(tiny, "detect") == render_text(tiny, "detect")


def test_skipped_reasons_are_sorted():
    stats = ParseStats(
        total_lines=5, parsed=0, skipped=5,
        skipped_by_reason={"no_match": 3, "bad_size": 2}, first_errors=[ParseIssue(1, "x", "y")],
    )  # fmt: skip
    report = build_report(ParseResult(entries=[], stats=stats), [], source_name="t")
    assert "Skipped lines: bad_size: 2, no_match: 3" in render_text(report, "detect")


def test_times_use_the_log_time_not_the_clock():
    later = entry(time=T0 + timedelta(days=400))
    assert "2027-11-14" in render_text(report_of([later]), "analyze")


def test_the_busiest_period_is_the_one_with_most_requests():
    entries = [entry(time=T0)] * 3 + [entry(time=T0 + timedelta(hours=1))]
    text = render_text(report_of(entries), "analyze")
    assert "started at 2026-10-10T10:00:00+00:00 with 3 requests" in text


def test_a_source_name_with_control_characters_is_escaped():
    text = render_text(report_of([entry()], source="a\x1b[2Jb.log"), "detect")
    assert "\x1b" not in text and "File: a\\x1b[2Jb.log" in text


def test_a_hostile_address_is_escaped_in_the_detect_view():
    hostile = entry(ip="\x1b[2J", path="/.env", request="GET /.env HTTP/1.1")
    text = render_text(report_of([hostile]), "detect")
    assert "\x1b" not in text and "\\x1b[2J" in text


def test_top_zero_leaves_no_empty_lists():
    text = render_text(report_of([entry()], top_n=0), "analyze")
    assert "Top paths" not in text and "Top IP addresses" not in text
    assert "\n\n\n" not in text
