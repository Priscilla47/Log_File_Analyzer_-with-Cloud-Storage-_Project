"""Tests for the report: its content, the JSON layout and the Markdown rendering."""

import json
import re
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginsight import __version__
from loginsight.analysis.summary import summarize
from loginsight.detection import Detection, Severity, detect
from loginsight.parsing.models import LogEntry, ParseIssue, ParseResult, ParseStats
from loginsight.parsing.parser import parse_file
from loginsight.reporting import report as report_module
from loginsight.reporting.report import (
    MAX_PROBLEMS_SHOWN,
    MAX_TABLE_ROWS,
    build_report,
    render_json,
    render_markdown,
)

GOLDEN = Path(__file__).parent / "golden"
SAMPLES = Path(__file__).parents[2] / "data" / "samples"
T0 = datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc)
KEYS = ["tool", "source", "summary", "traffic", "detections"]


def make_entry(**changes) -> LogEntry:
    fields = dict(
        ip="203.0.113.1", time=T0, method="GET", path="/", query="", protocol="HTTP/1.1",
        status=200, size=10, request="GET / HTTP/1.1",
    )  # fmt: skip
    return LogEntry(**{**fields, **changes})


def make_stats(entries=(), issues=(), skipped=0) -> ParseStats:
    return ParseStats(
        total_lines=len(entries) + skipped,
        parsed=len(entries),
        skipped=skipped,
        skipped_by_reason={"no_match": skipped} if skipped else {},
        first_errors=list(issues),
    )


def make_result(entries=(), issues=(), skipped=0) -> ParseResult:
    entries = list(entries)
    return ParseResult(entries=entries, stats=make_stats(entries, issues, skipped))


def make_detection(**changes) -> Detection:
    fields = dict(
        rule_id="sqli-union-select", label="sql_injection", severity=Severity.HIGH,
        ip="198.51.100.7", time=T0, first_index=0, last_index=0, count=1, evidence="GET /x",
    )  # fmt: skip
    return Detection(**{**fields, **changes})


def report_for(entries=(), detections=(), **options):
    return build_report(make_result(entries), list(detections), source_name="access.log", **options)


@pytest.fixture(scope="module")
def tiny():
    result = parse_file(GOLDEN / "tiny.log")
    return result, detect(result.entries)


class TestBuildReport:
    def test_holds_what_it_was_given(self, tiny):
        result, detections = tiny
        report = build_report(result, detections, source_name="tiny.log", top_n=3, bucket="minute")
        assert report.source_name == "tiny.log"
        assert report.stats is result.stats
        assert report.summary == summarize(result.entries, 3)
        assert report.bucket == "minute"
        assert sum(b.requests for b in report.buckets) == 4
        assert len(report.buckets) == 66  # 10:00 to 11:05, empty minutes included
        assert report.detections == detections

    def test_defaults_are_ten_and_hour(self, tiny):
        report = build_report(tiny[0], [], source_name="tiny.log")
        assert report.bucket == "hour"
        assert report.summary == summarize(tiny[0].entries, 10)

    @pytest.mark.parametrize(
        "name",
        ["/var/log/nginx/access.log", "C:\\logs\\access.log", "logs/access.log", "access.log"],
    )
    def test_source_is_the_file_name_only(self, name):
        report = build_report(make_result(), [], source_name=name)
        assert report.source_name == "access.log"

    def test_a_trailing_slash_is_ignored(self):
        assert build_report(make_result(), [], source_name="logs/dir/").source_name == "dir"

    def test_detections_are_ordered_by_severity(self):
        low = make_detection(rule_id="a-low", severity=Severity.LOW, first_index=0, last_index=0)
        high = make_detection(rule_id="b-high", severity=Severity.HIGH, first_index=5, last_index=5)
        mid = make_detection(rule_id="c-mid", severity=Severity.MEDIUM, first_index=2, last_index=2)
        report = report_for(detections=[low, high, mid])
        assert [d.rule_id for d in report.detections] == ["b-high", "c-mid", "a-low"]

    def test_the_input_list_is_not_changed(self):
        low = make_detection(rule_id="a-low", severity=Severity.LOW)
        high = make_detection(rule_id="b-high")
        given = [low, high]
        report_for(detections=given)
        assert given == [low, high]

    @pytest.mark.parametrize("bucket", ["day", "", "Hour", None])
    def test_bad_bucket_is_rejected_even_without_entries(self, bucket):
        with pytest.raises(ValueError, match="bucket"):
            report_for(bucket=bucket)

    def test_negative_top_n_is_rejected(self):
        with pytest.raises(ValueError, match="top_n"):
            report_for(top_n=-1)

    def test_top_n_limits_the_top_lists(self):
        entries = [make_entry(path=f"/p{i}") for i in range(5)]
        assert len(report_for(entries, top_n=2).summary.top_paths) == 2

    def test_is_frozen(self):
        with pytest.raises(FrozenInstanceError):
            report_for().bucket = "minute"

    def test_empty_input_gives_an_empty_report(self):
        report = report_for()
        assert report.buckets == [] and report.detections == []
        assert report.summary.total_requests == 0


class TestRenderJson:
    def test_has_the_documented_keys_in_order(self, tiny):
        data = json.loads(render_json(build_report(*tiny, source_name="tiny.log")))
        assert list(data) == KEYS
        assert list(data["tool"]) == ["name", "version"]
        assert data["tool"] == {"name": "loginsight", "version": __version__}
        assert list(data["source"]) == ["name", "parse"]
        assert list(data["traffic"]) == ["bucket", "buckets"]

    def test_parse_statistics(self, tiny):
        parse = json.loads(render_json(build_report(*tiny, source_name="t")))["source"]["parse"]
        assert parse["total_lines"] == 5
        assert parse["parsed"] == 4
        assert parse["skipped"] == 1
        assert parse["success_rate"] == 0.8
        assert parse["skipped_by_reason"] == {"no_match": 1}
        assert parse["first_errors"] == [
            {"line_number": 5, "reason": "no_match", "line": "this line is not a log line"}
        ]

    def test_counts_match_summarize_and_detect(self, tiny):
        result, detections = tiny
        data = json.loads(render_json(build_report(result, detections, source_name="t")))
        assert data["summary"] == summarize(result.entries).to_dict()
        assert data["detections"] == [d.to_dict() for d in detections]
        assert [b["requests"] for b in data["traffic"]["buckets"]] == [2, 2]
        assert [b["errors"] for b in data["traffic"]["buckets"]] == [0, 2]
        assert data["traffic"]["buckets"][0]["start"] == "2026-10-10T10:00:00+00:00"
        assert data["traffic"]["bucket"] == "hour"

    def test_layout(self):
        text = render_json(report_for())
        assert text.endswith("}\n") and not text.endswith("\n\n")
        assert text.startswith('{\n  "tool": {\n    "name"')  # 2-space indent

    def test_empty_input_is_valid_json(self):
        data = json.loads(render_json(report_for()))
        assert list(data) == KEYS
        assert data["summary"]["total_requests"] == 0
        assert data["summary"]["first_time"] is None
        assert data["traffic"]["buckets"] == []
        assert data["detections"] == []
        assert data["source"]["parse"]["success_rate"] == 1.0

    def test_text_is_not_ascii_escaped(self):
        report = report_for([make_entry(path="/café")])
        assert "/café" in render_json(report)

    def test_skipped_lines_listed_at_most_ten(self):
        issues = [ParseIssue(i, "no_match", f"junk {i}") for i in range(1, 13)]
        report = build_report(make_result([], issues, skipped=12), [], source_name="t")
        data = json.loads(render_json(report))
        assert len(data["source"]["parse"]["first_errors"]) == MAX_PROBLEMS_SHOWN == 10

    def test_is_deterministic(self, tiny):
        first = render_json(build_report(*tiny, source_name="tiny.log"))
        second = render_json(build_report(*tiny, source_name="tiny.log"))
        assert first == second

    def test_matches_the_golden_file(self, tiny):
        text = render_json(build_report(*tiny, source_name="tiny.log"))
        expected = (GOLDEN / "tiny.json").read_text(encoding="utf-8")
        assert text.replace(f'"{__version__}"', '"VERSION"') == expected


class TestRenderMarkdown:
    def test_matches_the_golden_file(self, tiny):
        text = render_markdown(build_report(*tiny, source_name="tiny.log"))
        assert text == (GOLDEN / "tiny.md").read_text(encoding="utf-8")

    def test_has_the_sections(self, tiny):
        text = render_markdown(build_report(*tiny, source_name="tiny.log"))
        headings = re.findall(r"^## (.+)$", text, re.MULTILINE)
        assert headings == ["Summary", "Status codes", "Traffic", "Detections", "Parse problems"]
        assert text.startswith("# Log report: tiny.log\n")
        assert text.endswith("\n") and not text.endswith("\n\n")

    def test_empty_input(self):
        text = render_markdown(report_for())
        assert "No detections found." in text
        assert "No traffic." in text
        assert "Requests: 0" in text
        assert "First request: -" in text
        assert "Error rate (4xx and 5xx): 0.0%" in text
        assert "## Parse problems" not in text
        assert "Top IP addresses" not in text

    def test_parse_problems_only_when_something_was_skipped(self, tiny):
        clean = report_for([make_entry()])
        assert "Parse problems" not in render_markdown(clean)
        assert "## Parse problems" in render_markdown(build_report(*tiny, source_name="t"))

    def test_parse_problems_list_at_most_ten_lines(self):
        issues = [ParseIssue(i, "no_match", f"junk {i}") for i in range(1, 13)]
        report = build_report(make_result([], issues, skipped=12), [], source_name="t")
        text = render_markdown(report)
        assert "12 of 12 lines could not be read" in text
        assert "The first 10 are listed." in text
        assert text.count("| junk ") == 10
        assert "junk 10" in text and "junk 11" not in text

    def test_no_first_n_note_when_all_problems_are_listed(self):
        issues = [ParseIssue(1, "no_match", "junk")]
        text = render_markdown(build_report(make_result([], issues, 1), [], source_name="t"))
        assert "are listed" not in text

    def test_reasons_are_listed_in_order(self):
        stats = ParseStats(
            total_lines=5, parsed=0, skipped=5,
            skipped_by_reason={"no_match": 3, "bad_size": 2}, first_errors=[],
        )  # fmt: skip
        report = build_report(ParseResult(entries=[], stats=stats), [], source_name="t")
        assert "(bad_size: 2, no_match: 3)" in render_markdown(report)

    def test_charts_are_linked_only_when_asked(self, tiny):
        report = build_report(*tiny, source_name="t")
        assert "charts/" not in render_markdown(report)
        text = render_markdown(report, charts=True)
        for name in ("status.png", "traffic.png", "top_paths.png"):
            assert f"](charts/{name})" in text
        assert text.rstrip().splitlines()[-1] == "![Top paths](charts/top_paths.png)"

    def test_detections_are_listed_by_severity(self):
        detections = [
            make_detection(rule_id="a-low", severity=Severity.LOW),
            make_detection(rule_id="b-high"),
        ]
        text = render_markdown(report_for(detections=detections))
        assert text.index("b-high") < text.index("a-low")
        assert "| high | b-high | 198.51.100.7 | 2026-10-10T10:00:00+00:00 | 1 | GET /x |" in text

    def test_big_tables_are_cut_with_a_note(self):
        detections = [
            make_detection(rule_id=f"rule-{i}", first_index=i, last_index=i)
            for i in range(MAX_TABLE_ROWS + 7)
        ]
        text = render_markdown(report_for(detections=detections))
        assert text.count("| high | rule-") == MAX_TABLE_ROWS == 100
        assert "_7 more not shown; the JSON report has them all._" in text

    def test_a_table_of_exactly_the_limit_has_no_note(self):
        detections = [
            make_detection(rule_id=f"rule-{i}", first_index=i, last_index=i)
            for i in range(MAX_TABLE_ROWS)
        ]
        assert "more not shown" not in render_markdown(report_for(detections=detections))

    def test_traffic_names_the_busiest_period(self):
        entries = [
            make_entry(time=T0),
            make_entry(time=T0.replace(hour=11)),
            make_entry(time=T0.replace(hour=11, minute=5)),
        ]
        text = render_markdown(report_for(entries))
        assert "Requests per hour, over 2 periods." in text
        assert "started at 2026-10-10T11:00:00+00:00 with 2 requests" in text
        assert "Requests per minute" in render_markdown(report_for(entries, bucket="minute"))

    def test_human_sizes(self):
        sizes = {0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB",
                 1024**2: "1.0 MiB", 5 * 1024**3: "5.0 GiB", 2 * 1024**4: "2.0 TiB"}  # fmt: skip
        for count, text in sizes.items():
            assert report_module._human_bytes(count) == text

    def test_data_sent_uses_human_sizes(self):
        text = render_markdown(report_for([make_entry(size=2048)]))
        assert "- Data sent: 2.0 KiB" in text

    def test_is_deterministic(self, tiny):
        report = build_report(*tiny, source_name="tiny.log")
        assert render_markdown(report) == render_markdown(report)


HOSTILE = [
    "a|b",
    "<script>alert(1)</script>",
    "`code`",
    "line one\nline two",
    "carriage\rreturn",
    "tab\there",
    "[link](http://evil.example)",
    "![img](http://evil.example/x.png)",
    "*bold* _em_ ~~gone~~",
    "&lt;b&gt; &amp;",
    "back\\slash",
    "nul\x00byte \x1b[31m escape",
    "| --- | --- |",
    "\u2028 line separator",
]


class TestEscaping:
    @pytest.mark.parametrize("text", HOSTILE)
    def test_hostile_text_cannot_break_the_detections_table(self, text):
        detection = make_detection(evidence=text, ip=text)
        lines = render_markdown(report_for(detections=[detection])).splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("| Severity"))
        rows = []
        for line in lines[start:]:
            if not line:
                break
            rows.append(line)
        assert len(rows) == 3  # header, separator, one row
        for row in rows:
            # every unescaped pipe is a cell border: 6 cells, so 7 borders
            assert len(re.findall(r"(?<!\\)\|", row)) == 7

    @pytest.mark.parametrize("text", HOSTILE)
    def test_nothing_is_left_that_markdown_or_html_could_act_on(self, text):
        out = report_module._escape(text)
        for char in "`*_[]()<>|&#~!":
            assert not re.search(rf"(?<!\\){re.escape(char)}", out) or char not in text
        assert "\n" not in out and "\r" not in out and "\x00" not in out and "\x1b" not in out

    def test_a_script_tag_does_not_appear_as_a_tag(self):
        text = render_markdown(
            report_for(detections=[make_detection(evidence="<script>x</script>")])
        )
        assert "<script>" not in text and "</script>" not in text
        assert r"\<script\>" in text

    def test_a_backslash_cannot_cancel_the_escape(self):
        # "\|" in the log must not turn the escaped pipe into a cell border
        assert report_module._escape("\\|") == "\\\\\\|"

    def test_paths_ips_and_the_source_name_are_escaped_too(self):
        entry = make_entry(ip="a|b", path="/x|y<i>")
        text = render_markdown(build_report(make_result([entry]), [], source_name="we|ird.log"))
        assert "# Log report: we\\|ird.log" in text
        assert "| a\\|b | 1 |" in text
        assert "| /x\\|y\\<i\\> | 1 |" in text

    def test_parse_problem_text_is_escaped(self):
        issue = ParseIssue(3, "no_match", "<b>|`x`\nnext")
        text = render_markdown(build_report(make_result([], [issue], 1), [], source_name="t"))
        assert "| 3 | no\\_match | \\<b\\>\\|\\`x\\` next |" in text

    def test_plain_text_is_left_alone(self):
        assert report_module._escape("GET /index.html HTTP/1.1") == "GET /index.html HTTP/1.1"
        assert report_module._escape("") == ""


class TestNoWallClockNoAbsolutePath:
    def test_two_reports_built_apart_are_identical(self, tiny):
        a = build_report(*tiny, source_name="/home/me/tiny.log")
        b = build_report(*tiny, source_name="/other/place/tiny.log")
        assert render_json(a) == render_json(b)
        assert render_markdown(a) == render_markdown(b)

    def test_the_source_path_never_appears(self, tiny):
        report = build_report(*tiny, source_name="/home/secret-user/logs/tiny.log")
        for text in (render_json(report), render_markdown(report, charts=True)):
            assert "secret-user" not in text and "/home/" not in text

    def test_the_current_year_is_not_in_the_output(self):
        # an empty report has no log time in it, so any date or time would come from the clock
        for text in (render_json(report_for()), render_markdown(report_for())):
            assert not re.search(r"\d{4}-\d{2}-\d{2}", text)
            assert not re.search(r"\d{2}:\d{2}", text)

    def test_the_module_does_not_read_the_clock(self):
        source = Path(report_module.__file__).read_text(encoding="utf-8")
        for forbidden in ("now(", "today(", "utcnow", "time.time", "import time", "Path.cwd"):
            assert forbidden not in source


class TestDemoLog:
    @pytest.fixture(scope="class")
    @classmethod
    def demo(cls):
        result = parse_file(SAMPLES / "demo.log")
        detections = detect(result.entries)
        return result, detections, build_report(result, detections, source_name="demo.log")

    def test_counts_match_summarize_and_detect(self, demo):
        result, detections, report = demo
        data = json.loads(render_json(report))
        assert data["summary"]["total_requests"] == summarize(result.entries).total_requests == 500
        assert len(data["detections"]) == len(detections) == 34
        assert data["source"]["parse"]["parsed"] == 500
        assert sum(b["requests"] for b in data["traffic"]["buckets"]) == 500

    def test_markdown_lists_every_detection(self, demo):
        _, detections, report = demo
        text = render_markdown(report)
        rows = re.findall(r"^\| (?:low|medium|high|critical) \|", text, re.MULTILINE)
        assert len(rows) == len(detections)

    def test_is_deterministic(self, demo):
        result, detections, report = demo
        again = build_report(result, detections, source_name="demo.log")
        assert render_json(report) == render_json(again)
        assert render_markdown(report) == render_markdown(again)

    def test_a_changed_detection_changes_the_report(self, demo):
        _, _, report = demo
        other = replace(report, detections=report.detections[1:])
        assert render_json(other) != render_json(report)
