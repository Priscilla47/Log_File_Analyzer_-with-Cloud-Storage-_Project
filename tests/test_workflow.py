"""analyze_text: the steps the command line and the dashboard share."""

import json
from pathlib import Path

import pytest

from loginsight.detection import Severity, load_rules
from loginsight.reporting.report import render_json
from loginsight.workflow import (
    SKIP_WARNING_SHARE,
    Analysis,
    NothingReadError,
    analyze_text,
)

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"
GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
SQLI = (
    "198.51.100.8 - - [10/Oct/2026:10:00:03 +0000] "
    '"GET /s?q=1\'+UNION+SELECT+1 HTTP/1.1" 200 10 "-" "x"\n'
)


class TestResult:
    def test_it_returns_a_report_and_no_warnings_for_a_clean_log(self):
        analysis = analyze_text(GOOD * 5, "access.log")
        assert isinstance(analysis, Analysis)
        assert analysis.report.source_name == "access.log"
        assert analysis.report.summary.total_requests == 5
        assert analysis.warnings == []

    def test_the_format_is_detected_and_recorded(self):
        apache = analyze_text((SAMPLES / "demo.log").read_text(), "demo.log").report
        nginx = analyze_text((SAMPLES / "demo_nginx.log").read_text(), "demo_nginx.log").report
        assert (apache.log_format, nginx.log_format) == ("apache", "nginx")

    def test_it_gives_the_same_report_as_the_command_line(self, capsys):
        from loginsight.cli import main

        text = (SAMPLES / "demo.log").read_text()
        assert main(["detect", str(SAMPLES / "demo.log"), "--format", "json"]) == 0
        cli_report = json.loads(capsys.readouterr().out)
        mine = json.loads(render_json(analyze_text(text, "demo.log").report))
        assert mine == cli_report

    def test_the_options_reach_the_report(self):
        text = (SAMPLES / "demo.log").read_text()
        report = analyze_text(text, "demo.log", top_n=3, bucket="minute").report
        assert len(report.summary.top_ips) == 3 and report.bucket == "minute"

    def test_a_path_is_reduced_to_the_file_name(self):
        assert analyze_text(GOOD, "some/dir/x.log").report.source_name == "x.log"


class TestDetections:
    def test_the_default_rules_are_used(self):
        report = analyze_text(GOOD + SQLI, "a.log").report
        assert [d.label for d in report.detections] == ["sql_injection"]

    def test_given_rules_replace_them(self):
        rules = load_rules()
        none = type(rules)(signatures=(), brute_force=rules.brute_force, scanner=rules.scanner)
        assert analyze_text(GOOD + SQLI, "a.log", rules=none).report.detections == []

    def test_the_minimum_severity_filters_before_the_report_is_built(self):
        text = GOOD + SQLI
        assert len(analyze_text(text, "a.log", min_severity=Severity.HIGH).report.detections) == 1
        assert analyze_text(text, "a.log", min_severity=Severity.CRITICAL).report.detections == []


class TestProblems:
    def test_a_file_where_no_line_can_be_read_raises(self):
        with pytest.raises(NothingReadError) as raised:
            analyze_text("junk\n" * 4, "a.log")
        error = raised.value
        assert (error.total_lines, error.reasons) == (4, "no_match: 4")
        assert "4 lines" in str(error) and "no_match: 4" in str(error)

    def test_several_reasons_are_listed(self):
        with pytest.raises(NothingReadError) as raised:
            analyze_text("junk\n" + "x" * 9000 + "\n", "a.log")
        assert set(raised.value.reasons.split(", ")) == {"no_match: 1", "line_too_long: 1"}

    @pytest.mark.parametrize("text", ["", "\n", "  \n\t\n"])
    def test_an_empty_log_is_not_an_error(self, text):
        analysis = analyze_text(text, "a.log")
        assert analysis.report.summary.total_requests == 0 and analysis.warnings == []

    def test_a_log_with_a_few_bad_lines_gives_no_warning(self):
        assert analyze_text(GOOD * 9 + "junk\n", "a.log").warnings == []  # exactly 10 percent

    def test_more_bad_lines_than_the_share_gives_a_warning(self):
        analysis = analyze_text(GOOD * 8 + "junk\n" * 2, "a.log")
        assert analysis.warnings == ["2 of 10 lines (20%) could not be read"]

    def test_the_share_is_ten_percent(self):
        assert SKIP_WARNING_SHARE == 0.10
        assert analyze_text(GOOD * 17 + "junk\n" * 2, "a.log").warnings == [
            "2 of 19 lines (11%) could not be read"
        ]

    def test_a_bad_bucket_or_format_is_still_a_value_error(self):
        with pytest.raises(ValueError):
            analyze_text(GOOD, "a.log", bucket="week")
