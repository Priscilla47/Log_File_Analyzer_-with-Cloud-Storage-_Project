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


class TestReadingThenBuilding:
    """The slow part (reading) and the cheap part (a report for one period) are separate."""

    def test_reading_then_building_equals_analysing_for_every_period(self):
        from loginsight.workflow import build, read_text

        text = (SAMPLES / "demo.log").read_text()
        reading = read_text(text)
        for bucket in ("minute", "hour", "day"):
            expected = analyze_text(text, "demo.log", bucket=bucket)
            assert build(reading, "demo.log", bucket=bucket) == expected.report
            assert reading.warnings == expected.warnings
            assert reading.entries == expected.entries

    def test_building_does_not_change_the_reading(self):
        from loginsight.workflow import build, read_text

        reading = read_text(GOOD * 3 + SQLI)
        before = (list(reading.detections), list(reading.entries), list(reading.warnings))
        for bucket in ("minute", "day", "hour"):
            build(reading, "a.log", bucket=bucket, top_n=1)
        assert (reading.detections, reading.entries, reading.warnings) == before

    def test_only_the_traffic_depends_on_the_period(self):
        from loginsight.workflow import build, read_text

        reading = read_text(GOOD * 2 + SQLI)
        minute, day = (build(reading, "a.log", bucket=b) for b in ("minute", "day"))
        assert minute.buckets != day.buckets and minute.bucket == "minute" and day.bucket == "day"
        assert minute.summary == day.summary and minute.detections == day.detections

    def test_the_detections_and_the_rules_are_applied_when_reading(self):
        from loginsight.workflow import read_text

        reading = read_text(GOOD + SQLI)
        assert [d.label for d in reading.detections] == ["sql_injection"]
        assert read_text(GOOD + SQLI, min_severity=Severity.CRITICAL).detections == []
        assert reading.log_format == "apache"

    def test_a_log_nothing_can_be_read_from_is_refused_when_reading(self):
        from loginsight.workflow import read_text

        with pytest.raises(NothingReadError):
            read_text("junk\nmore junk\n")

    def test_an_empty_text_reads_to_nothing(self):
        from loginsight.workflow import build, read_text

        reading = read_text("")
        assert reading.entries == [] and reading.detections == [] and reading.warnings == []
        assert build(reading, "a.log").summary.total_requests == 0

    def test_a_wrong_period_or_count_is_refused_when_building(self):
        from loginsight.workflow import build, read_text

        reading = read_text(GOOD)
        with pytest.raises(ValueError):
            build(reading, "a.log", bucket="week")
        with pytest.raises(ValueError):
            build(reading, "a.log", top_n=-1)

    def test_a_reading_cannot_be_changed_by_assigning(self):
        from loginsight.workflow import read_text

        reading = read_text(GOOD)
        with pytest.raises(AttributeError):
            reading.log_format = "nginx"  # type: ignore[misc]


def _file_opener(path, opened):
    """An ``open_lines`` that records every file it opens."""

    def open_lines():
        file = open(path, encoding="utf-8-sig", errors="replace")
        opened.append(file)
        return file

    return open_lines


# the same awkward logs the parsers are tested with: endings, a byte order mark, junk
LOGS = {
    "unix": GOOD * 3 + SQLI,
    "windows": (GOOD * 3 + SQLI).replace("\n", "\r\n"),
    "old mac": (GOOD * 3 + SQLI).replace("\n", "\r"),
    "mixed": GOOD + "\r\n" + SQLI + "\r" + GOOD + "junk\r\n",
    "junk between": GOOD + "junk\n\n" + SQLI + "more junk\n",
    "mostly junk": GOOD + "junk\n" * 5,
    "empty": "",
}


class TestReadingLines:
    @pytest.mark.parametrize("name", LOGS)
    def test_it_gives_what_reading_the_text_gives(self, name, tmp_path):
        from loginsight.workflow import read_lines, read_text

        path = tmp_path / "a.log"
        path.write_bytes(LOGS[name].encode())
        opened = []
        streamed = read_lines(_file_opener(path, opened))
        assert streamed == read_text(LOGS[name])

    @pytest.mark.parametrize("name", ["demo.log", "demo_nginx.log", "clean.log"])
    def test_it_gives_the_same_report_on_the_samples(self, name):
        from loginsight.workflow import build, read_lines

        text = (SAMPLES / name).read_text()
        streamed = build(read_lines(_file_opener(SAMPLES / name, [])), name)
        assert streamed == analyze_text(text, name).report

    def test_a_byte_order_mark_and_invalid_bytes_are_handled_like_a_file(self, tmp_path):
        from loginsight.workflow import read_bytes, read_lines

        raw = b"\xef\xbb\xbf" + (GOOD * 2).encode() + b"bad \xff\xfe line\n" + SQLI.encode()
        path = tmp_path / "a.log"
        path.write_bytes(raw)
        reading = read_lines(_file_opener(path, []))
        assert reading == read_bytes(raw)
        assert len(reading.entries) == 3 and reading.result.stats.skipped == 1

    def test_it_opens_the_log_twice_and_closes_both(self, tmp_path):
        from loginsight.workflow import read_lines

        path = tmp_path / "a.log"
        path.write_text(GOOD)
        opened = []
        read_lines(_file_opener(path, opened))
        assert len(opened) == 2 and all(file.closed for file in opened)

    def test_the_file_is_closed_when_nothing_can_be_read(self, tmp_path):
        from loginsight.workflow import read_lines

        path = tmp_path / "a.log"
        path.write_text("junk\n")
        opened = []
        with pytest.raises(NothingReadError):
            read_lines(_file_opener(path, opened))
        assert opened and all(file.closed for file in opened)

    def test_the_file_is_closed_when_reading_fails(self, tmp_path):
        from loginsight.workflow import read_lines

        class Broken:
            closed = False

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                Broken.closed = True

            def __iter__(self):
                raise OSError("disk went away")

        with pytest.raises(OSError, match="disk went away"):
            read_lines(Broken)  # type: ignore[arg-type]
        assert Broken.closed

    def test_a_log_is_never_held_as_one_text(self, tmp_path):
        """Only lines are asked of the file: nothing calls ``read()`` for all of it."""
        from loginsight.workflow import read_lines

        path = tmp_path / "a.log"
        path.write_text(GOOD * 3 + SQLI)

        class Wrapper:
            def __init__(self):
                self.inner = open(path, encoding="utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.inner.close()

            def __iter__(self):
                return iter(self.inner)

            def read(self, *args):
                raise AssertionError("the whole log was read as one text")

        assert len(read_lines(Wrapper).entries) == 4

    def test_the_options_apply(self, tmp_path):
        from loginsight.workflow import read_lines

        path = tmp_path / "a.log"
        path.write_text(GOOD + SQLI)
        opener = _file_opener(path, [])
        assert read_lines(opener, min_severity=Severity.CRITICAL).detections == []
        none = type(load_rules())(
            signatures=(), brute_force=load_rules().brute_force, scanner=load_rules().scanner
        )
        assert read_lines(opener, rules=none).detections == []

    def test_reading_bytes_equals_reading_their_text(self):
        from loginsight.workflow import read_bytes, read_text

        for text in LOGS.values():
            assert read_bytes(text.encode()) == read_text(text)

    def test_the_bytes_and_the_options(self):
        from loginsight.workflow import read_bytes

        raw = (GOOD + SQLI).encode()
        assert read_bytes(raw, min_severity=Severity.CRITICAL).detections == []
        assert len(read_bytes(raw).detections) == 1
        with pytest.raises(NothingReadError):
            read_bytes(b"junk\n")


class TestTheDetectedFormatIsUsedToParse:
    NGINX = GOOD.replace('"x"', r'"a\x22b \xC3\xA9"')

    def test_an_nginx_log_is_parsed_with_its_escapes_decoded(self, tmp_path):
        from loginsight.workflow import read_lines

        path = tmp_path / "n.log"
        path.write_text(self.NGINX * 2)
        reading = read_lines(_file_opener(path, []))
        assert reading.log_format == "nginx"
        assert [e.user_agent for e in reading.entries] == ['a"b é'] * 2

    def test_the_same_for_text_and_bytes(self):
        from loginsight.workflow import read_bytes, read_text

        for reading in (read_text(self.NGINX), read_bytes(self.NGINX.encode())):
            assert reading.log_format == "nginx" and reading.entries[0].user_agent == 'a"b é'
