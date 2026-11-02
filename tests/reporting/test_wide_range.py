"""A log that covers too long a time still gives a report, with a note that gaps are not listed."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.cli import EXIT_OK, main
from loginsight.detection import detect
from loginsight.parsing.parser import parse_file, parse_text
from loginsight.reporting.report import build_report, render_json, render_markdown
from loginsight.reporting.text import render_text

GOLDEN = Path(__file__).parent / "golden"
UTC = timezone.utc


def line(when):
    return (
        f"203.0.113.9 - - [{when.strftime('%d/%b/%Y:%H:%M:%S')} +0000] "
        '"GET /a HTTP/1.1" 200 5 "-" "x"'
    )


def build(times, bucket="hour"):
    result = parse_text("\n".join(line(t) for t in times) + "\n")
    return build_report(result, detect(result.entries), source_name="w.log", bucket=bucket)


NOW = datetime(2026, 10, 10, 10, 0, 0, tzinfo=UTC)
STRAY = datetime(1970, 1, 1, 0, 0, 5, tzinfo=UTC)


class TestBuildReport:
    def test_a_stray_old_timestamp_does_not_stop_the_report(self):
        report = build([NOW, NOW + timedelta(minutes=5), STRAY])
        assert report.gaps_filled is False
        assert [b.requests for b in report.buckets] == [1, 2]

    def test_a_long_log_with_minute_buckets_does_not_stop_the_report(self):
        report = build([NOW, NOW + timedelta(days=100)], bucket="minute")
        assert report.gaps_filled is False and len(report.buckets) == 2

    def test_a_normal_log_is_filled_as_before(self):
        report = build([NOW, NOW + timedelta(hours=3)])
        assert report.gaps_filled is True and len(report.buckets) == 4

    def test_no_entries_counts_as_filled(self):
        assert build_report(parse_text(""), [], source_name="e.log").gaps_filled is True

    def test_the_golden_log_is_filled(self):
        result = parse_file(GOLDEN / "tiny.log")
        assert build_report(result, [], source_name="tiny.log").gaps_filled is True

    def test_other_errors_still_propagate(self):
        with pytest.raises(ValueError, match="bucket must be one of"):
            build([NOW], bucket="week")


class TestRenderings:
    def test_json_says_whether_gaps_are_filled(self):
        filled = json.loads(render_json(build([NOW, NOW + timedelta(hours=2)])))
        sparse = json.loads(render_json(build([NOW, STRAY])))
        assert filled["traffic"]["gaps_filled"] is True
        assert sparse["traffic"]["gaps_filled"] is False
        assert list(sparse["traffic"]) == ["bucket", "gaps_filled", "buckets"]

    def test_markdown_has_the_note_only_when_not_filled(self):
        note = "Quiet periods are not listed"
        assert note in render_markdown(build([NOW, STRAY]))
        assert note not in render_markdown(build([NOW, NOW + timedelta(hours=2)]))

    def test_the_analyze_view_has_the_note_only_when_not_filled(self):
        note = "Quiet periods are not listed"
        assert note in render_text(build([NOW, STRAY]), "analyze")
        assert note not in render_text(build([NOW, NOW + timedelta(hours=2)]), "analyze")

    def test_the_detect_view_shows_no_traffic_and_so_no_note(self):
        assert "Quiet periods" not in render_text(build([NOW, STRAY]), "detect")

    def test_the_chart_can_be_drawn(self, tmp_path):
        from loginsight.reporting.writers import write_report

        written = write_report(build([NOW, STRAY]), tmp_path / "out")
        assert all(path.is_file() for path in written)


class TestCommandLine:
    @pytest.fixture
    def stray_log(self, tmp_path):
        path = tmp_path / "stray.log"
        path.write_text(
            "\n".join(line(NOW + timedelta(minutes=n)) for n in range(5))
            + "\n"
            + line(STRAY)
            + "\n"
        )
        return path

    @pytest.mark.parametrize("command", ["analyze", "detect"])
    @pytest.mark.parametrize("fmt", ["text", "md", "json"])
    def test_every_command_and_format_works(self, stray_log, capsys, command, fmt):
        assert main([command, str(stray_log), "--format", fmt]) == EXIT_OK
        out, err = capsys.readouterr()
        assert err == "" and "Traceback" not in out
        shows_traffic = fmt == "md" or (fmt == "text" and command == "analyze")
        assert ("Quiet periods are not listed" in out) == shows_traffic

    def test_a_long_log_with_minute_buckets(self, tmp_path, capsys):
        path = tmp_path / "long.log"
        path.write_text(line(NOW) + "\n" + line(NOW + timedelta(days=120)) + "\n")
        assert main(["analyze", str(path), "--bucket", "minute", "--format", "json"]) == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["traffic"]["gaps_filled"] is False
        assert [b["requests"] for b in data["traffic"]["buckets"]] == [1, 1]

    def test_the_output_folder_gets_all_files(self, stray_log, tmp_path, capsys):
        out = tmp_path / "out"
        assert main(["analyze", str(stray_log), "--output", str(out)]) == EXIT_OK
        assert capsys.readouterr().err == ""
        assert sorted(p.name for p in out.rglob("*") if p.is_file()) == [
            "report.json", "report.md", "status.png", "top_paths.png", "traffic.png",
        ]  # fmt: skip
