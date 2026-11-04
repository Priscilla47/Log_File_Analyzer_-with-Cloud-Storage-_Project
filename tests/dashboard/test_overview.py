"""The overview the dashboard shows for an uploaded log: numbers, cards, errors and warnings."""

import json
from pathlib import Path

import pytest

from loginsight.cli import main
from loginsight.dashboard import data
from loginsight.dashboard.data import UPLOAD_LIMIT_BYTES, UPLOAD_LIMIT_MB, Card, analyze_upload
from loginsight.reporting.report import human_bytes

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
BAD = '203.0.113.6 - - [10/Oct/2026:10:00:02 +0000] "GET /missing HTTP/1.1" 404 10 "-" "x"\n'
SERVER = '203.0.113.7 - - [10/Oct/2026:10:00:03 +0000] "GET /boom HTTP/1.1" 500 20 "-" "x"\n'


def cards(outcome):
    return {card.label: card for card in outcome.cards}


class TestTheLimit:
    def test_the_limit_is_fifty_megabytes(self):
        assert UPLOAD_LIMIT_MB == 50
        assert UPLOAD_LIMIT_BYTES == 50 * 1024 * 1024

    def test_a_file_of_exactly_the_limit_is_accepted(self):
        raw = (GOOD * 3).encode().ljust(UPLOAD_LIMIT_BYTES, b"\n")  # blank lines are ignored
        assert analyze_upload(raw, "big.log").error is None

    def test_one_byte_more_is_refused_with_a_readable_message(self):
        outcome = analyze_upload(b"x" * (UPLOAD_LIMIT_BYTES + 1), "big.log")
        assert outcome.cards == [] and outcome.report is None
        assert outcome.error == (
            "This file is 50.0 MB, and the dashboard takes files up to 50 MB. "
            "For a bigger log use the command line: loginsight analyze FILE"
        )

    def test_the_limit_can_be_given(self):
        assert analyze_upload(GOOD.encode(), "a.log", limit=10).error is not None
        assert analyze_upload(GOOD.encode(), "a.log", limit=len(GOOD)).error is None


class TestTheCards:
    def test_the_five_headline_numbers_in_order(self):
        outcome = analyze_upload((GOOD + BAD + SERVER + "junk\n").encode(), "a.log")
        assert [card.label for card in outcome.cards] == [
            "Requests",
            "Unique IPs",
            "Error rate",
            "Data sent",
            "Skipped lines",
        ]

    def test_the_values(self):
        outcome = analyze_upload((GOOD + BAD + SERVER + "junk\n").encode(), "a.log")
        by_label = cards(outcome)
        assert by_label["Requests"].value == "3"
        assert by_label["Unique IPs"].value == "3"
        assert by_label["Error rate"].value == "66.7%"
        assert by_label["Data sent"].value == human_bytes(1530)
        assert by_label["Skipped lines"].value == "1"

    def test_each_card_explains_itself(self):
        outcome = analyze_upload(GOOD.encode(), "a.log")
        assert all(isinstance(card, Card) and len(card.help) > 10 for card in outcome.cards)
        assert "4xx and 5xx" in cards(outcome)["Error rate"].help
        assert "of 1 lines" in cards(outcome)["Skipped lines"].help

    def test_the_facts_about_the_file_are_listed(self):
        outcome = analyze_upload((GOOD + "junk\n").encode(), "some/dir/access.log")
        assert outcome.facts == [
            "File: access.log",
            "Format: apache",
            "Lines: 2 read, 1 parsed, 1 skipped (50.0% parsed)",
        ]

    def test_the_format_is_detected(self):
        raw = (SAMPLES / "demo_nginx.log").read_bytes()
        assert "Format: nginx" in analyze_upload(raw, "demo_nginx.log").facts

    def test_the_report_is_kept_for_the_charts(self):
        outcome = analyze_upload(GOOD.encode(), "a.log")
        assert outcome.report.summary.total_requests == 1 and outcome.name == "a.log"


class TestEqualsTheCommandLine:
    @pytest.mark.parametrize("sample", ["demo.log", "demo_nginx.log", "clean.log"])
    def test_every_number_matches_the_json_report(self, sample, capsys):
        assert main(["analyze", str(SAMPLES / sample), "--format", "json"]) == 0
        summary = json.loads(capsys.readouterr().out)["summary"]
        outcome = analyze_upload((SAMPLES / sample).read_bytes(), sample)
        by_label = cards(outcome)
        assert by_label["Requests"].value == str(summary["total_requests"])
        assert by_label["Unique IPs"].value == str(summary["unique_ips"])
        assert by_label["Error rate"].value == f"{summary['error_rate']:.1%}"
        assert by_label["Data sent"].value == human_bytes(summary["total_bytes"])

    @pytest.mark.parametrize("sample", ["demo.log", "demo_nginx.log", "clean.log"])
    def test_the_skipped_count_matches_the_json_report(self, sample, capsys):
        main(["analyze", str(SAMPLES / sample), "--format", "json"])
        parse = json.loads(capsys.readouterr().out)["source"]["parse"]
        outcome = analyze_upload((SAMPLES / sample).read_bytes(), sample)
        assert cards(outcome)["Skipped lines"].value == str(parse["skipped"])
        assert f"of {parse['total_lines']} lines" in cards(outcome)["Skipped lines"].help

    def test_the_whole_report_equals_the_one_the_command_line_builds(self, capsys):
        from loginsight.reporting.report import render_json

        main(["detect", str(SAMPLES / "demo.log"), "--format", "json"])
        cli_json = capsys.readouterr().out
        outcome = analyze_upload((SAMPLES / "demo.log").read_bytes(), "demo.log")
        assert render_json(outcome.report) == cli_json

    def test_the_demo_log_numbers(self):
        outcome = analyze_upload((SAMPLES / "demo.log").read_bytes(), "demo.log")
        assert cards(outcome)["Requests"].value == "500"


class TestWarningsAndErrors:
    def test_no_warning_for_a_clean_log(self):
        assert analyze_upload((GOOD * 5).encode(), "a.log").warnings == []

    def test_the_same_warning_as_the_command_line_when_many_lines_are_skipped(self):
        outcome = analyze_upload((GOOD * 8 + "junk\n" * 2).encode(), "a.log")
        assert outcome.warnings == ["2 of 10 lines (20%) could not be read"]
        assert outcome.error is None and outcome.cards  # a warning still shows the numbers

    def test_exactly_ten_percent_gives_none(self):
        assert analyze_upload((GOOD * 9 + "junk\n").encode(), "a.log").warnings == []

    def test_a_file_in_another_format_is_an_error_not_a_crash(self):
        outcome = analyze_upload(("2026-10-10 INFO started\n" * 3).encode(), "a.log")
        assert outcome.cards == [] and outcome.report is None
        assert outcome.error == (
            "None of the 3 lines could be read as an access-log entry (no_match: 3). "
            "Is this an Apache or Nginx access log?"
        )

    def test_binary_data_is_an_error_not_a_crash(self):
        outcome = analyze_upload(bytes(range(256)) * 20, "a.log")
        assert outcome.error is not None and "None of the" in outcome.error

    def test_an_empty_file_is_not_an_error_but_says_there_is_nothing_to_show(self):
        for raw in (b"", b"\n\n  \n"):
            outcome = analyze_upload(raw, "empty.log")
            assert outcome.error is None
            assert outcome.notice == "The file has no requests in it."
            assert cards(outcome)["Requests"].value == "0"
            assert cards(outcome)["Error rate"].value == "0.0%"

    def test_a_normal_log_has_no_notice(self):
        assert analyze_upload(GOOD.encode(), "a.log").notice is None

    def test_an_error_message_never_contains_text_from_the_file(self):
        hostile = b"**bold** [click](http://evil) <script>\n"
        outcome = analyze_upload(hostile, "**x**.log")
        assert "bold" not in outcome.error and "evil" not in outcome.error
        assert "x**" not in outcome.error

    def test_bad_bytes_and_a_byte_order_mark_are_handled_like_the_command_line(self):
        raw = b"\xef\xbb\xbf" + GOOD.encode() + b"\xff\xfe garbage\n"
        outcome = analyze_upload(raw, "a.log")
        assert cards(outcome)["Requests"].value == "1"
        assert cards(outcome)["Skipped lines"].value == "1"

    def test_a_byte_order_mark_does_not_end_up_in_the_first_address(self):
        outcome = analyze_upload(b"\xef\xbb\xbf" + GOOD.encode(), "a.log")
        assert outcome.report.summary.top_ips == [("203.0.113.5", 1)]

    def test_an_invalid_byte_becomes_a_replacement_character_not_nothing(self):
        raw = GOOD.replace("/index.html", "/a\x00b").encode().replace(b"\x00", b"\xff")
        path = analyze_upload(raw, "a.log").report.summary.top_paths[0][0]
        assert path == "/a\ufffdb"  # exactly what the command line reads

    def test_the_skipped_card_counts_lines_of_the_file_not_parsed_ones(self):
        outcome = analyze_upload((GOOD + "junk\n" + "more junk\n").encode(), "a.log")
        assert cards(outcome)["Skipped lines"].help.endswith("out of 3 lines in the file.")

    def test_crlf_and_old_mac_line_endings(self):
        raw = (GOOD.rstrip("\n") + "\r\n" + BAD.rstrip("\n") + "\r").encode()
        assert cards(analyze_upload(raw, "a.log"))["Requests"].value == "2"


def test_the_helpers_hold_no_streamlit():
    assert not hasattr(data, "st") and not hasattr(data, "streamlit")
