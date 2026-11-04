"""The tables behind the dashboard's charts: plain data, equal to the numbers in the report."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.dashboard import data
from loginsight.dashboard.data import (
    BUCKETS,
    DEFAULT_BUCKET,
    analyze_upload,
    status_table,
    top_paths_table,
    traffic_table,
)

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
UTC = timezone.utc


def line(status=200, path="/a", when="10/Oct/2026:10:00:01 +0000", ip="203.0.113.5"):
    return f'{ip} - - [{when}] "GET {path} HTTP/1.1" {status} 100 "-" "x"\n'


def report_of(text, bucket="hour"):
    return analyze_upload(text.encode(), "a.log", bucket=bucket).report


class TestTheChoices:
    def test_the_buckets_offered(self):
        assert BUCKETS == ("minute", "hour", "day") and DEFAULT_BUCKET == "hour"

    def test_the_default_is_one_of_them(self):
        assert DEFAULT_BUCKET in BUCKETS


class TestStatusTable:
    def test_the_four_main_classes_are_always_there_in_order(self):
        table = status_table(report_of(line(200)))
        assert table == {"Status class": ["2xx", "3xx", "4xx", "5xx"], "Requests": [1, 0, 0, 0]}

    def test_the_numbers_are_the_reports(self):
        text = line(200) * 3 + line(301) + line(404) * 2 + line(500)
        report = report_of(text)
        table = status_table(report)
        classes = report.summary.status_classes
        assert dict(zip(table["Status class"], table["Requests"], strict=True)) == {
            name: classes[name] for name in ("2xx", "3xx", "4xx", "5xx")
        }

    def test_other_classes_appear_only_when_they_have_requests(self):
        table = status_table(report_of(line(200) + line(101) + line(999)))
        assert table["Status class"] == ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]
        assert table["Requests"] == [1, 1, 0, 0, 0, 1]

    def test_an_empty_log_gives_the_four_main_classes_with_zeros(self):
        assert status_table(report_of("")) == {
            "Status class": ["2xx", "3xx", "4xx", "5xx"],
            "Requests": [0, 0, 0, 0],
        }

    def test_the_columns_have_the_same_length(self):
        table = status_table(report_of(line(101) + line(200)))
        assert len({len(column) for column in table.values()}) == 1

    def test_the_total_is_the_number_of_requests(self):
        text = line(200) * 4 + line(404) + line(101)
        assert sum(status_table(report_of(text))["Requests"]) == 6


class TestTrafficTable:
    def test_one_row_per_period_with_requests_and_errors(self):
        text = line(200, when="10/Oct/2026:10:05:00 +0000") + line(
            500, when="10/Oct/2026:12:10:00 +0000"
        )
        table = traffic_table(report_of(text))
        assert list(table) == ["Time (UTC)", "Requests", "Errors"]
        assert table["Time (UTC)"] == [
            datetime(2026, 10, 10, 10, tzinfo=UTC),
            datetime(2026, 10, 10, 11, tzinfo=UTC),
            datetime(2026, 10, 10, 12, tzinfo=UTC),
        ]
        assert table["Requests"] == [1, 0, 1] and table["Errors"] == [0, 0, 1]

    def test_the_numbers_are_the_reports(self):
        report = analyze_upload((SAMPLES / "demo.log").read_bytes(), "demo.log").report
        table = traffic_table(report)
        assert table["Requests"] == [b.requests for b in report.buckets]
        assert table["Errors"] == [b.errors for b in report.buckets]
        assert sum(table["Requests"]) == report.summary.total_requests

    def test_an_empty_log_gives_empty_columns(self):
        assert traffic_table(report_of("")) == {"Time (UTC)": [], "Requests": [], "Errors": []}

    @pytest.mark.parametrize("bucket", BUCKETS)
    def test_the_series_has_one_row_per_period_of_the_chosen_size(self, bucket):
        times = [
            datetime(2026, 10, 10, 10, 0, tzinfo=UTC) + timedelta(minutes=m) for m in (0, 90, 3000)
        ]
        text = "".join(line(when=t.strftime("%d/%b/%Y:%H:%M:%S +0000")) for t in times)
        rows = len(traffic_table(report_of(text, bucket))["Requests"])
        assert rows == {"minute": 3001, "hour": 51, "day": 3}[bucket]

    def test_a_longer_period_gives_a_shorter_series(self):
        text = (SAMPLES / "demo.log").read_text()
        lengths = [len(traffic_table(report_of(text, b))["Requests"]) for b in BUCKETS]
        assert lengths == sorted(lengths, reverse=True) and len(set(lengths)) >= 2

    def test_whatever_the_period_the_totals_are_the_same(self):
        text = (SAMPLES / "demo.log").read_text()
        totals = {sum(traffic_table(report_of(text, b))["Requests"]) for b in BUCKETS}
        assert totals == {500}

    def test_a_wide_range_lists_only_the_periods_with_requests(self):
        text = line(when="10/Oct/2026:10:00:00 +0000") + line(when="10/Oct/1970:10:00:00 +0000")
        table = traffic_table(report_of(text, "minute"))
        assert table["Requests"] == [1, 1]


class TestTopPathsTable:
    def test_busiest_first_with_the_reports_counts(self):
        text = line(path="/a") * 3 + line(path="/b") * 5 + line(path="/c")
        table = top_paths_table(report_of(text))
        assert table == {"Path": ["/b", "/a", "/c"], "Requests": [5, 3, 1]}

    def test_it_is_the_reports_list(self):
        report = analyze_upload((SAMPLES / "demo.log").read_bytes(), "demo.log").report
        table = top_paths_table(report)
        assert list(zip(table["Path"], table["Requests"], strict=True)) == report.summary.top_paths

    def test_an_empty_log_gives_empty_columns(self):
        assert top_paths_table(report_of("")) == {"Path": [], "Requests": []}

    def test_a_long_path_is_shortened_with_an_ellipsis(self):
        table = top_paths_table(report_of(line(path="/" + "a" * 200)))
        label = table["Path"][0]
        assert len(label) == data.MAX_PATH_LABEL and label.endswith("…")
        assert label.startswith("/aaaa")

    def test_a_path_of_exactly_the_limit_is_kept(self):
        path = "/" + "b" * (data.MAX_PATH_LABEL - 1)
        assert top_paths_table(report_of(line(path=path)))["Path"] == [path]

    def test_the_limit_is_sixty_characters(self):
        sixty, sixty_one = "/" + "d" * 59, "/" + "d" * 60
        assert top_paths_table(report_of(line(path=sixty)))["Path"] == [sixty]
        assert top_paths_table(report_of(line(path=sixty_one)))["Path"] == ["/" + "d" * 58 + "…"]

    def test_control_characters_are_shown_as_escapes(self):
        raw = line(path="/a%00b").replace("%00", "\x01")
        label = top_paths_table(report_of(raw))["Path"][0]
        assert label == "/a\\x01b"

    def test_two_paths_that_look_alike_once_shortened_stay_two_bars(self):
        long = "/" + "c" * 100
        text = line(path=long + "x") * 3 + line(path=long + "y") * 2
        table = top_paths_table(report_of(text))
        assert len(set(table["Path"])) == 2 and table["Requests"] == [3, 2]
        assert table["Path"][0] != table["Path"][1]

    def test_a_request_without_a_path_gets_a_readable_label(self):
        raw = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "-" 408 0 "-" "x"\n'
        assert top_paths_table(report_of(raw))["Path"] == ["(no path)"]


class TestTheOutcomeCarriesThem:
    def test_a_good_file_has_all_three_and_the_bucket(self):
        outcome = analyze_upload((SAMPLES / "demo.log").read_bytes(), "demo.log", bucket="day")
        assert outcome.charts is not None and outcome.charts.bucket == "day"
        assert outcome.charts.status == status_table(outcome.report)
        assert outcome.charts.traffic == traffic_table(outcome.report)
        assert outcome.charts.top_paths == top_paths_table(outcome.report)

    def test_the_default_bucket_is_an_hour(self):
        assert analyze_upload((SAMPLES / "demo.log").read_bytes(), "d").charts.bucket == "hour"

    def test_a_file_that_cannot_be_read_has_no_charts(self):
        assert analyze_upload(b"junk\n" * 3, "a.log").charts is None

    def test_an_empty_file_has_no_charts_either(self):
        assert analyze_upload(b"", "a.log").charts is None

    def test_a_wide_range_says_the_gaps_are_not_filled(self):
        raw = line(when="10/Oct/2026:10:00:00 +0000") + line(when="10/Oct/1970:10:00:00 +0000")
        outcome = analyze_upload(raw.encode(), "a.log", bucket="minute")
        assert outcome.charts.gaps_filled is False
        assert analyze_upload(line().encode(), "a.log").charts.gaps_filled is True

    def test_a_bad_bucket_is_a_value_error(self):
        with pytest.raises(ValueError):
            analyze_upload(line().encode(), "a.log", bucket="week")

    def test_the_colours_are_colour_blind_safe_and_different(self):
        assert data.COLOUR_MAIN != data.COLOUR_ERRORS
        assert {data.COLOUR_MAIN, data.COLOUR_ERRORS} <= {
            "#0072B2",
            "#D55E00",
            "#009E73",
            "#E69F00",
        }
