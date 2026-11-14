"""filter_detections and the tables behind the detections list (issue #81)."""

from datetime import datetime, timedelta, timezone

import pytest

from loginsight.dashboard import filters
from loginsight.dashboard.filters import (
    detections_table,
    filter_detections,
    ip_counts,
    label_counts,
    same_address,
    severity_counts,
)
from loginsight.detection.models import Detection, Severity

T0 = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)


def det(rule="r", label="xss", severity=Severity.HIGH, ip="203.0.113.5", minutes=0, **kwargs):
    return Detection(
        rule_id=rule,
        label=label,
        severity=severity,
        ip=ip,
        time=kwargs.pop("time", T0 + timedelta(minutes=minutes)),
        first_index=0,
        last_index=kwargs.pop("last_index", 0),
        count=kwargs.pop("count", 1),
        evidence=kwargs.pop("evidence", "GET /x"),
        **kwargs,
    )


A = det("a", "sql_injection", Severity.CRITICAL, "203.0.113.5", 0)
B = det("b", "xss", Severity.HIGH, "203.0.113.6", 10)
C = det("c", "xss", Severity.MEDIUM, "203.0.113.5", 20)
D = det("d", "scanner", Severity.LOW, "2001:db8::1", 30)
ALL = [A, B, C, D]


class TestEachFilterAlone:
    def test_no_condition_keeps_everything_in_order(self):
        assert filter_detections(ALL) == ALL

    def test_severity(self):
        assert filter_detections(ALL, severities={Severity.HIGH, Severity.LOW}) == [B, D]

    def test_class(self):
        assert filter_detections(ALL, labels=["xss"]) == [B, C]

    def test_ip(self):
        assert filter_detections(ALL, ip="203.0.113.5") == [A, C]

    def test_start_alone(self):
        assert filter_detections(ALL, start=T0 + timedelta(minutes=20)) == [C, D]

    def test_end_alone(self):
        assert filter_detections(ALL, end=T0 + timedelta(minutes=20)) == [A, B]


class TestCombined:
    def test_conditions_combine_with_and(self):
        result = filter_detections(
            ALL, severities={Severity.CRITICAL, Severity.MEDIUM}, labels={"xss"}, ip="203.0.113.5"
        )
        assert result == [C]

    def test_every_condition_at_once(self):
        result = filter_detections(
            ALL,
            severities=set(Severity),
            labels={"xss", "scanner"},
            ip="203.0.113.6",
            start=T0,
            end=T0 + timedelta(hours=1),
        )
        assert result == [B]

    def test_no_match_gives_an_empty_list(self):
        assert filter_detections(ALL, labels={"xss"}, severities={Severity.CRITICAL}) == []

    def test_an_empty_list_of_detections(self):
        assert filter_detections([], severities={Severity.HIGH}, ip="1.2.3.4") == []

    def test_an_empty_choice_allows_nothing_but_none_allows_everything(self):
        assert filter_detections(ALL, severities=set()) == []
        assert filter_detections(ALL, labels=[]) == []
        assert filter_detections(ALL, severities=None, labels=None) == ALL

    def test_the_input_is_not_changed_and_a_new_list_is_returned(self):
        original = list(ALL)
        result = filter_detections(ALL)
        assert ALL == original and result is not ALL


class TestTimeBoundaries:
    def test_start_is_included_and_end_is_excluded(self):
        at = T0 + timedelta(minutes=10)  # exactly B's time
        assert B in filter_detections(ALL, start=at)
        assert B not in filter_detections(ALL, end=at)
        assert filter_detections(ALL, start=at, end=at) == []

    def test_one_microsecond_either_side(self):
        at = T0 + timedelta(minutes=10)
        eps = timedelta(microseconds=1)
        assert B not in filter_detections(ALL, start=at + eps)
        assert B in filter_detections(ALL, end=at + eps)

    def test_times_with_other_offsets_are_compared_as_instants(self):
        plus_two = timezone(timedelta(hours=2))
        late = det("l", time=datetime(2026, 10, 10, 12, 5, tzinfo=plus_two))  # 10:05 UTC
        assert filter_detections([late], start=T0 + timedelta(minutes=5)) == [late]
        assert filter_detections([late], end=T0 + timedelta(minutes=5)) == []
        assert filter_detections([late], start=datetime(2026, 10, 10, 12, 5, tzinfo=plus_two))

    def test_a_time_without_a_zone_is_utc(self):
        naive = det("n", time=datetime(2026, 10, 10, 10, 30))
        assert filter_detections([naive], start=T0 + timedelta(minutes=30)) == [naive]
        assert filter_detections([naive], end=datetime(2026, 10, 10, 10, 30)) == []
        assert filter_detections([A], start=datetime(2026, 10, 10, 10, 0)) == [A]


class TestAddresses:
    def test_the_same_ipv6_address_written_differently_matches(self):
        assert filter_detections(ALL, ip="2001:0DB8:0:0:0:0:0:1") == [D]

    def test_an_address_that_is_a_prefix_does_not_match(self):
        assert filter_detections(ALL, ip="203.0.113.") == []
        assert filter_detections(ALL, ip="203.0.113.50") == []

    def test_text_that_is_not_an_address_only_equals_itself(self):
        odd = det("o", ip="not-an-ip")
        assert filter_detections([odd, A], ip="not-an-ip") == [odd]
        assert filter_detections([odd], ip="NOT-AN-IP") == []

    @pytest.mark.parametrize(
        ("first", "second", "same"),
        [
            ("1.2.3.4", "1.2.3.4", True),
            ("::1", "0:0:0:0:0:0:0:1", True),
            ("1.2.3.4", "1.2.3.5", False),
            ("1.2.3.4", "::ffff:1.2.3.4", False),
            ("", "", True),
            ("", "1.2.3.4", False),
        ],
    )
    def test_same_address(self, first, second, same):
        assert same_address(first, second) is same


class TestHostileText:
    EVIL = "GET /<script>alert(1)</script>\x1b[31m **bold** [x](javascript:alert(1))\x00"

    def test_the_table_holds_the_evidence_as_escaped_text(self):
        table = detections_table([det(evidence=self.EVIL, ip="1.2.3.4\x1b")])
        (evidence,) = table["Evidence"]
        assert "\x1b" not in evidence and "\x00" not in evidence
        assert "\\x1b[31m" in evidence and "\\x00" in evidence
        assert "<script>" in evidence  # kept as text: the table never renders it as HTML
        assert table["IP"] == ["1.2.3.4\\x1b"]

    def test_filtering_by_hostile_evidence_text_is_not_a_thing(self):
        # the evidence is not a filter at all: nothing in it can change what is kept
        assert filter_detections([det(evidence=self.EVIL)], ip="1.2.3.4") == []


class TestCounts:
    def test_severity_counts_list_every_severity_most_serious_first(self):
        assert severity_counts(ALL + [det("e")]) == {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 1,
            Severity.LOW: 1,
        }
        assert list(severity_counts([])) == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        assert set(severity_counts([]).values()) == {0}

    def test_label_counts_most_frequent_first_then_by_name_and_only_those_that_occur(self):
        assert list(label_counts(ALL).items()) == [("xss", 2), ("scanner", 1), ("sql_injection", 1)]
        assert label_counts([]) == {}

    def test_ip_counts_most_frequent_first_then_by_address(self):
        assert list(ip_counts(ALL).items()) == [
            ("203.0.113.5", 2),
            ("2001:db8::1", 1),
            ("203.0.113.6", 1),
        ]
        assert ip_counts([]) == {}


class TestTable:
    def test_one_column_per_name_and_one_row_per_detection_in_order(self):
        table = detections_table(ALL)
        assert tuple(table) == filters.COLUMNS
        assert {len(column) for column in table.values()} == {4}
        assert table["Rule"] == ["a", "b", "c", "d"]
        assert table["Class"] == ["sql_injection", "xss", "xss", "scanner"]
        assert table["Requests"] == [1, 1, 1, 1]

    def test_a_burst_shows_how_many_requests_it_holds(self):
        burst = det("burst", "brute_force", count=12, last_index=11)
        assert detections_table([A, burst])["Requests"] == [1, 12]

    def test_the_badge_names_the_severity_in_words(self):
        badges = detections_table(ALL)["Severity"]
        assert [b.split(" ", 1)[1] for b in badges] == ["critical", "high", "medium", "low"]
        assert len(set(badges)) == 4

    def test_times_are_utc_without_a_zone_so_every_row_reads_the_same(self):
        plus_two = timezone(timedelta(hours=2))
        row = det(time=datetime(2026, 10, 10, 12, 0, tzinfo=plus_two))
        assert detections_table([row])["Time (UTC)"] == [datetime(2026, 10, 10, 10, 0)]

    def test_the_time_bounds_are_whole_seconds(self):
        early = det("e", time=datetime(2026, 10, 10, 10, 0, 0, 900_000, tzinfo=timezone.utc))
        late = det("l", time=datetime(2026, 10, 10, 10, 0, 5, 100_000, tzinfo=timezone.utc))
        assert filters.time_bounds([early, late]) == (
            datetime(2026, 10, 10, 10, 0, 0),
            datetime(2026, 10, 10, 10, 0, 5),
        )
        assert filters.time_bounds([early, det("same", time=early.time)]) is None

    def test_no_detections_give_empty_columns(self):
        table = detections_table([])
        assert tuple(table) == filters.COLUMNS and not any(table.values())
