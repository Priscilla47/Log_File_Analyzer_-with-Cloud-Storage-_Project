"""The detections list, the per-address view and the kept analysis (issues #81, #82, #83)."""

from datetime import datetime, timedelta
from pathlib import Path

from loginsight.dashboard import data, filters
from loginsight.detection.models import Severity
from tests.dashboard.test_render import GOOD, Upload, run

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
DEMO = (SAMPLES / "demo.log").read_bytes()


def demo(**choices):
    return run(Upload(DEMO, "demo.log"), **choices)


def report():
    return data.analyze_upload(DEMO, "demo.log").report


def tables(fake):
    return [call[0] for call in fake.calls if call[0] == "dataframe"], fake.of("dataframe")


class TestTheFilters:
    def test_four_filters_each_value_with_its_count(self):
        fake = demo()
        detections = report().detections
        ((_, severities, _),) = [c[1:] for c in fake.calls if c[0] == "multiselect"][:1]
        assert severities == tuple(
            f"{s} ({n})" for s, n in filters.severity_counts(detections).items()
        )
        by_label = filters.label_counts(detections)
        (classes,) = [c[2] for c in fake.calls if c[0] == "multiselect" and c[1] == "Class"]
        assert classes == tuple(f"{label} ({n})" for label, n in by_label.items())
        (address,) = [c for c in fake.calls if c[0] == "selectbox" and c[1] == "Address"][:1]
        assert address[4].startswith("filter_ip:")
        assert address[3] == tuple(f"{a} ({n})" for a, n in filters.ip_counts(detections).items())
        (slider,) = [c for c in fake.calls if c[0] == "slider"]
        assert slider[1] == "Time range (UTC)"
        assert slider[2:4] == filters.time_bounds(detections)
        assert slider[4] == filters.SLIDER_STEP

    def test_no_choice_lists_every_detection(self):
        fake = demo()
        detections = report().detections
        assert (f"Showing {len(detections)} of {len(detections)} detections.",) in fake.of(
            "caption"
        )
        table = fake.of("dataframe")[0][0]
        assert table == filters.detections_table(detections)

    def test_the_widget_keys_belong_to_the_chosen_file(self):
        keys = [c[-1] for c in demo().calls if c[0] in ("multiselect", "selectbox")]
        assert keys and all(key.endswith(":a1b2c3") for key in keys)
        assert len(set(keys)) == len(keys)

    def test_the_slider_key_belongs_to_the_chosen_file_too(self):
        # a slider that kept its position from another file would hide detections silently
        keys = [c[5] for c in demo().calls if c[0] == "slider"]
        assert keys == ["filter_time:a1b2c3"]

    def test_choosing_a_severity_narrows_the_table(self):
        everything = report().detections
        fake = demo(Severity=[Severity.CRITICAL])
        expected = [d for d in everything if d.severity is Severity.CRITICAL]
        assert expected and len(expected) < len(everything)
        assert fake.of("dataframe")[0][0] == filters.detections_table(expected)
        assert (f"Showing {len(expected)} of {len(everything)} detections.",) in fake.of("caption")

    def test_the_conditions_combine(self):
        everything = report().detections
        label = everything[0].label
        fake = demo(Class=[label], filter_ip=everything[0].ip, Severity=[everything[0].severity])
        expected = filters.filter_detections(
            everything, [everything[0].severity], [label], everything[0].ip
        )
        assert fake.of("dataframe")[0][0] == filters.detections_table(expected)

    def test_a_time_range_keeps_the_detections_inside_it(self):
        everything = report().detections
        first, last = filters.time_bounds(everything)
        fake = demo(time=(first, first + (last - first) / 2))
        assert 0 < len(fake.of("dataframe")[0][0]["Rule"]) < len(everything)

    def test_nothing_matching_says_so_and_draws_no_table(self):
        fake = demo(Severity=[Severity.CRITICAL], Class=["scanner"], filter_ip="203.0.113.250")
        assert ("No detection matches these filters.",) in fake.of("info")
        assert (f"Showing 0 of {len(report().detections)} detections.",) in fake.of("caption")

    def test_a_log_without_detections_says_so_and_offers_no_filters(self):
        fake = run(Upload(GOOD.encode()))
        assert fake.of("success") == [("No attacks were detected in this log.",)]
        assert not {"multiselect", "slider"} & set(fake.names())

    def test_all_detections_in_one_second_need_no_slider(self):
        line = (
            '203.0.113.9 - - [10/Oct/2026:10:00:01 +0000] "GET /?q=1%27%20UNION%20SELECT%201 '
            'HTTP/1.1" 200 5 "-" "x"\n'
        )
        fake = run(Upload(line.encode()))
        assert len(fake.of("dataframe")[0][0]["Rule"]) >= 1 and "slider" not in fake.names()

    def test_many_addresses_are_capped_and_the_page_says_so(self):
        lines = "".join(
            f"198.51.{n // 250}.{n % 250 + 1} - - [10/Oct/2026:10:00:01 +0000] "
            f'"GET /?q=1%27%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x"\n'
            for n in range(260)
        )
        fake = run(Upload(lines.encode()))
        (box,) = [c for c in fake.calls if c[0] == "selectbox" and c[1] == "Address"]
        assert len(box[2]) == filters.MAX_ADDRESS_CHOICES == 200
        assert (
            "The address list holds the 200 addresses with the most detections of 260.",
        ) in fake.of("caption")

    def test_a_short_list_of_addresses_has_no_cap_note(self):
        assert not any("address list holds" in c[0] for c in demo().of("caption"))

    def test_a_hostile_address_is_escaped_in_its_choice_label(self):
        line = (
            "203.0.113.9\x1b[31m - - [10/Oct/2026:10:00:01 +0000] "
            '"GET /?q=1%27%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x"\n'
        )
        fake = run(Upload(line.encode()))
        (box,) = [c for c in fake.calls if c[0] == "selectbox" and c[1] == "Address"]
        assert all("\x1b" not in label for label in box[3])

    def test_the_section_comes_after_the_charts(self):
        names = demo().names()
        assert names.index("bar_chart") < names.index("multiselect") < names.index("dataframe")


class TestTheSliderRange:
    FULL = (datetime(2026, 1, 1, 10), datetime(2026, 1, 1, 11))

    def test_the_whole_range_applies_no_limit(self):
        assert filters.range_to_filter(self.FULL, self.FULL) == (None, None)

    def test_a_part_includes_its_last_second(self):
        lo, hi = datetime(2026, 1, 1, 10, 5), datetime(2026, 1, 1, 10, 6)
        assert filters.range_to_filter(self.FULL, (lo, hi)) == (lo, hi + timedelta(seconds=1))

    def test_a_chosen_range_keeps_the_detections_on_its_last_second_and_drops_the_next(self):
        from datetime import timezone

        from loginsight.dashboard.filters import filter_detections
        from loginsight.detection.models import Detection

        def at(second, rule):
            return Detection(
                rule_id=rule, label="xss", severity=Severity.HIGH, ip="203.0.113.5",
                time=datetime(2026, 1, 1, 10, 0, second, tzinfo=timezone.utc),
                first_index=0, last_index=0, count=1, evidence="x",
            )  # fmt: skip

        rows = [at(0, "a"), at(1, "b"), at(2, "c"), at(3, "d")]
        full = filters.time_bounds(rows)
        one, two = datetime(2026, 1, 1, 10, 0, 1), datetime(2026, 1, 1, 10, 0, 2)

        def kept(chosen):
            start, end = filters.range_to_filter(full, chosen)
            return [d.rule_id for d in filter_detections(rows, start=start, end=end)]

        assert kept(full) == ["a", "b", "c", "d"]  # the whole range excludes nothing
        assert kept((one, two)) == ["b", "c"]  # the last second is in, the next one is out
        assert kept((one, one)) == ["b"]
        assert kept((full[0], two)) == ["a", "b", "c"]

    def test_bounds_are_the_first_and_last_second_and_none_without_a_choice(self):
        detections = report().detections
        lo, hi = filters.time_bounds(detections)
        assert lo.microsecond == hi.microsecond == 0 and lo.tzinfo is None and lo < hi
        assert filters.time_bounds([]) is None
        assert filters.time_bounds(detections[:1]) is None
