"""The per-address view and its tables (issue #82)."""

import functools
from pathlib import Path

from loginsight.dashboard import data, filters
from loginsight.parsing.parser import parse_file
from tests.dashboard.test_render import Upload, run

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
DEMO = (SAMPLES / "demo.log").read_bytes()


ENTRIES = parse_file(SAMPLES / "demo.log").entries  # read once: every test below uses it


def demo(**choices):
    return run(Upload(DEMO, "demo.log"), **choices)


@functools.cache
def report():
    return data.analyze_upload(DEMO, "demo.log").report


class TestOneAddress:
    def test_nothing_is_chosen_at_first(self):
        fake = demo()
        assert ("Choose an address to see everything it did.",) in fake.of("caption")
        assert ("This address does not appear in the log.",) not in fake.of("info")
        assert not {"column.metric"} & set(fake.names()[fake.names().index("subheader") :])
        assert "One address" in [c[0] for c in fake.of("subheader")]

    def test_the_choices_are_the_addresses_with_detections_then_the_busiest(self):
        fake = demo()
        choices = [c for c in fake.calls if c[0] == "selectbox" and c[1] == "Address"][1][2]
        assert choices == tuple(data.ip_choices(report()))
        counts = list(filters.ip_counts(report().detections))
        assert list(choices[: len(counts)]) == counts

    def test_a_chosen_address_shows_its_numbers_tables_and_detections(self):
        from loginsight.dashboard.profile import ip_profile

        entries = ENTRIES
        top = data.ip_choices(report())[0]
        fake = demo(address=top)
        profile = ip_profile(entries, report().detections, top)
        cards = {c[1]: c[2] for c in fake.calls if c[0] == "column.metric"}
        assert cards["Detections"] == str(len(profile.detections)) and profile.detections
        assert fake.of("columns")[-2:] == [(4,), (2,)]
        assert ("Responses it received",) in fake.of("caption")
        assert ("Paths it asked for",) in fake.of("caption")
        shown = [call[1] for call in fake.calls if call[0] == "dataframe"]
        assert data.profile_status_table(profile) in shown
        assert data.profile_paths_table(profile) in shown
        assert filters.detections_table(profile.detections) in shown
        assert ("No detections name this address.",) not in fake.of("caption")

    def test_an_address_without_detections_says_so(self):
        quiet = next(
            ip for ip in data.ip_choices(report()) if ip not in {d.ip for d in report().detections}
        )
        fake = demo(address=quiet)
        assert ("No detections name this address.",) in fake.of("caption")

    def test_an_address_that_is_not_in_the_log_gets_an_explicit_message(self):
        fake = demo(address="198.51.100.77")
        assert ("This address does not appear in the log.",) in fake.of("info")
        assert ("Responses it received",) not in fake.of("caption")


class TestTheProfileTables:
    def profile(self, ip):
        from loginsight.dashboard.profile import ip_profile

        entries = ENTRIES
        return ip_profile(entries, report().detections, ip, top_n=2)

    def test_cards_name_requests_times_and_detections(self):
        ip = data.ip_choices(report())[0]
        cards = data.profile_cards(self.profile(ip))
        assert [c.label for c in cards] == ["Requests", "First seen", "Last seen", "Detections"]
        assert cards[1].value.endswith(" UTC") and len(cards[0].help) > 10

    def test_an_unknown_address_has_dashes_not_a_crash(self):
        cards = data.profile_cards(self.profile("198.51.100.77"))
        assert [c.value for c in cards] == ["0", "-", "-", "0"]

    def test_the_status_table_lists_only_the_classes_it_got_and_adds_up(self):
        profile = self.profile(data.ip_choices(report())[0])
        table = data.profile_status_table(profile)
        assert sum(table["Requests"]) == profile.requests
        assert all(count > 0 for count in table["Requests"])

    def test_the_paths_table_ends_with_the_other_paths_so_it_adds_up(self):
        for ip in data.ip_choices(report()):
            profile = self.profile(ip)
            table = data.profile_paths_table(profile)
            assert sum(table["Requests"]) == profile.requests
            if profile.other_requests:
                assert table["Path"][-1].startswith("(other paths: ")
                assert table["Path"][-1] == f"(other paths: {profile.distinct_paths - 2})"
            else:
                assert not any(p.startswith("(other paths") for p in table["Path"])

    def test_hostile_paths_are_escaped(self):
        from loginsight.dashboard.profile import IpProfile

        profile = IpProfile(
            ip="1.2.3.4", known=True, requests=1, first_seen=None, last_seen=None,
            status_classes={"2xx": 1}, distinct_paths=1, top_paths=[("/\x1b[2J", 1)],
            other_requests=0, detections=[],
        )  # fmt: skip
        assert data.profile_paths_table(profile)["Path"] == ["/\\x1b[2J"]


class TestTheAddressChoices:
    def test_they_are_capped(self):
        assert len(data.ip_choices(report(), limit=3)) == 3
        assert data.ip_choices(report(), limit=0) == []

    def test_no_address_twice(self):
        choices = data.ip_choices(report())
        assert len(choices) == len(set(choices))
        assert set(choices) >= {ip for ip, _ in report().summary.top_ips}


class TestTheOutcomeKeepsTheRequests:
    def test_the_outcome_keeps_every_request_for_the_address_view(self):
        outcome = data.analyze_upload(DEMO, "demo.log")
        assert len(outcome.entries) == outcome.report.summary.total_requests
        assert data.analyze_upload(b"junk\n", "j.log").entries == []
