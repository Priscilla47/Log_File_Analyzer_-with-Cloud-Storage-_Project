"""ip_profile: everything one address did (issue #82)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.analysis.summary import summarize
from loginsight.dashboard.profile import TOP_PATHS, ip_profile
from loginsight.detection import detect, load_rules
from loginsight.detection.models import Detection, Severity
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
T0 = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)


def entry(ip="203.0.113.5", path="/", status=200, minutes=0, size=10):
    return LogEntry(
        ip=ip,
        time=T0 + timedelta(minutes=minutes),
        method="GET",
        path=path,
        query="",
        protocol="HTTP/1.1",
        status=status,
        size=size,
        request=f"GET {path} HTTP/1.1",
    )


def found(ip, index=0):
    return Detection(
        rule_id="r",
        label="xss",
        severity=Severity.HIGH,
        ip=ip,
        time=T0,
        first_index=index,
        last_index=index,
        count=1,
        evidence="x",
    )


ENTRIES = [
    entry("203.0.113.5", "/a", 200, 0),
    entry("203.0.113.5", "/a", 404, 5),
    entry("203.0.113.5", "/b", 500, 3),
    entry("203.0.113.6", "/a", 200, 1),
    entry("2001:db8::1", "/v6", 301, 2),
]


class TestAKnownAddress:
    profile = ip_profile(ENTRIES, [found("203.0.113.5"), found("203.0.113.6")], "203.0.113.5")

    def test_it_counts_its_requests_and_times(self):
        assert self.profile.known and self.profile.ip == "203.0.113.5"
        assert self.profile.requests == 3
        assert self.profile.first_seen == T0
        assert self.profile.last_seen == T0 + timedelta(minutes=5)

    def test_the_status_mix_adds_up_to_the_requests(self):
        mix = self.profile.status_classes
        assert (mix["2xx"], mix["4xx"], mix["5xx"]) == (1, 1, 1)
        assert sum(mix.values()) == self.profile.requests

    def test_paths_are_ranked_and_add_up_with_the_rest(self):
        assert self.profile.top_paths == [("/a", 2), ("/b", 1)]
        assert self.profile.distinct_paths == 2
        assert self.profile.other_requests == 0

    def test_only_its_own_detections(self):
        assert [d.ip for d in self.profile.detections] == ["203.0.113.5"]


class TestPathsBeyondTheLimit:
    def test_ten_paths_are_listed_by_default(self):
        many = [entry(path=f"/p{i}") for i in range(12)]
        profile = ip_profile(many, [], "203.0.113.5")
        assert len(profile.top_paths) == TOP_PATHS == 10
        assert profile.distinct_paths == 12 and profile.other_requests == 2

    def test_the_requests_to_the_other_paths_are_counted_so_nothing_is_lost(self):
        many = [entry(path=f"/p{i}") for i in range(7)] + [entry(path="/p0")]
        profile = ip_profile(many, [], "203.0.113.5", top_n=3)
        assert len(profile.top_paths) == 3 and profile.top_paths[0] == ("/p0", 2)
        assert profile.distinct_paths == 7
        assert sum(c for _, c in profile.top_paths) + profile.other_requests == 8
        assert profile.other_requests == 8 - 4

    def test_a_negative_limit_is_an_error_and_zero_lists_none(self):
        with pytest.raises(ValueError):
            ip_profile(ENTRIES, [], "203.0.113.5", top_n=-1)
        profile = ip_profile(ENTRIES, [], "203.0.113.5", top_n=0)
        assert profile.top_paths == [] and profile.other_requests == 3


class TestUnknownAndSpecialAddresses:
    def test_an_unknown_address_gives_an_explicit_empty_profile(self):
        profile = ip_profile(ENTRIES, [found("203.0.113.5")], "198.51.100.1")
        assert not profile.known
        assert profile.requests == 0 and profile.distinct_paths == 0
        assert profile.first_seen is None and profile.last_seen is None
        assert profile.top_paths == [] and profile.detections == []
        assert profile.other_requests == 0
        assert set(profile.status_classes.values()) == {0}

    def test_no_entries_at_all(self):
        assert not ip_profile([], [], "1.2.3.4").known

    def test_a_blank_address_is_unknown_not_an_error(self):
        assert not ip_profile(ENTRIES, [], "").known

    def test_ipv6_in_any_spelling(self):
        profile = ip_profile(ENTRIES, [found("2001:db8::1")], "2001:0DB8:0:0:0:0:0:1")
        assert profile.known and profile.requests == 1
        assert profile.status_classes["3xx"] == 1
        assert len(profile.detections) == 1

    def test_an_address_that_is_not_an_ip_matches_only_itself(self):
        weird = [entry("unknown-host", "/h")]
        assert ip_profile(weird, [], "unknown-host").requests == 1
        assert not ip_profile(weird, [], "UNKNOWN-HOST").known


class TestDetectionsWithoutRequests:
    def test_an_address_with_no_detections_still_has_a_profile(self):
        profile = ip_profile(ENTRIES, [], "203.0.113.6")
        assert profile.known and profile.requests == 1 and profile.detections == []

    def test_an_address_with_several_detections(self):
        profile = ip_profile(ENTRIES, [found("203.0.113.5", i) for i in range(4)], "203.0.113.5")
        assert len(profile.detections) == 4

    def test_a_detection_alone_makes_the_address_known(self):
        profile = ip_profile([], [found("198.51.100.9")], "198.51.100.9")
        assert profile.known and profile.requests == 0 and len(profile.detections) == 1


@pytest.fixture(scope="module", params=["demo.log", "demo_nginx.log"])
def parsed(request):
    entries = parse_file(SAMPLES / request.param).entries
    return entries, detect(entries, load_rules())


class TestTheNumbersAddUp:
    def test_the_requests_of_all_addresses_add_up_to_the_total(self, parsed):
        entries, detections = parsed
        addresses = {e.ip for e in entries}
        profiles = [ip_profile(entries, detections, ip) for ip in addresses]
        assert (
            sum(p.requests for p in profiles) == len(entries) == summarize(entries).total_requests
        )
        assert sum(len(p.detections) for p in profiles) == len(detections)

    def test_each_profile_is_consistent_inside(self, parsed):
        entries, detections = parsed
        for ip in {e.ip for e in entries}:
            p = ip_profile(entries, detections, ip, top_n=3)
            assert sum(p.status_classes.values()) == p.requests
            assert sum(c for _, c in p.top_paths) + p.other_requests == p.requests
            assert p.first_seen <= p.last_seen
            assert len(p.top_paths) <= min(3, p.distinct_paths)

    def test_the_profile_of_the_busiest_address_equals_the_report_summary(self, parsed):
        entries, detections = parsed
        ip, count = summarize(entries).top_ips[0]
        assert ip_profile(entries, detections, ip).requests == count
