from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from loginsight.parsing.models import LogEntry

WHEN = datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc)

FIELDS = {
    "ip",
    "time",
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "size",
    "referer",
    "user_agent",
    "request",
}


def make(**overrides):
    values = {
        "ip": "192.0.2.1",
        "time": WHEN,
        "method": "GET",
        "path": "/s",
        "query": "q=a%20b",
        "protocol": "HTTP/1.1",
        "status": 200,
        "size": 1024,
        "request": "GET /s?q=a%20b HTTP/1.1",
    }
    values.update(overrides)
    return LogEntry(**values)


def test_can_be_built_with_every_field():
    entry = make(referer="http://example.test/", user_agent="Mozilla/5.0")
    assert entry.ip == "192.0.2.1"
    assert entry.time == WHEN
    assert entry.method == "GET"
    assert entry.path == "/s"
    assert entry.query == "q=a%20b"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.size == 1024
    assert entry.referer == "http://example.test/"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.request == "GET /s?q=a%20b HTTP/1.1"


def test_referer_and_user_agent_default_to_none():
    entry = make()
    assert entry.referer is None
    assert entry.user_agent is None


def test_request_is_required():
    with pytest.raises(TypeError):
        LogEntry(
            ip="192.0.2.1",
            time=WHEN,
            method="GET",
            path="/",
            query="",
            protocol="HTTP/1.1",
            status=200,
            size=0,
        )


def test_is_immutable():
    entry = make()
    with pytest.raises(FrozenInstanceError):
        entry.status = 500


def test_entries_with_the_same_values_are_equal():
    assert make() == make()
    assert make() != make(status=404)


def test_entries_are_hashable():
    assert len({make(), make(), make(status=404)}) == 2


def test_target_includes_the_query_when_present():
    assert make(path="/s", query="q=a%20b").target == "/s?q=a%20b"


def test_target_is_just_the_path_without_a_query():
    assert make(path="/s", query="").target == "/s"


def test_target_of_a_malformed_request_is_empty():
    assert make(method="", path="", query="", protocol="", request="-").target == ""


def test_to_dict_has_exactly_the_eleven_fields():
    assert set(make().to_dict()) == FIELDS


def test_to_dict_values_match_the_entry():
    entry = make(referer="http://example.test/", user_agent="UA")
    data = entry.to_dict()
    assert data["ip"] == "192.0.2.1"
    assert data["time"] == WHEN
    assert data["status"] == 200
    assert data["referer"] == "http://example.test/"
    assert data["user_agent"] == "UA"
    assert data["request"] == "GET /s?q=a%20b HTTP/1.1"


def test_to_dict_returns_a_new_dict_each_time():
    entry = make()
    first = entry.to_dict()
    first["status"] = 999
    assert entry.to_dict()["status"] == 200


def test_to_dict_output_still_works_with_the_existing_analyzer():
    # Transition check: the prototype analyzer takes a list of dicts.
    from loginsight.analysis.analyzer import analyze_entries

    entries = [make(ip="192.0.2.1", size=1048576), make(ip="192.0.2.2", status=404, size=0)]
    _, stats = analyze_entries([e.to_dict() for e in entries])
    assert stats["total_requests"] == 2
    assert stats["unique_ips"] == 2
    assert stats["status_code_counts"] == {200: 1, 404: 1}
    assert stats["total_data_transferred_MB"] == 1.0
