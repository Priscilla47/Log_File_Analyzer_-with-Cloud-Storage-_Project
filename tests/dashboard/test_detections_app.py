"""The detections list, the address view and the kept analysis on the real page."""

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")

import streamlit  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

from loginsight.cli import main  # noqa: E402
from loginsight.dashboard import data, filters, launch  # noqa: E402
from loginsight.detection.models import Severity  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
DEMO = (SAMPLES / "demo.log").read_bytes()


@pytest.fixture(autouse=True)
def fresh_cache():
    streamlit.cache_resource.clear()
    yield
    streamlit.cache_resource.clear()


def upload(name, raw):
    app = AppTest.from_file(str(launch.APP_FILE), default_timeout=30).run()
    app.file_uploader[0].upload(name, raw).run()
    return app


def rows(frame):
    return len(frame.value)


@pytest.fixture
def cli_detections(capsys):
    assert main(["detect", str(SAMPLES / "demo.log"), "--format", "json"]) == 0
    return json.loads(capsys.readouterr().out)["detections"]


def test_the_list_has_every_detection_the_command_line_finds(cli_detections):
    app = upload("demo.log", DEMO)
    assert not app.exception
    table = app.dataframe[0].value
    assert len(table) == len(cli_detections) > 0
    assert list(table["Rule"]) == [d["rule_id"] for d in cli_detections]
    assert list(table["IP"]) == [d["ip"] for d in cli_detections]


def test_the_filter_widgets_offer_each_value_with_its_count(cli_detections):
    app = upload("demo.log", DEMO)
    assert [w.label for w in app.multiselect] == ["Severity", "Class"]
    assert app.multiselect[0].options == [
        f"{s} ({n})"
        for s, n in filters.severity_counts(
            data.analyze_upload(DEMO, "d").report.detections
        ).items()
    ]
    assert len(app.slider) == 1 and app.slider[0].label == "Time range (UTC)"


def test_choosing_a_severity_narrows_the_list_and_the_caption(cli_detections):
    app = upload("demo.log", DEMO)
    wanted = [d for d in cli_detections if d["severity"] == "critical"]
    assert 0 < len(wanted) < len(cli_detections)
    app.multiselect[0].select(Severity.CRITICAL).run()
    assert not app.exception
    assert [r for r in app.dataframe[0].value["Rule"]] == [d["rule_id"] for d in wanted]
    assert f"Showing {len(wanted)} of {len(cli_detections)} detections." in [
        c.value for c in app.caption
    ]


def test_clearing_the_choice_shows_everything_again(cli_detections):
    app = upload("demo.log", DEMO)
    app.multiselect[0].select(Severity.CRITICAL).run()
    app.multiselect[0].unselect(Severity.CRITICAL).run()
    assert rows(app.dataframe[0]) == len(cli_detections)


def test_a_choice_with_no_match_says_so():
    detections = data.analyze_upload(DEMO, "d").report.detections
    label = next(d.label for d in detections if d.severity is Severity.CRITICAL)
    other = next(
        s for s in Severity if not any(d.label == label and d.severity is s for d in detections)
    )
    app = upload("demo.log", DEMO)
    app.multiselect[1].select(label).run()
    app.multiselect[0].select(other).run()
    assert not app.exception
    assert "No detection matches these filters." in [i.value for i in app.info]
    assert not [f for f in app.dataframe if "Rule" in f.value]


def test_a_clean_log_has_no_filters_and_says_so():
    app = upload("clean.log", (SAMPLES / "clean.log").read_bytes())
    assert not app.exception
    assert "No attacks were detected in this log." in [s.value for s in app.success]
    assert len(app.multiselect) == 0 and len(app.slider) == 0


def test_hostile_evidence_is_shown_as_text_and_the_page_survives():
    evil = (
        '203.0.113.7 - - [10/Oct/2026:10:00:01 +0000] "GET /?q=<script>alert(1)</script>'
        '%1b%5b2J UNION SELECT 1 HTTP/1.1" 200 5 "-" "x"\n'
        '203.0.113.7 - - [10/Oct/2026:10:00:05 +0000] "GET /?a=%27%20OR%201=1-- HTTP/1.1" '
        '200 5 "-" "x"\n'
    )
    app = upload("evil.log", evil.encode())
    assert not app.exception
    evidence = list(app.dataframe[0].value["Evidence"])
    assert evidence and all("\x1b" not in text for text in evidence)
    assert not app.markdown or all("<script>" not in m.value for m in app.markdown)


def test_the_address_view_shows_one_address():
    app = upload("demo.log", DEMO)
    assert app.subheader[-1].value == "One address"
    assert "Choose an address to see everything it did." in [c.value for c in app.caption]
    top = data.ip_choices(data.analyze_upload(DEMO, "d").report)[0]
    app.selectbox[-1].select(top).run()
    assert not app.exception
    shown = {m.label: m.value for m in app.metric}
    assert {"Requests", "First seen", "Last seen", "Detections"} <= set(shown)
    assert int(shown["Requests"]) >= 1


def test_each_address_request_count_adds_up_to_the_total_on_the_cards():
    base = upload("demo.log", DEMO)
    total = int({m.label: m.value for m in base.metric}["Requests"])
    choices = base.selectbox[-1].options
    seen = 0
    for choice in choices[:3]:
        app = upload("demo.log", DEMO)
        app.selectbox[-1].select(choice).run()
        seen += int([m.value for m in app.metric if m.label == "Requests"][-1])
    assert 0 < seen <= total


def test_changing_a_filter_does_not_read_the_log_again(monkeypatch):
    calls = []
    real = data.analyze_upload

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(data, "analyze_upload", counting)
    app = upload("demo.log", DEMO)
    assert len(calls) == 1
    app.multiselect[0].select(Severity.HIGH).run()
    app.multiselect[1].select("xss").run()
    app.selectbox[-1].select(app.selectbox[-1].options[0]).run()
    assert len(calls) == 1


def test_a_different_period_or_file_does_read_it_again(monkeypatch):
    calls = []
    real = data.analyze_upload

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(data, "analyze_upload", counting)
    app = upload("demo.log", DEMO)
    app.radio[0].set_value("minute").run()
    assert len(calls) == 2
    app.file_uploader[0].upload("other.log", DEMO.replace(b"203.0.113", b"198.51.100")).run()
    assert len(calls) == 3 and not app.exception
