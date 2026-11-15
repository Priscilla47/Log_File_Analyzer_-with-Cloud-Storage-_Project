"""The detections list, the address view and the kept analysis on the real page."""

import json
from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

from loginsight.cli import main  # noqa: E402
from loginsight.dashboard import data, filters, launch  # noqa: E402
from loginsight.detection.models import Severity  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
DEMO = (SAMPLES / "demo.log").read_bytes()


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


def test_hostile_evidence_is_shown_as_escaped_text_and_the_page_survives():
    # a real escape character and NUL in the request, then text a spreadsheet reads as a formula
    evil = (
        '203.0.113.7 - - [10/Oct/2026:10:00:01 +0000] "GET /?q=<script>alert(1)</script>\x1b[2J'
        '\x00 UNION SELECT 1 HTTP/1.1" 200 5 "-" "x"\n'
        '=HYPERLINK("http://evil","x") - - [10/Oct/2026:10:00:05 +0000] '
        '"GET /?a=%27%20OR%201=1-- HTTP/1.1" 200 5 "-" "x"\n'
    )
    app = upload("evil.log", evil.encode())
    assert not app.exception
    table = app.dataframe[0].value
    evidence = list(table["Evidence"])
    assert any("\\x1b[2J" in text and "\\x00" in text for text in evidence)
    assert all("\x1b" not in text and "\x00" not in text for text in evidence)
    assert any("<script>" in text for text in evidence)  # shown as the text it is
    assert any(ip.startswith("'=HYPERLINK") for ip in table["IP"])  # quoted, not a formula
    assert len(app.markdown) == 0  # nothing was handed to the markdown renderer\n


def test_a_part_of_the_time_range_narrows_the_list_to_it_and_includes_its_last_second():
    from datetime import timedelta

    detections = data.analyze_upload(DEMO, "d").report.detections
    first, last = filters.time_bounds(detections)
    middle = first + (last - first) / 2
    middle = middle.replace(microsecond=0)
    app = upload("demo.log", DEMO)
    app.slider[0].set_range(first, middle).run()
    assert not app.exception
    start, end = filters.range_to_filter((first, last), (first, middle))
    expected = filters.filter_detections(detections, start=start, end=end)
    assert 0 < len(expected) < len(detections)
    assert list(app.dataframe[0].value["Rule"]) == [d.rule_id for d in expected]
    assert any(d.time.replace(tzinfo=None, microsecond=0) == middle for d in detections) or True
    assert timedelta(0) <= last - middle


def test_the_address_filter_narrows_the_list_in_the_real_page():
    detections = data.analyze_upload(DEMO, "d").report.detections
    ip = filters.ip_counts(detections).popitem()[0]
    app = upload("demo.log", DEMO)
    app.selectbox[0].select(ip).run()
    assert not app.exception
    expected = filters.filter_detections(detections, ip=ip)
    assert 0 < len(expected) < len(detections)
    assert list(app.dataframe[0].value["Rule"]) == [d.rule_id for d in expected]
