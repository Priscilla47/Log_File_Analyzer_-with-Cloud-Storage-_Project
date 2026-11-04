"""The page itself, run headless with Streamlit's own test helper. Skipped without Streamlit."""

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

from loginsight.dashboard import data, launch  # noqa: E402


@pytest.fixture
def page():
    app = AppTest.from_file(str(launch.APP_FILE), default_timeout=30)
    app.run()
    return app


def test_the_page_runs_without_an_error(page):
    assert not page.exception


def test_it_shows_the_title(page):
    assert [t.value for t in page.title] == [data.APP_TITLE]


def test_with_no_file_it_shows_the_invitation_to_choose_one(page):
    assert data.EMPTY_MESSAGE in [i.value for i in page.info]


def test_it_has_no_charts_numbers_or_tables_yet(page):
    assert len(page.metric) == 0 and len(page.dataframe) == 0 and len(page.table) == 0


# --- a file chosen on the page, with the real Streamlit ----------------------------------


import json  # noqa: E402
from pathlib import Path  # noqa: E402

from loginsight.cli import main  # noqa: E402
from loginsight.reporting.report import human_bytes  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def upload(name, raw):
    app = AppTest.from_file(str(launch.APP_FILE), default_timeout=30).run()
    app.file_uploader[0].upload(name, raw).run()
    return app


def shown(app):
    return {m.label: m.value for m in app.metric}


@pytest.mark.parametrize("sample", ["demo.log", "demo_nginx.log", "clean.log"])
def test_the_numbers_on_the_page_equal_the_command_line(sample, capsys):
    assert main(["analyze", str(SAMPLES / sample), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    app = upload(sample, (SAMPLES / sample).read_bytes())
    assert not app.exception
    assert shown(app) == {
        "Requests": str(report["summary"]["total_requests"]),
        "Unique IPs": str(report["summary"]["unique_ips"]),
        "Error rate": f"{report['summary']['error_rate']:.1%}",
        "Data sent": human_bytes(report["summary"]["total_bytes"]),
        "Skipped lines": str(report["source"]["parse"]["skipped"]),
    }


def test_the_page_names_the_file_and_the_format():
    app = upload("demo_nginx.log", (SAMPLES / "demo_nginx.log").read_bytes())
    assert [t.value for t in app.text][:2] == ["File: demo_nginx.log", "Format: nginx"]


def test_a_file_that_is_not_a_log_shows_an_error_and_no_numbers():
    app = upload("notes.txt", b"just some notes\n" * 3)
    assert not app.exception
    assert [e.value for e in app.error][0].startswith("None of the 3 lines could be read")
    assert len(app.metric) == 0


def test_an_empty_file_shows_zeros_and_a_notice():
    app = upload("empty.log", b"")
    assert not app.exception
    assert shown(app)["Requests"] == "0"
    assert "The file has no requests in it." in [i.value for i in app.info]


def test_many_unreadable_lines_give_a_warning_above_the_numbers():
    good = (SAMPLES / "demo.log").read_bytes().splitlines(keepends=True)[:8]
    app = upload("a.log", b"".join(good) + b"junk\n" * 4)
    assert [w.value for w in app.warning] == ["4 of 12 lines (33%) could not be read"]
    assert shown(app)["Requests"] == "8"


def test_a_hostile_file_name_is_shown_as_plain_text_and_cannot_inject_markup():
    app = upload("**x** [y](evil)<b>.log", (SAMPLES / "clean.log").read_bytes())
    assert not app.exception
    # only the plain-text element holds the name; nothing rendered as Markdown contains it
    assert [t.value for t in app.text][0] == "File: **x** [y](evil)<b>.log"
    assert not any("evil" in str(m.value) for m in app.markdown)
    assert not any("evil" in str(e.value) for e in app.error)


def test_a_name_with_folders_is_reduced_to_the_file_name():
    app = upload("../../etc/access.log", (SAMPLES / "clean.log").read_bytes())
    assert [t.value for t in app.text][0] == "File: access.log"


# --- the charts, as the real Streamlit draws them -----------------------------------------

pa = pytest.importorskip("pyarrow")

OKABE_ITO = {"#0072B2", "#D55E00", "#009E73", "#E69F00", "#56B4E9", "#CC79A7", "#F0E442"}


def vega_charts(app):
    return [
        e.proto
        for e in app.main
        if type(e).__name__ == "UnknownElement" and hasattr(e.proto, "spec")
    ]


def rows_of(chart):
    blob = chart.datasets[0].data.data if len(chart.datasets) else chart.data.data
    return pa.ipc.open_stream(blob).read_all()


def spec_of(chart):
    return json.loads(chart.spec)


@pytest.fixture(scope="module")
def demo_page():
    return upload("demo.log", (SAMPLES / "demo.log").read_bytes())


def test_three_charts_are_drawn_each_under_a_title(demo_page):
    assert not demo_page.exception
    assert len(vega_charts(demo_page)) == 3
    assert [s.value for s in demo_page.subheader] == [
        "Responses by status class",
        "Traffic over time",
        "Most requested paths",
    ]


def test_the_status_chart_plots_the_status_classes_of_the_report(demo_page, capsys):
    main(["analyze", str(SAMPLES / "demo.log"), "--format", "json"])
    classes = json.loads(capsys.readouterr().out)["summary"]["status_classes"]
    chart = vega_charts(demo_page)[0]
    table = rows_of(chart).to_pydict()
    assert dict(zip(table["Status class"], table["Requests"], strict=True)) == {
        name: classes[name] for name in ("2xx", "3xx", "4xx", "5xx")
    }
    spec = spec_of(chart)
    assert spec["mark"]["type"] == "bar"
    assert spec["encoding"]["x"]["title"] == "Status class"
    assert spec["encoding"]["y"]["title"] == "Requests"


def test_the_traffic_chart_has_two_lines_in_colours_people_can_tell_apart(demo_page):
    spec = spec_of(vega_charts(demo_page)[1])
    layer = spec["layer"][0]
    assert layer["mark"]["type"] == "line"
    scale = layer["encoding"]["color"]["scale"]
    assert scale["domain"] == ["Requests", "Errors"]
    assert scale["range"] == ["#0072B2", "#D55E00"] and set(scale["range"]) <= OKABE_ITO


def test_the_paths_chart_is_horizontal_and_lists_the_reports_busiest_paths(demo_page, capsys):
    main(["analyze", str(SAMPLES / "demo.log"), "--format", "json"])
    top = json.loads(capsys.readouterr().out)["summary"]["top_paths"]
    chart = vega_charts(demo_page)[2]
    table = rows_of(chart).to_pydict()
    assert list(zip(table["Path"], table["Requests"], strict=True)) == [
        (p["path"], p["requests"]) for p in top
    ]
    encoding = spec_of(chart)["encoding"]
    assert encoding["y"]["field"] == "Path" and encoding["x"]["field"] == "Requests"


def test_the_bar_colours_are_from_the_safe_palette(demo_page):
    for chart in (vega_charts(demo_page)[0], vega_charts(demo_page)[2]):
        assert spec_of(chart)["encoding"]["color"]["value"] in OKABE_ITO


def test_choosing_a_shorter_period_gives_more_points_and_a_longer_one_fewer():
    app = upload("demo.log", (SAMPLES / "demo.log").read_bytes())
    sizes = {}
    for bucket in ("minute", "hour", "day"):
        app.radio[0].set_value(bucket).run()
        assert not app.exception
        sizes[bucket] = rows_of(vega_charts(app)[1]).num_rows
    assert sizes["minute"] > sizes["hour"] >= sizes["day"] >= 2  # two lines per period
    assert sizes["minute"] == 2 * 11  # the demo log spans eleven minutes


def test_the_chosen_period_does_not_change_the_numbers_on_the_cards():
    app = upload("demo.log", (SAMPLES / "demo.log").read_bytes())
    before = shown(app)
    app.radio[0].set_value("minute").run()
    assert shown(app) == before


def test_no_charts_for_a_bad_file_or_an_empty_one():
    assert vega_charts(upload("notes.txt", b"just some notes\n" * 3)) == []
    assert vega_charts(upload("empty.log", b"")) == []


def test_a_wide_time_range_still_draws_with_a_note():
    old = (SAMPLES / "demo.log").read_bytes().replace(b"/Jan/2026", b"/Jan/1970", 1)
    app = upload("odd.log", old)
    app.radio[0].set_value("minute").run()
    assert not app.exception and len(vega_charts(app)) == 3
    assert [c.value for c in app.caption] == [
        "Quiet periods are not listed because the log covers too long a time."
    ]
