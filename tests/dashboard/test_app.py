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
