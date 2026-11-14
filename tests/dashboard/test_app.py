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
