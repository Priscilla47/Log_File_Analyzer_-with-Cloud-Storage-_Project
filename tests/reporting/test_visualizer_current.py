"""Characterization tests for the prototype chart functions.

These pin what ``plot_status_codes`` and ``plot_requests_by_hour`` do TODAY, so the
reorganisation planned for next week shows up as deliberate, visible differences.
"""

import matplotlib.pyplot as plt
import pandas as pd
import pytest

from loginsight.reporting.visualizer import plot_requests_by_hour, plot_status_codes

PNG_SIGNATURE = b"\x89PNG"

CHARTS = [
    pytest.param(plot_status_codes, "status_codes.png", id="status_codes"),
    pytest.param(plot_requests_by_hour, "requests_by_hour.png", id="requests_by_hour"),
]


def make_df(stamps, statuses):
    return pd.DataFrame({"status": statuses, "time": pd.to_datetime(stamps)})


@pytest.fixture
def df():
    # 200 twice, 404 once. Hours 10, 10 and 13.
    return make_df(["2025-06-01 10:05", "2025-06-01 10:50", "2025-06-01 13:00"], [200, 200, 404])


@pytest.fixture
def chart_spy(monkeypatch):
    """Record what is on the axes at the moment the chart is saved."""
    seen = {}
    real_savefig = plt.savefig

    def spy(*args, **kwargs):
        ax = plt.gca()
        seen["title"] = ax.get_title()
        seen["xlabel"] = ax.get_xlabel()
        seen["ylabel"] = ax.get_ylabel()
        seen["bar_heights"] = [patch.get_height() for patch in ax.patches]
        seen["xtick_labels"] = [tick.get_text() for tick in ax.get_xticklabels()]
        points = ax.lines[0].get_xydata() if ax.lines else []
        seen["line_points"] = [tuple(point) for point in points]
        return real_savefig(*args, **kwargs)

    monkeypatch.setattr(plt, "savefig", spy)
    return seen


# --- files ----------------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "filename"), CHARTS)
def test_chart_creates_a_non_empty_png_in_the_working_directory(plot, filename, df, tmp_path):
    plot(df)
    path = tmp_path / filename
    assert path.exists()
    assert path.stat().st_size > 0
    assert path.read_bytes().startswith(PNG_SIGNATURE)


@pytest.mark.parametrize(("plot", "filename"), CHARTS)
def test_chart_writes_only_its_own_file(plot, filename, df, tmp_path):
    plot(df)
    assert [p.name for p in tmp_path.iterdir()] == [filename]


@pytest.mark.parametrize(("plot", "filename"), CHARTS)
def test_chart_overwrites_an_existing_file(plot, filename, df, tmp_path):
    (tmp_path / filename).write_bytes(b"old content")
    plot(df)
    assert (tmp_path / filename).read_bytes().startswith(PNG_SIGNATURE)


# --- no leaks -------------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "filename"), CHARTS)
def test_no_figure_is_left_open_after_plotting(plot, filename, df):
    plot(df)
    assert plt.get_fignums() == []


# --- what is drawn --------------------------------------------------------------------


def test_status_chart_bars_are_ordered_by_frequency(df, chart_spy):
    plot_status_codes(df)
    assert chart_spy["bar_heights"] == [2, 1]
    assert chart_spy["xtick_labels"] == ["200", "404"]


def test_status_chart_title_and_axis_labels(df, chart_spy):
    plot_status_codes(df)
    assert chart_spy["title"] == "Status Code Distribution"
    assert chart_spy["xlabel"] == "Status Code"
    assert chart_spy["ylabel"] == "Frequency"


def test_hourly_chart_counts_requests_per_hour(df, chart_spy):
    plot_requests_by_hour(df)
    assert chart_spy["line_points"] == [(10, 2), (13, 1)]


def test_hourly_chart_title_and_axis_labels(df, chart_spy):
    plot_requests_by_hour(df)
    assert chart_spy["title"] == "Requests per Hour"
    assert chart_spy["xlabel"] == "Hour of Day"
    assert chart_spy["ylabel"] == "Number of Requests"


def test_hourly_chart_groups_by_hour_of_day_and_ignores_the_date(chart_spy):
    two_days = make_df(["2025-06-01 10:00", "2025-06-02 10:30"], [200, 200])
    plot_requests_by_hour(two_days)
    assert chart_spy["line_points"] == [(10, 2)]


# --- side effect on the input ---------------------------------------------------------


def test_hourly_chart_adds_an_hour_column_to_the_input(df):
    # Current behaviour: the caller's DataFrame is modified. Worth removing in the refactor.
    assert "hour" not in df.columns
    plot_requests_by_hour(df)
    assert df["hour"].tolist() == [10, 10, 13]


def test_status_chart_leaves_the_input_unchanged(df):
    before = df.copy()
    plot_status_codes(df)
    pd.testing.assert_frame_equal(df, before)


# --- data shapes ----------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "filename"), CHARTS)
def test_single_row_of_data_produces_a_chart(plot, filename, tmp_path):
    plot(make_df(["2025-06-01 09:00"], [200]))
    assert (tmp_path / filename).read_bytes().startswith(PNG_SIGNATURE)


def test_data_spanning_many_hours_gives_one_point_per_hour(chart_spy):
    stamps = [f"2025-06-01 {hour:02d}:00" for hour in range(0, 24)]
    plot_requests_by_hour(make_df(stamps, [200] * 24))
    assert [x for x, _ in chart_spy["line_points"]] == list(range(24))
    assert {y for _, y in chart_spy["line_points"]} == {1}


# --- empty input ----------------------------------------------------------------------


@pytest.fixture
def empty_df():
    return pd.DataFrame(
        {
            "status": pd.Series([], dtype="int64"),
            "time": pd.Series([], dtype="datetime64[ns]"),
        }
    )


@pytest.mark.xfail(strict=True, raises=IndexError, reason="known bug: empty input, fixed later")
def test_status_chart_on_empty_data_should_not_raise(empty_df):
    # Observed: IndexError, and the half-built figure is left open (a leak).
    plot_status_codes(empty_df)


def test_hourly_chart_on_empty_data_saves_a_blank_chart(empty_df, tmp_path):
    # Observed: no error, a chart with no points is written.
    plot_requests_by_hour(empty_df)
    assert (tmp_path / "requests_by_hour.png").read_bytes().startswith(PNG_SIGNATURE)
    assert plt.get_fignums() == []
