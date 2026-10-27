"""Tests for the chart module: each function writes one PNG file and returns its path."""

import ast
import errno
import os
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import matplotlib.pyplot as plt
import pytest

from loginsight.analysis.timeseries import TimeBucket
from loginsight.reporting import charts
from loginsight.reporting.charts import plot_status_codes, plot_top_paths, plot_traffic

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
T0 = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)

STATUS = {"1xx": 0, "2xx": 80, "3xx": 5, "4xx": 12, "5xx": 3, "other": 0}
BUCKETS = [
    TimeBucket(start=T0 + timedelta(hours=h), requests=r, errors=e)
    for h, (r, e) in enumerate([(10, 1), (0, 0), (25, 5), (7, 0)])
]
PATHS = [("/home", 50), ("/login", 30), ("/about", 4)]

# One case per chart: the function and some data for it.
CASES = [
    pytest.param(plot_status_codes, STATUS, id="status"),
    pytest.param(plot_traffic, BUCKETS, id="traffic"),
    pytest.param(plot_top_paths, PATHS, id="paths"),
]
EMPTY = [
    pytest.param(plot_status_codes, {}, id="status-empty"),
    pytest.param(plot_status_codes, dict.fromkeys(STATUS, 0), id="status-all-zero"),
    pytest.param(plot_traffic, [], id="traffic-empty"),
    pytest.param(plot_top_paths, [], id="paths-empty"),
]


def png_size(path):
    header = Path(path).read_bytes()[:24]
    assert header.startswith(PNG_SIGNATURE)
    return struct.unpack(">II", header[16:24])


@pytest.fixture
def figure_spy(monkeypatch):
    """Capture the figure a chart function builds, at the moment it is saved."""
    seen = {}
    real_save = charts._save

    def spy(figure, output):
        seen["figure"] = figure
        return real_save(figure, output)

    monkeypatch.setattr(charts, "_save", spy)
    return seen


def axes_of(spy):
    (ax,) = spy["figure"].axes
    return ax


# --- files ----------------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_chart_writes_a_png_and_returns_its_path(plot, data, tmp_path):
    target = tmp_path / "chart.png"
    assert plot(data, target) == target
    assert target.stat().st_size > 0
    assert target.read_bytes().startswith(PNG_SIGNATURE)


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_the_image_is_800_by_450_pixels(plot, data, tmp_path):
    assert png_size(plot(data, tmp_path / "c.png")) == (800, 450)


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_string_path_is_accepted_and_a_path_object_returned(plot, data, tmp_path):
    result = plot(data, str(tmp_path / "s.png"))
    assert isinstance(result, Path)
    assert result.exists()


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_missing_folders_are_created(plot, data, tmp_path):
    target = tmp_path / "a" / "b" / "c" / "chart.png"
    plot(data, target)
    assert target.exists()


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_an_existing_file_is_overwritten(plot, data, tmp_path):
    target = tmp_path / "chart.png"
    target.write_bytes(b"old")
    plot(data, target)
    assert target.read_bytes().startswith(PNG_SIGNATURE)


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_only_the_requested_file_is_written_and_nothing_goes_to_the_working_folder(
    plot, data, tmp_path, monkeypatch
):
    work = tmp_path / "work"
    out = tmp_path / "out"
    work.mkdir()
    out.mkdir()
    monkeypatch.chdir(work)
    plot(data, out / "only.png")
    assert list(work.iterdir()) == []
    assert [p.name for p in out.iterdir()] == ["only.png"]


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_writing_into_a_directory_path_fails_with_an_os_error(plot, data, tmp_path):
    with pytest.raises(OSError):
        plot(data, tmp_path)


# --- a failed save never damages anything --------------------------------------------

PREVIOUS = b"PREVIOUS GOOD CHART"


def directory_listing(folder):
    return sorted(p.name for p in Path(folder).iterdir())


@pytest.fixture
def existing_chart(tmp_path):
    target = tmp_path / "chart.png"
    target.write_bytes(PREVIOUS)
    return target


def half_write_then_fail(path, data):
    """Stand-in for the file write: leave half a file behind, then fail like a full disk."""
    Path(path).write_bytes(data[: len(data) // 2])
    raise OSError(errno.ENOSPC, "No space left on device")


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failed_write_leaves_an_existing_chart_untouched(plot, data, existing_chart, monkeypatch):
    monkeypatch.setattr(charts, "_write_bytes", half_write_then_fail)
    with pytest.raises(OSError, match="No space left"):
        plot(data, existing_chart)
    assert existing_chart.read_bytes() == PREVIOUS


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failed_write_leaves_no_temporary_file_behind(plot, data, existing_chart, monkeypatch):
    monkeypatch.setattr(charts, "_write_bytes", half_write_then_fail)
    with pytest.raises(OSError):
        plot(data, existing_chart)
    assert directory_listing(existing_chart.parent) == ["chart.png"]


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failed_write_of_a_new_chart_creates_nothing(plot, data, tmp_path, monkeypatch):
    monkeypatch.setattr(charts, "_write_bytes", half_write_then_fail)
    with pytest.raises(OSError):
        plot(data, tmp_path / "new.png")
    assert directory_listing(tmp_path) == []


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failed_render_leaves_an_existing_chart_untouched(
    plot, data, existing_chart, monkeypatch
):
    def explode(self, *args, **kwargs):
        raise RuntimeError("rendering failed")

    monkeypatch.setattr(charts.Figure, "savefig", explode)
    with pytest.raises(RuntimeError):
        plot(data, existing_chart)
    assert existing_chart.read_bytes() == PREVIOUS
    assert directory_listing(existing_chart.parent) == ["chart.png"]


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failure_when_putting_the_file_in_place_removes_the_temporary_file(
    plot, data, existing_chart, monkeypatch
):
    def refuse(source, destination):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(charts.os, "replace", refuse)
    with pytest.raises(PermissionError):
        plot(data, existing_chart)
    assert existing_chart.read_bytes() == PREVIOUS
    assert directory_listing(existing_chart.parent) == ["chart.png"]


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_an_interrupt_while_writing_also_cleans_up_and_is_not_swallowed(
    plot, data, existing_chart, monkeypatch
):
    def interrupted(path, content):
        Path(path).write_bytes(content[:10])
        raise KeyboardInterrupt

    monkeypatch.setattr(charts, "_write_bytes", interrupted)
    with pytest.raises(KeyboardInterrupt):
        plot(data, existing_chart)
    assert existing_chart.read_bytes() == PREVIOUS
    assert directory_listing(existing_chart.parent) == ["chart.png"]


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_directory_as_the_target_leaves_no_temporary_file(plot, data, tmp_path):
    folder = tmp_path / "taken"
    folder.mkdir()
    with pytest.raises(OSError):
        plot(data, folder)
    assert directory_listing(tmp_path) == ["taken"]
    assert directory_listing(folder) == []


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_the_chart_appears_complete_or_not_at_all(plot, data, tmp_path, monkeypatch):
    """While the data is being written the real file is either the old one or absent."""
    target = tmp_path / "chart.png"
    seen = []
    real_write = charts._write_bytes

    def watch(path, content):
        seen.append(target.exists())
        real_write(path, content)
        seen.append(target.exists())

    monkeypatch.setattr(charts, "_write_bytes", watch)
    plot(data, target)
    assert seen == [False, False]
    assert target.read_bytes().startswith(PNG_SIGNATURE)


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_successful_save_leaves_only_the_chart(plot, data, tmp_path):
    plot(data, tmp_path / "a.png")
    plot(data, tmp_path / "a.png")
    assert directory_listing(tmp_path) == ["a.png"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_new_chart_gets_the_normal_permissions_for_a_new_file(tmp_path):
    umask = os.umask(0)
    os.umask(umask)
    plot_status_codes(STATUS, tmp_path / "chart.png")
    assert (tmp_path / "chart.png").stat().st_mode & 0o777 == 0o666 & ~umask


def test_a_second_save_in_the_middle_of_the_first_does_not_collide(tmp_path, monkeypatch):
    """Two writers to one path, forced to overlap: both must succeed and the file stays valid."""
    target = tmp_path / "shared.png"
    real_write = charts._write_bytes
    nested = []

    def write_with_a_rival_in_the_middle(path, content):
        real_write(path, content[:100])  # the first writer has written part of its file...
        if not nested:
            nested.append(True)
            plot_status_codes({"2xx": 9}, target)  # ...when a second writer saves the same chart
        real_write_rest(path, content)

    def real_write_rest(path, content):
        with open(path, "ab") as file:
            file.write(content[100:])

    monkeypatch.setattr(charts, "_write_bytes", write_with_a_rival_in_the_middle)
    plot_status_codes({"2xx": 1}, target)
    assert nested == [True]
    assert png_size(target) == (800, 450)
    assert directory_listing(tmp_path) == ["shared.png"]


def test_several_threads_saving_the_same_file_leave_one_valid_chart(tmp_path):
    target = tmp_path / "shared.png"
    errors = []

    def worker(n):
        try:
            for _ in range(2):
                plot_status_codes({"2xx": n + 1, "4xx": n}, target)
        except Exception as error:  # noqa: BLE001 - report anything from the threads
            errors.append(error)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert png_size(target) == (800, 450)
    assert directory_listing(tmp_path) == ["shared.png"]


# --- no global state ------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "data"), CASES + EMPTY)
def test_calling_a_chart_50_times_leaves_no_figure_open(plot, data, tmp_path, monkeypatch):
    # Leaks come from creating figures, not from saving them, so skip the (slow) PNG
    # rendering here. pyplot starts warning at 20 open figures, so 50 is well past that.
    monkeypatch.setattr(charts, "_save", lambda figure, output: Path(output))
    for _ in range(50):
        plot(data, tmp_path / "unused.png")
    assert plt.get_fignums() == []


@pytest.mark.parametrize(("plot", "data"), CASES + EMPTY)
def test_a_few_complete_renders_leave_no_figure_open(plot, data, tmp_path):
    for n in range(3):
        plot(data, tmp_path / f"{n}.png")
    assert plt.get_fignums() == []


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_a_failed_write_leaves_no_figure_open(plot, data, tmp_path):
    with pytest.raises(OSError):
        plot(data, tmp_path)
    assert plt.get_fignums() == []


def test_the_module_does_not_import_pyplot():
    tree = ast.parse(Path(charts.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
    assert not any("pyplot" in name for name in imported if name)


def test_the_old_prototype_module_is_gone():
    with pytest.raises(ImportError):
        __import__("loginsight.reporting.visualizer")


# --- empty data -----------------------------------------------------------------------


@pytest.mark.parametrize(("plot", "data"), EMPTY)
def test_empty_data_writes_a_valid_png_and_raises_nothing(plot, data, tmp_path):
    target = plot(data, tmp_path / "empty.png")
    assert png_size(target) == (800, 450)


@pytest.mark.parametrize(("plot", "data"), EMPTY)
def test_empty_data_says_so_on_the_chart(plot, data, tmp_path, figure_spy):
    plot(data, tmp_path / "empty.png")
    texts = [t.get_text() for t in figure_spy["figure"].texts + axes_of(figure_spy).texts]
    assert "No data" in texts


@pytest.mark.parametrize(
    ("plot", "empty", "full"),
    [
        (plot_status_codes, {}, STATUS),
        (plot_traffic, [], BUCKETS),
        (plot_top_paths, [], PATHS),
    ],
    ids=["status", "traffic", "paths"],
)
def test_an_empty_chart_keeps_the_title_of_the_real_one(plot, empty, full, tmp_path, figure_spy):
    plot(full, tmp_path / "full.png")
    full_title = axes_of(figure_spy).get_title()
    plot(empty, tmp_path / "empty.png")
    assert axes_of(figure_spy).get_title() == full_title != ""


@pytest.mark.parametrize(("plot", "data"), CASES)
def test_real_data_does_not_say_no_data(plot, data, tmp_path, figure_spy):
    plot(data, tmp_path / "c.png")
    texts = [t.get_text() for t in figure_spy["figure"].texts + axes_of(figure_spy).texts]
    assert "No data" not in texts


# --- status chart ---------------------------------------------------------------------


def test_status_chart_shows_the_four_main_classes_with_their_counts(tmp_path, figure_spy):
    plot_status_codes(STATUS, tmp_path / "s.png")
    ax = axes_of(figure_spy)
    assert [t.get_text() for t in ax.get_xticklabels()] == ["2xx", "3xx", "4xx", "5xx"]
    assert [p.get_height() for p in ax.patches] == [80, 5, 12, 3]


def test_status_chart_always_shows_a_zero_class_among_the_main_four(tmp_path, figure_spy):
    plot_status_codes({"2xx": 10, "3xx": 0, "4xx": 0, "5xx": 0}, tmp_path / "s.png")
    ax = axes_of(figure_spy)
    assert [p.get_height() for p in ax.patches] == [10, 0, 0, 0]


def test_status_chart_adds_1xx_and_other_only_when_they_are_not_zero(tmp_path, figure_spy):
    plot_status_codes({**STATUS, "1xx": 2}, tmp_path / "s.png")
    assert [t.get_text() for t in axes_of(figure_spy).get_xticklabels()][0] == "1xx"
    plot_status_codes({**STATUS, "other": 7}, tmp_path / "s.png")
    assert [t.get_text() for t in axes_of(figure_spy).get_xticklabels()][-1] == "other"
    plot_status_codes({**STATUS, "1xx": 2, "other": 7}, tmp_path / "s.png")
    labels = [t.get_text() for t in axes_of(figure_spy).get_xticklabels()]
    assert labels == ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]


def test_status_chart_order_does_not_depend_on_the_dictionary_order(tmp_path, figure_spy):
    shuffled = {"5xx": 3, "2xx": 80, "4xx": 12, "3xx": 5}
    plot_status_codes(shuffled, tmp_path / "s.png")
    assert [p.get_height() for p in axes_of(figure_spy).patches] == [80, 5, 12, 3]


def test_status_chart_labels_each_bar_with_its_count(tmp_path, figure_spy):
    plot_status_codes(STATUS, tmp_path / "s.png")
    labels = [t.get_text() for t in axes_of(figure_spy).texts]
    assert labels == ["80", "5", "12", "3"]


def test_status_chart_title_and_axis_labels(tmp_path, figure_spy):
    plot_status_codes(STATUS, tmp_path / "s.png")
    ax = axes_of(figure_spy)
    assert ax.get_title() == "Responses by status class"
    assert ax.get_xlabel() == "Status class"
    assert ax.get_ylabel() == "Requests"


def test_status_chart_rejects_an_unknown_class_and_a_negative_count(tmp_path):
    with pytest.raises(ValueError, match="6xx"):
        plot_status_codes({"2xx": 1, "6xx": 1}, tmp_path / "s.png")
    with pytest.raises(ValueError, match="negative"):
        plot_status_codes({"2xx": -1}, tmp_path / "s.png")
    assert not (tmp_path / "s.png").exists()


def test_status_chart_leaves_its_input_unchanged(tmp_path):
    data = dict(STATUS)
    plot_status_codes(data, tmp_path / "s.png")
    assert data == STATUS


def test_status_chart_with_one_huge_count_still_renders(tmp_path):
    plot_status_codes({"2xx": 10**9, "4xx": 1}, tmp_path / "s.png")
    assert png_size(tmp_path / "s.png") == (800, 450)


# --- traffic chart --------------------------------------------------------------------


def test_traffic_chart_has_a_requests_line_and_an_errors_line(tmp_path, figure_spy):
    plot_traffic(BUCKETS, tmp_path / "t.png")
    ax = axes_of(figure_spy)
    assert [line.get_label() for line in ax.lines] == ["Requests", "Errors"]
    assert list(ax.lines[0].get_ydata()) == [10, 0, 25, 7]
    assert list(ax.lines[1].get_ydata()) == [1, 0, 5, 0]


def test_traffic_chart_has_one_point_per_bucket_including_empty_ones(tmp_path, figure_spy):
    plot_traffic(BUCKETS, tmp_path / "t.png")
    assert len(axes_of(figure_spy).lines[0].get_xdata()) == 4


def test_traffic_chart_title_axes_and_legend(tmp_path, figure_spy):
    plot_traffic(BUCKETS, tmp_path / "t.png")
    ax = axes_of(figure_spy)
    assert ax.get_title() == "Traffic over time"
    assert "UTC" in ax.get_xlabel()
    assert ax.get_ylabel() == "Requests"
    assert ax.get_legend() is not None


def test_traffic_chart_with_one_bucket_shows_a_visible_marker(tmp_path, figure_spy):
    plot_traffic([TimeBucket(start=T0, requests=5, errors=1)], tmp_path / "t.png")
    ax = axes_of(figure_spy)
    assert ax.lines[0].get_marker() not in (None, "None", "")


def test_traffic_chart_with_no_errors_draws_a_flat_errors_line(tmp_path, figure_spy):
    plot_traffic([TimeBucket(start=T0, requests=3, errors=0)] * 2, tmp_path / "t.png")
    assert list(axes_of(figure_spy).lines[1].get_ydata()) == [0, 0]


def test_traffic_chart_accepts_minute_buckets(tmp_path):
    buckets = [
        TimeBucket(start=T0 + timedelta(minutes=m), requests=m % 7, errors=0) for m in range(120)
    ]
    plot_traffic(buckets, tmp_path / "t.png")
    assert png_size(tmp_path / "t.png") == (800, 450)


def test_traffic_chart_with_10_000_buckets_is_fast(tmp_path):
    buckets = [
        TimeBucket(start=T0 + timedelta(minutes=m), requests=m % 50, errors=m % 5)
        for m in range(10_000)
    ]
    started = time.perf_counter()
    plot_traffic(buckets, tmp_path / "t.png")
    assert time.perf_counter() - started < 10.0


def test_traffic_chart_leaves_its_input_unchanged(tmp_path):
    buckets = list(BUCKETS)
    plot_traffic(buckets, tmp_path / "t.png")
    assert buckets == BUCKETS


# --- top paths chart ------------------------------------------------------------------


def test_top_paths_chart_lists_the_busiest_path_at_the_top(tmp_path, figure_spy):
    plot_top_paths(PATHS, tmp_path / "p.png")
    ax = axes_of(figure_spy)
    labels = [t.get_text() for t in ax.get_yticklabels()]
    assert labels == ["/home", "/login", "/about"]
    assert ax.yaxis_inverted()
    assert [p.get_width() for p in ax.patches] == [50, 30, 4]


def test_top_paths_chart_labels_each_bar_with_its_count(tmp_path, figure_spy):
    plot_top_paths(PATHS, tmp_path / "p.png")
    assert [t.get_text() for t in axes_of(figure_spy).texts] == ["50", "30", "4"]


def test_a_long_path_is_shortened_with_an_ellipsis(tmp_path, figure_spy):
    long_path = "/products/" + "very-long-name-" * 10
    plot_top_paths([(long_path, 9), ("/short", 3)], tmp_path / "p.png")
    labels = [t.get_text() for t in axes_of(figure_spy).get_yticklabels()]
    assert labels[0].endswith("…")
    assert len(labels[0]) == charts.MAX_LABEL_LENGTH
    assert labels[0] == long_path[: charts.MAX_LABEL_LENGTH - 1] + "…"
    assert labels[1] == "/short"


def test_a_path_exactly_at_the_limit_is_not_shortened(tmp_path, figure_spy):
    exact = "/" + "x" * (charts.MAX_LABEL_LENGTH - 1)
    plot_top_paths([(exact, 1)], tmp_path / "p.png")
    assert [t.get_text() for t in axes_of(figure_spy).get_yticklabels()] == [exact]


def test_an_empty_path_from_a_malformed_request_gets_a_readable_label(tmp_path, figure_spy):
    plot_top_paths([("", 4), ("/a", 2)], tmp_path / "p.png")
    labels = [t.get_text() for t in axes_of(figure_spy).get_yticklabels()]
    assert labels == ["(no path)", "/a"]


def test_top_paths_chart_title_and_axis_label(tmp_path, figure_spy):
    plot_top_paths(PATHS, tmp_path / "p.png")
    ax = axes_of(figure_spy)
    assert ax.get_title() == "Most requested paths"
    assert ax.get_xlabel() == "Requests"


def test_top_paths_chart_with_one_path(tmp_path, figure_spy):
    plot_top_paths([("/only", 1)], tmp_path / "p.png")
    assert [p.get_width() for p in axes_of(figure_spy).patches] == [1]


def test_top_paths_chart_with_many_paths_still_renders(tmp_path):
    paths = [(f"/page/{n}", 100 - n) for n in range(60)]
    plot_top_paths(paths, tmp_path / "p.png")
    assert png_size(tmp_path / "p.png") == (800, 450)


def test_top_paths_chart_with_unusual_characters_in_a_path(tmp_path):
    odd = [("/$100/50%_off/<b>", 3), ("/ünï/😀", 2), ("/a\\b", 1)]
    plot_top_paths(odd, tmp_path / "p.png")
    assert png_size(tmp_path / "p.png") == (800, 450)


def test_a_path_with_dollar_signs_is_drawn_literally_not_as_math_text(tmp_path, figure_spy):
    # matplotlib reads $...$ as math, so each dollar sign in a path is escaped.
    plot_top_paths([("/a$b$c", 1)], tmp_path / "p.png")
    label = axes_of(figure_spy).get_yticklabels()[0]
    assert label.get_text() == r"/a\$b\$c"
    figure_spy["figure"].canvas.draw()  # would raise on invalid math text


def test_top_paths_chart_leaves_its_input_unchanged(tmp_path):
    paths = list(PATHS)
    plot_top_paths(paths, tmp_path / "p.png")
    assert paths == PATHS


# --- works with the real analysis output ----------------------------------------------


def test_the_charts_accept_what_the_analysis_functions_return(tmp_path):
    from loginsight.analysis.timeseries import requests_per_bucket
    from loginsight.parsing.parser import parse_file

    sample = Path(__file__).resolve().parents[2] / "data" / "samples" / "demo.log"
    entries = parse_file(sample).entries
    plot_traffic(requests_per_bucket(entries, "hour"), tmp_path / "t.png")
    assert png_size(tmp_path / "t.png") == (800, 450)
