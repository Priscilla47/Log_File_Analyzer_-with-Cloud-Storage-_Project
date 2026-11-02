"""write_to_storage: the report goes to any Storage, and is the same as on disk."""

from pathlib import Path

import pytest

from loginsight.detection import detect
from loginsight.parsing.parser import parse_file
from loginsight.reporting import charts
from loginsight.reporting.report import build_report, render_json, render_markdown
from loginsight.reporting.writers import FORMATS, write_report, write_to_storage

GOLDEN = Path(__file__).parent / "golden"
KEYS = [
    "report.json",
    "report.md",
    "charts/status.png",
    "charts/traffic.png",
    "charts/top_paths.png",
]


@pytest.fixture(scope="module")
def report():
    result = parse_file(GOLDEN / "tiny.log")
    return build_report(result, detect(result.entries), source_name="tiny.log")


@pytest.fixture(scope="module")
def empty_report():
    result = parse_file(GOLDEN / "empty.log")
    return build_report(result, [], source_name="empty.log")


def test_everything_is_written_by_default_in_a_fixed_order(report, memory_storage_class):
    storage = memory_storage_class()
    assert write_to_storage(report, storage) == KEYS
    assert storage.list() == sorted(KEYS)


def test_nothing_touches_the_disk(report, memory_storage_class, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_to_storage(report, memory_storage_class())
    assert list(tmp_path.iterdir()) == []


def test_the_content_is_the_rendered_report(report, memory_storage_class):
    storage = memory_storage_class()
    write_to_storage(report, storage)
    assert storage.read_text("report.json") == render_json(report)
    assert storage.read_text("report.md") == render_markdown(report, charts=True)


def test_the_bytes_equal_what_write_report_puts_on_disk(report, memory_storage_class, tmp_path):
    storage = memory_storage_class()
    write_to_storage(report, storage)
    write_report(report, tmp_path)
    for key in KEYS:
        assert storage.files[key] == (tmp_path / key).read_bytes(), key


def test_each_chart_is_stored_under_its_own_name(report, memory_storage_class):
    storage = memory_storage_class()
    write_to_storage(report, storage)
    assert storage.files["charts/status.png"] == charts.status_codes_png(
        report.summary.status_classes
    )
    assert storage.files["charts/traffic.png"] == charts.traffic_png(report.buckets)
    assert storage.files["charts/top_paths.png"] == charts.top_paths_png(report.summary.top_paths)
    assert len({storage.files[key] for key in KEYS[2:]}) == 3  # three different pictures


def test_text_files_are_utf8_with_unix_line_endings(report, memory_storage_class):
    storage = memory_storage_class()
    write_to_storage(report, storage, ["json", "md"])
    for key in ("report.json", "report.md"):
        assert b"\r" not in storage.files[key] and storage.files[key].endswith(b"\n")


@pytest.mark.parametrize(
    "formats, expected",
    [
        (["json"], ["report.json"]),
        (["md"], ["report.md"]),
        (["charts"], KEYS[2:]),
        (["md", "json"], KEYS[:2]),
        (iter(["charts", "json"]), [KEYS[0], *KEYS[2:]]),
        ([], []),
    ],
)
def test_only_the_asked_formats_are_written(report, memory_storage_class, formats, expected):
    storage = memory_storage_class()
    assert write_to_storage(report, storage, formats) == expected
    assert storage.list() == sorted(expected)


def test_markdown_links_charts_only_when_they_are_written(report, memory_storage_class):
    with_charts, without = memory_storage_class(), memory_storage_class()
    write_to_storage(report, with_charts, ["md", "charts"])
    write_to_storage(report, without, ["md"])
    assert "charts/status.png" in with_charts.read_text("report.md")
    assert "charts/" not in without.read_text("report.md")


def test_an_unknown_format_is_refused_before_anything_is_written(report, memory_storage_class):
    storage = memory_storage_class()
    with pytest.raises(ValueError, match="'pdf'"):
        write_to_storage(report, storage, ["json", "pdf"])
    assert storage.list() == []


def test_an_empty_report_is_written_too(empty_report, memory_storage_class):
    storage = memory_storage_class()
    assert write_to_storage(empty_report, storage) == KEYS
    assert "No detections found." in storage.read_text("report.md")


def test_a_failing_storage_stops_the_write_and_reports_the_error(report, memory_storage_class):
    class Full(memory_storage_class):
        def write_bytes(self, key, data):
            if key == "report.md":
                raise OSError(28, "No space left on device")
            super().write_bytes(key, data)

    storage = Full()
    with pytest.raises(OSError, match="No space"):
        write_to_storage(report, storage)
    assert storage.list() == ["report.json"]  # what came before stays, nothing after it


def test_the_formats_constant_is_unchanged():
    assert FORMATS == ("json", "md", "charts")


class TestPngFunctions:
    def test_each_is_a_valid_800_by_450_png(self, report):
        for data in (
            charts.status_codes_png(report.summary.status_classes),
            charts.traffic_png(report.buckets),
            charts.top_paths_png(report.summary.top_paths),
        ):
            assert data.startswith(b"\x89PNG\r\n\x1a\n")
            assert int.from_bytes(data[16:20], "big") == 800
            assert int.from_bytes(data[20:24], "big") == 450

    def test_they_equal_the_files_the_plot_functions_write(self, report, tmp_path):
        pairs = [
            (charts.status_codes_png(report.summary.status_classes),
             charts.plot_status_codes(report.summary.status_classes, tmp_path / "a.png")),
            (charts.traffic_png(report.buckets),
             charts.plot_traffic(report.buckets, tmp_path / "b.png")),
            (charts.top_paths_png(report.summary.top_paths),
             charts.plot_top_paths(report.summary.top_paths, tmp_path / "c.png")),
        ]  # fmt: skip
        for data, path in pairs:
            assert data == path.read_bytes()

    def test_empty_data_gives_the_no_data_chart(self):
        assert charts.status_codes_png({}).startswith(b"\x89PNG")
        assert charts.traffic_png([]).startswith(b"\x89PNG")
        assert charts.top_paths_png([]).startswith(b"\x89PNG")

    def test_bad_status_data_still_raises(self):
        with pytest.raises(ValueError, match="unknown status class"):
            charts.status_codes_png({"9xx": 1})
        with pytest.raises(ValueError, match="negative count"):
            charts.status_codes_png({"2xx": -1})
