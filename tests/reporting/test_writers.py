"""Tests for write_report: which files it writes, where, and that they are sound."""

import json
import os
import struct
from pathlib import Path

import pytest

from loginsight.detection import detect
from loginsight.parsing.parser import parse_file
from loginsight.reporting import writers
from loginsight.reporting.report import Report, build_report, render_json, render_markdown
from loginsight.reporting.writers import FORMATS, write_report

GOLDEN = Path(__file__).parent / "golden"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(scope="module")
def report() -> Report:
    result = parse_file(GOLDEN / "tiny.log")
    return build_report(result, detect(result.entries), source_name="tiny.log")


@pytest.fixture(scope="module")
def empty_report() -> Report:
    result = parse_file(GOLDEN / "empty.log")
    return build_report(result, [], source_name="empty.log")


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data.startswith(PNG_SIGNATURE)
    assert data[12:16] == b"IHDR"
    return struct.unpack(">II", data[16:24])


def names(folder: Path) -> list[str]:
    return sorted(str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file())


class TestWriteReport:
    def test_writes_everything_by_default(self, report, tmp_path):
        written = write_report(report, tmp_path / "out")
        folder = tmp_path / "out"
        assert written == [
            folder / "report.json",
            folder / "report.md",
            folder / "charts" / "status.png",
            folder / "charts" / "traffic.png",
            folder / "charts" / "top_paths.png",
        ]
        assert names(folder) == [
            "charts/status.png", "charts/top_paths.png", "charts/traffic.png",
            "report.json", "report.md",
        ]  # fmt: skip

    def test_creates_missing_folders(self, report, tmp_path):
        target = tmp_path / "a" / "b" / "c"
        write_report(report, target, ["json"])
        assert (target / "report.json").is_file()

    def test_accepts_an_existing_folder_and_a_string_path(self, report, tmp_path):
        write_report(report, str(tmp_path), ["json"])
        write_report(report, str(tmp_path), ["json"])
        assert names(tmp_path) == ["report.json"]

    def test_returned_paths_exist_and_are_the_ones_written(self, report, tmp_path):
        written = write_report(report, tmp_path)
        assert all(path.is_file() for path in written)
        assert sorted(str(p.relative_to(tmp_path)) for p in written) == names(tmp_path)

    def test_files_hold_the_rendered_report(self, report, tmp_path):
        write_report(report, tmp_path)
        assert (tmp_path / "report.json").read_text(encoding="utf-8") == render_json(report)
        assert (tmp_path / "report.md").read_text(encoding="utf-8") == render_markdown(
            report, charts=True
        )

    def test_the_png_files_are_valid_images(self, report, tmp_path):
        write_report(report, tmp_path)
        for name in ("status", "traffic", "top_paths"):
            assert png_size(tmp_path / "charts" / f"{name}.png") == (800, 450)

    @pytest.mark.parametrize("formats", [["json"], ["md"], ["charts"], ["json", "md"]])
    def test_only_the_asked_formats_are_written(self, report, tmp_path, formats):
        written = write_report(report, tmp_path, formats)
        expected = {
            "json": ["report.json"],
            "md": ["report.md"],
            "charts": ["charts/status.png", "charts/top_paths.png", "charts/traffic.png"],
        }
        assert names(tmp_path) == sorted(n for f in formats for n in expected[f])
        assert len(written) == len(names(tmp_path))

    def test_order_does_not_depend_on_the_order_asked(self, report, tmp_path):
        a = write_report(report, tmp_path / "a", ["charts", "md", "json"])
        b = write_report(report, tmp_path / "b", ["json", "md", "charts"])
        assert [p.name for p in a] == [p.name for p in b]

    def test_markdown_links_charts_only_when_they_are_written(self, report, tmp_path):
        write_report(report, tmp_path / "with", ["md", "charts"])
        write_report(report, tmp_path / "without", ["md"])
        assert "charts/status.png" in (tmp_path / "with" / "report.md").read_text()
        assert "charts/" not in (tmp_path / "without" / "report.md").read_text()

    def test_every_chart_the_markdown_links_exists(self, report, tmp_path):
        write_report(report, tmp_path)
        text = (tmp_path / "report.md").read_text(encoding="utf-8")
        links = [part.split(")")[0] for part in text.split("](")[1:]]
        assert links and all((tmp_path / link).is_file() for link in links)

    def test_formats_may_be_any_iterable(self, report, tmp_path):
        write_report(report, tmp_path, iter(["json"]))
        write_report(report, tmp_path, ("md",))
        assert names(tmp_path) == ["report.json", "report.md"]

    def test_no_formats_writes_nothing(self, report, tmp_path):
        assert write_report(report, tmp_path / "out", []) == []
        assert (tmp_path / "out").is_dir() and names(tmp_path / "out") == []

    def test_unknown_format_is_rejected_before_anything_is_written(self, report, tmp_path):
        with pytest.raises(ValueError, match="'pdf'"):
            write_report(report, tmp_path / "out", ["json", "pdf"])
        assert not (tmp_path / "out").exists()

    def test_formats_constant(self):
        assert FORMATS == ("json", "md", "charts")

    def test_rewriting_replaces_the_files(self, report, empty_report, tmp_path):
        write_report(report, tmp_path)
        write_report(empty_report, tmp_path)
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert data["source"]["name"] == "empty.log"

    def test_the_same_report_gives_identical_files(self, report, tmp_path):
        write_report(report, tmp_path / "a")
        write_report(report, tmp_path / "b")
        for name in names(tmp_path / "a"):
            assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()

    def test_text_files_use_unix_line_endings_and_utf8(self, report, tmp_path):
        write_report(report, tmp_path, ["json", "md"])
        for name in ("report.json", "report.md"):
            data = (tmp_path / name).read_bytes()
            assert b"\r" not in data and data.endswith(b"\n")
            data.decode("utf-8")

    def test_nothing_is_written_outside_the_folder(self, report, tmp_path):
        out = tmp_path / "out"
        write_report(report, out)
        assert names(tmp_path) == [f"out/{n}" for n in names(out)]
        assert names(Path.cwd()) == names(tmp_path)  # cwd is tmp_path in these tests

    def test_the_files_name_no_absolute_path(self, report, tmp_path):
        write_report(report, tmp_path)
        for name in ("report.json", "report.md"):
            assert str(tmp_path) not in (tmp_path / name).read_text(encoding="utf-8")


class TestEmptyInput:
    def test_everything_is_written_and_valid(self, empty_report, tmp_path):
        write_report(empty_report, tmp_path)
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert data["summary"]["total_requests"] == 0
        assert "No detections found." in (tmp_path / "report.md").read_text(encoding="utf-8")
        for name in ("status", "traffic", "top_paths"):
            assert png_size(tmp_path / "charts" / f"{name}.png") == (800, 450)


class TestFailures:
    def test_a_file_in_the_way_of_the_folder_raises(self, report, tmp_path):
        blocker = tmp_path / "out"
        blocker.write_text("x")
        with pytest.raises(OSError):
            write_report(report, blocker, ["json"])
        assert blocker.read_text() == "x"

    def test_a_failed_write_leaves_no_temporary_file(self, report, tmp_path, monkeypatch):
        def broken(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(writers.os, "replace", broken)
        with pytest.raises(OSError, match="disk full"):
            write_report(report, tmp_path, ["json"])
        assert names(tmp_path) == []

    def test_a_failed_write_keeps_the_old_file(self, report, tmp_path, monkeypatch):
        write_report(report, tmp_path, ["json"])
        before = (tmp_path / "report.json").read_bytes()
        monkeypatch.setattr(writers, "render_json", lambda r: (_ for _ in ()).throw(OSError("x")))
        with pytest.raises(OSError):
            write_report(report, tmp_path, ["json"])
        assert (tmp_path / "report.json").read_bytes() == before

    def test_a_read_only_folder_raises_and_writes_nothing(self, report, tmp_path):
        if os.geteuid() == 0:
            pytest.skip("root can write anywhere")
        folder = tmp_path / "ro"
        folder.mkdir()
        folder.chmod(0o500)
        try:
            with pytest.raises(PermissionError):
                write_report(report, folder, ["json"])
        finally:
            folder.chmod(0o700)
        assert names(folder) == []
