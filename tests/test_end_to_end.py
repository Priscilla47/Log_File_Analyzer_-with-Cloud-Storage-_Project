"""End-to-end tests: run the real command on the sample logs and check the files it writes.

The unit tests prove the pieces. These prove the whole path, from a log file on disk to the
report files, the way a user runs it, in a separate process.
"""

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SAMPLES = ROOT / "data" / "samples"
DEMO = SAMPLES / "demo.log"
CLEAN = SAMPLES / "clean.log"
LABELS = SAMPLES / "demo.labels.jsonl"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHARTS = ("status", "traffic", "top_paths")
FILES = ["report.json", "report.md", *(f"charts/{name}.png" for name in CHARTS)]


def loginsight(*args, cwd=None):
    """Run ``python -m loginsight`` in a new process."""
    return subprocess.run(
        [sys.executable, "-m", "loginsight", *map(str, args)],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def detect(log, out):
    done = loginsight("detect", log, "--output", out)
    assert done.returncode == 0, done.stderr
    return done


def report_of(out) -> dict:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def labelled_classes() -> set[str]:
    rows = [json.loads(line) for line in LABELS.read_text(encoding="utf-8").splitlines()]
    return {row["label"] for row in rows}


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    return detect(DEMO, out), out


class TestDemoLog:
    def test_prints_the_paths_it_wrote_and_nothing_else(self, demo_run):
        done, out = demo_run
        assert done.stderr == ""
        assert done.stdout.splitlines() == [str(out / name) for name in FILES]

    def test_writes_every_file(self, demo_run):
        _, out = demo_run
        assert all((out / name).is_file() for name in FILES)

    def test_counts(self, demo_run):
        data = report_of(demo_run[1])
        assert data["summary"]["total_requests"] == 500
        assert data["source"]["parse"]["parsed"] == 500
        assert data["source"]["parse"]["skipped"] == 0
        assert data["source"]["name"] == "demo.log"

    def test_every_labelled_attack_class_is_detected(self, demo_run):
        found = {d["label"] for d in report_of(demo_run[1])["detections"]}
        assert labelled_classes() <= found
        # a 500-line log is too short to hold a scanner burst (see the samples README)
        assert labelled_classes() == {
            "sql_injection", "xss", "path_traversal", "command_injection",
            "sensitive_file_probe", "brute_force",
        }  # fmt: skip

    def test_markdown_has_the_sections(self, demo_run):
        text = (demo_run[1] / "report.md").read_text(encoding="utf-8")
        for title in ("Summary", "Status codes", "Traffic", "Detections", "Charts"):
            assert f"\n## {title}\n" in text
        assert "## Parse problems" not in text  # nothing was skipped

    def test_the_markdown_lists_what_the_json_holds(self, demo_run):
        _, out = demo_run
        text = (out / "report.md").read_text(encoding="utf-8")
        for detection in report_of(out)["detections"]:
            assert detection["rule_id"] in text

    def test_the_charts_are_valid_images(self, demo_run):
        for name in CHARTS:
            data = (demo_run[1] / "charts" / f"{name}.png").read_bytes()
            assert data.startswith(PNG_SIGNATURE)
            assert struct.unpack(">II", data[16:24]) == (800, 450)

    def test_the_markdown_links_charts_that_exist(self, demo_run):
        _, out = demo_run
        for name in CHARTS:
            assert f"](charts/{name}.png)" in (out / "report.md").read_text(encoding="utf-8")

    def test_the_reports_name_no_folder(self, demo_run):
        _, out = demo_run
        for name in ("report.json", "report.md"):
            assert str(ROOT) not in (out / name).read_text(encoding="utf-8")

    def test_same_command_same_bytes(self, demo_run, tmp_path):
        _, first = demo_run
        detect(DEMO, tmp_path)
        for name in FILES:
            assert (first / name).read_bytes() == (tmp_path / name).read_bytes(), name

    def test_a_different_folder_to_run_from_changes_nothing(self, demo_run, tmp_path):
        _, first = demo_run
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        done = loginsight("detect", DEMO, "--output", tmp_path / "out", cwd=elsewhere)
        assert done.returncode == 0
        assert (first / "report.json").read_bytes() == (tmp_path / "out/report.json").read_bytes()

    def test_analyze_gives_the_same_report_files(self, demo_run, tmp_path):
        assert loginsight("analyze", DEMO, "--output", tmp_path).returncode == 0
        assert report_of(tmp_path) == report_of(demo_run[1])


class TestCleanLog:
    def test_nothing_is_detected(self, tmp_path):
        detect(CLEAN, tmp_path)
        assert report_of(tmp_path)["detections"] == []
        assert report_of(tmp_path)["summary"]["total_requests"] == 300
        assert "No detections found." in (tmp_path / "report.md").read_text(encoding="utf-8")

    def test_text_output_agrees(self):
        done = loginsight("detect", CLEAN)
        assert done.returncode == 0 and done.stdout.endswith("No detections found.\n")


class TestJunkLines:
    @pytest.fixture(scope="class")
    @classmethod
    def junk_run(cls, tmp_path_factory):
        folder = tmp_path_factory.mktemp("junk")
        log = folder / "demo_with_junk.log"
        junk = "".join(f"this is not a log line {n}\n" for n in range(20))
        log.write_text(DEMO.read_text(encoding="utf-8") + junk, encoding="utf-8")
        done = loginsight("detect", log, "--output", folder / "out")
        return done, folder / "out"

    def test_exit_code_is_still_zero(self, junk_run):
        assert junk_run[0].returncode == 0

    def test_the_statistics_show_the_skipped_lines(self, junk_run):
        parse = report_of(junk_run[1])["source"]["parse"]
        assert (parse["total_lines"], parse["parsed"], parse["skipped"]) == (520, 500, 20)
        assert parse["skipped_by_reason"] == {"no_match": 20}
        assert len(parse["first_errors"]) == 10

    def test_the_detections_are_the_same_as_without_the_junk(self, junk_run, demo_run):
        assert report_of(junk_run[1])["detections"] == report_of(demo_run[1])["detections"]

    def test_the_markdown_has_the_problems_section(self, junk_run):
        text = (junk_run[1] / "report.md").read_text(encoding="utf-8")
        assert "\n## Parse problems\n" in text
        assert "20 of 520 lines could not be read" in text

    def test_four_percent_junk_gives_no_warning(self, junk_run):
        assert junk_run[0].stderr == ""  # 20 of 520 is under ten percent

    def test_more_junk_gives_a_warning_on_stderr(self, tmp_path):
        log = tmp_path / "mostly_junk.log"
        log.write_text("junk\n" * 30 + DEMO.read_text(encoding="utf-8")[:2000], encoding="utf-8")
        done = loginsight("analyze", log)
        assert done.returncode == 0
        assert done.stderr.startswith("loginsight: warning: ")
        assert "could not be read" in done.stderr


class TestMissingFile:
    def test_exit_code_and_message(self, tmp_path):
        missing = tmp_path / "nope.log"
        done = loginsight("detect", missing, "--output", tmp_path / "out")
        assert done.returncode == 1
        assert done.stdout == ""
        assert (
            done.stderr == f"loginsight: error: cannot read {missing}: No such file or directory\n"
        )
        assert not (tmp_path / "out").exists()

    def test_no_traceback(self, tmp_path):
        assert "Traceback" not in loginsight("analyze", tmp_path / "nope.log").stderr


class TestFileInAnotherFormat:
    def test_exit_code_and_message_for_a_file_nothing_could_be_read_from(self, tmp_path):
        other = tmp_path / "other.log"
        other.write_bytes(bytes(range(256)) * 8)
        done = loginsight("analyze", other, "--output", tmp_path / "out")
        assert done.returncode == 1
        assert done.stdout == ""
        lines = other.read_bytes().count(b"\n") + 1  # the last line has no newline
        assert done.stderr.startswith(f"loginsight: error: none of the {lines} lines in {other} ")
        assert "Traceback" not in done.stderr
        assert not (tmp_path / "out").exists()
