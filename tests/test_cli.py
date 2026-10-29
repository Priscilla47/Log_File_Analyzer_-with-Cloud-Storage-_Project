"""Tests for the command line: they call ``main`` with arguments and check what it prints."""

import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from loginsight import __version__, cli
from loginsight.cli import EXIT_OK, EXIT_PROBLEM, EXIT_USAGE, main
from loginsight.detection import Severity

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).parents[1]
DEMO = str(ROOT / "data" / "samples" / "demo.log")
CLEAN = str(ROOT / "data" / "samples" / "clean.log")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
ATTACK = (
    "198.51.100.7 - - [10/Oct/2026:10:00:02 +0000] "
    '"GET /search?q=1\'+UNION+SELECT+password+FROM+users-- HTTP/1.1" 500 120 "-" "x"\n'
)


def run(capsys, *argv):
    """Run ``main`` and return ``(exit status, stdout, stderr)``."""
    status = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


@pytest.fixture
def log(tmp_path):
    def make(text, name="access.log"):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return make


class TestVersionAndHelp:
    def test_version(self, capsys):
        status, out, err = run(capsys, "--version")
        assert (status, out, err) == (EXIT_OK, f"loginsight {__version__}\n", "")

    def test_python_dash_m_version(self):
        done = subprocess.run(
            [sys.executable, "-m", "loginsight", "--version"], capture_output=True, text=True
        )
        assert done.returncode == 0
        assert done.stdout == f"loginsight {__version__}\n"

    def test_help_lists_the_commands(self, capsys):
        status, out, _ = run(capsys, "--help")
        assert status == EXIT_OK
        assert "analyze" in out and "detect" in out

    @pytest.mark.parametrize("command", ["analyze", "detect"])
    def test_command_help(self, capsys, command):
        status, out, _ = run(capsys, command, "--help")
        assert status == EXIT_OK and "--format" in out and "--output" in out

    def test_the_options_belong_to_their_command(self, capsys):
        assert "--top" in run(capsys, "analyze", "--help")[1]
        assert "--min-severity" not in run(capsys, "analyze", "--help")[1]
        assert "--min-severity" in run(capsys, "detect", "--help")[1]
        assert "--top" not in run(capsys, "detect", "--help")[1]


class TestUsageErrors:
    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["frobnicate", DEMO],
            ["analyze"],
            ["detect"],
            ["analyze", DEMO, "--top", "0"],
            ["analyze", DEMO, "--top", "-3"],
            ["analyze", DEMO, "--top", "many"],
            ["analyze", DEMO, "--top", "2.5"],
            ["analyze", DEMO, "--bucket", "day"],
            ["analyze", DEMO, "--format", "xml"],
            ["detect", DEMO, "--format", "html"],
            ["detect", DEMO, "--min-severity", "urgent"],
            ["detect", DEMO, "--top", "3"],
            ["analyze", DEMO, "--min-severity", "high"],
            ["analyze", DEMO, "--nonsense"],
            ["analyze", DEMO, "extra.log"],
            ["analyze", DEMO, "--output"],
        ],
    )
    def test_exit_2_with_a_message_on_stderr(self, capsys, argv):
        status, out, err = run(capsys, *argv)
        assert status == EXIT_USAGE == 2
        assert out == ""
        assert "usage:" in err and "error:" in err
        assert "Traceback" not in err

    def test_the_top_message_names_the_problem(self, capsys):
        err = run(capsys, "analyze", DEMO, "--top", "0")[2]
        assert "--top: must be at least 1, got 0" in err
        assert "not a whole number" in run(capsys, "analyze", DEMO, "--top", "x")[2]


class TestAnalyze:
    def test_prints_a_readable_summary(self, capsys):
        status, out, err = run(capsys, "analyze", DEMO)
        assert status == EXIT_OK and err == ""
        assert "File: demo.log" in out
        assert "Lines: 500 read, 500 parsed, 0 skipped" in out
        assert "Requests:     500" in out
        assert "Top paths" in out and "Top IP addresses" in out
        assert "Traffic per hour" in out
        assert "Detections: 34" in out

    def test_default_format_is_text(self, capsys):
        assert run(capsys, "analyze", DEMO) == run(capsys, "analyze", DEMO, "--format", "text")

    def test_top_limits_the_lists(self, capsys):
        out = run(capsys, "analyze", DEMO, "--top", "3")[1]
        block = out.split("Top IP addresses\n")[1].split("\n\n")[0]
        assert len(block.splitlines()) == 3

    def test_top_defaults_to_ten(self, capsys):
        out = run(capsys, "analyze", DEMO)[1]
        assert len(out.split("Top IP addresses\n")[1].split("\n\n")[0].splitlines()) == 10
        assert len(out.split("Top paths\n")[1].split("\n\n")[0].splitlines()) == 10

    def test_top_one_is_allowed(self, capsys):
        status, out, _ = run(capsys, "analyze", DEMO, "--top", "1")
        assert status == EXIT_OK
        assert len(out.split("Top paths\n")[1].split("\n\n")[0].splitlines()) == 1

    def test_bucket_changes_the_traffic_line(self, capsys):
        out = run(capsys, "analyze", DEMO, "--bucket", "minute")[1]
        assert "Traffic per minute: 11 periods" in out

    def test_json(self, capsys):
        status, out, err = run(capsys, "analyze", DEMO, "--format", "json")
        data = json.loads(out)
        assert status == EXIT_OK and err == ""
        assert list(data) == ["tool", "source", "summary", "traffic", "detections"]
        assert data["summary"]["total_requests"] == 500
        assert len(data["detections"]) == 34

    def test_json_honours_top_and_bucket(self, capsys):
        data = json.loads(run(capsys, "analyze", DEMO, "--format", "json", "--top", "2",
                              "--bucket", "minute")[1])  # fmt: skip
        assert len(data["summary"]["top_paths"]) == 2
        assert data["traffic"]["bucket"] == "minute"

    def test_markdown(self, capsys):
        status, out, _ = run(capsys, "analyze", DEMO, "--format", "md")
        assert status == EXIT_OK
        assert out.startswith("# Log report: demo.log\n")
        assert "## Detections" in out and "charts/" not in out

    def test_nothing_found_is_still_success(self, capsys):
        status, out, _ = run(capsys, "analyze", CLEAN)
        assert status == EXIT_OK and "Detections: 0" in out

    def test_same_input_same_output(self, capsys):
        assert run(capsys, "analyze", DEMO) == run(capsys, "analyze", DEMO)

    def test_the_output_names_no_absolute_path(self, capsys):
        out = run(capsys, "analyze", DEMO)[1]
        assert str(ROOT) not in out


class TestDetect:
    def test_lists_the_detections(self, capsys):
        status, out, err = run(capsys, "detect", DEMO)
        assert status == EXIT_OK and err == ""
        assert "Detections: 34" in out
        assert "SEVERITY" in out and "sqli-union-select" in out

    def test_json_is_valid_and_complete(self, capsys):
        status, out, _ = run(capsys, "detect", DEMO, "--format", "json")
        data = json.loads(out)
        assert status == EXIT_OK
        assert len(data["detections"]) == 34
        assert {d["severity"] for d in data["detections"]} <= {str(s) for s in Severity}

    def test_markdown(self, capsys):
        out = run(capsys, "detect", DEMO, "--format", "md")[1]
        assert "| Severity | Rule | IP | Time | Count | Evidence |" in out

    def test_finding_attacks_is_not_an_error(self, capsys, log):
        assert run(capsys, "detect", log(GOOD + ATTACK))[0] == EXIT_OK

    def test_a_clean_log_says_so(self, capsys):
        status, out, _ = run(capsys, "detect", CLEAN)
        assert status == EXIT_OK and out.endswith("No detections found.\n")

    @pytest.mark.parametrize(
        ("level", "expected"), [("low", 34), ("medium", 26), ("high", 19), ("critical", 5)]
    )
    def test_min_severity_filters(self, capsys, level, expected):
        data = json.loads(run(capsys, "detect", DEMO, "--format", "json",
                              "--min-severity", level)[1])  # fmt: skip
        floor = Severity.from_name(level)
        assert len(data["detections"]) == expected
        assert all(Severity.from_name(d["severity"]) >= floor for d in data["detections"])

    def test_min_severity_high_hides_low_and_medium(self, capsys):
        out = run(capsys, "detect", DEMO, "--min-severity", "high")[1]
        words = {line.split()[0] for line in out.splitlines() if line.startswith("  ")}
        assert not words & {"low", "medium"} and words & {"high", "critical"}

    def test_min_severity_ignores_case(self, capsys):
        a = run(capsys, "detect", DEMO, "--min-severity", "HIGH")
        assert a == run(capsys, "detect", DEMO, "--min-severity", "high")

    def test_nothing_left_after_filtering(self, capsys, log):
        out = run(capsys, "detect", log(GOOD + ATTACK), "--min-severity", "critical")[1]
        assert "No detections found." in out

    def test_filter_applies_to_the_markdown_and_the_files(self, capsys, tmp_path):
        out = run(capsys, "detect", DEMO, "--format", "md", "--min-severity", "critical")[1]
        assert "| low |" not in out and "| medium |" not in out and "| high |" not in out
        run(capsys, "detect", DEMO, "--min-severity", "critical", "--output", tmp_path / "o")
        saved = json.loads((tmp_path / "o" / "report.json").read_text(encoding="utf-8"))
        assert len(saved["detections"]) == 5


class TestOutputFolder:
    @pytest.mark.parametrize("command", ["analyze", "detect"])
    def test_writes_the_files_and_prints_only_their_paths(self, capsys, tmp_path, command):
        target = tmp_path / "out"
        status, out, err = run(capsys, command, DEMO, "--output", target)
        assert status == EXIT_OK and err == ""
        expected = [
            target / "report.json", target / "report.md", target / "charts" / "status.png",
            target / "charts" / "traffic.png", target / "charts" / "top_paths.png",
        ]  # fmt: skip
        assert out.splitlines() == [str(path) for path in expected]
        for path in expected:
            assert path.is_file()

    def test_the_files_are_sound(self, capsys, tmp_path):
        run(capsys, "analyze", DEMO, "--output", tmp_path)
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert data["summary"]["total_requests"] == 500
        assert "![Status codes](charts/status.png)" in (tmp_path / "report.md").read_text()
        header = (tmp_path / "charts" / "traffic.png").read_bytes()[:24]
        assert header.startswith(PNG_SIGNATURE)
        assert struct.unpack(">II", header[16:24]) == (800, 450)

    def test_format_does_not_change_what_is_written(self, capsys, tmp_path):
        run(capsys, "analyze", DEMO, "--format", "json", "--output", tmp_path / "a")
        run(capsys, "analyze", DEMO, "--output", tmp_path / "b")
        for name in ("report.json", "report.md"):
            assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()

    def test_top_and_bucket_reach_the_files(self, capsys, tmp_path):
        run(capsys, "analyze", DEMO, "--top", "2", "--bucket", "minute", "--output", tmp_path)
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert len(data["summary"]["top_ips"]) == 2 and data["traffic"]["bucket"] == "minute"

    def test_creates_missing_folders(self, capsys, tmp_path):
        status, _, _ = run(capsys, "detect", DEMO, "--output", tmp_path / "a" / "b" / "c")
        assert status == EXIT_OK and (tmp_path / "a" / "b" / "c" / "report.json").is_file()

    def test_runs_twice_into_the_same_folder(self, capsys, tmp_path):
        first = run(capsys, "detect", DEMO, "--output", tmp_path)
        assert run(capsys, "detect", DEMO, "--output", tmp_path) == first

    def test_a_file_where_the_folder_should_be(self, capsys, tmp_path):
        blocker = tmp_path / "out"
        blocker.write_text("x")
        status, out, err = run(capsys, "analyze", DEMO, "--output", blocker)
        assert status == EXIT_PROBLEM and out == ""
        assert err.startswith(f"loginsight: error: cannot write to {blocker}: ")
        assert err.count("\n") == 1 and "Traceback" not in err

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
    def test_an_unwritable_folder(self, capsys, tmp_path):
        folder = tmp_path / "ro"
        folder.mkdir()
        folder.chmod(0o500)
        try:
            status, out, err = run(capsys, "analyze", DEMO, "--output", folder / "sub")
        finally:
            folder.chmod(0o700)
        assert status == EXIT_PROBLEM and out == ""
        assert "cannot write to" in err and "Permission denied" in err
        assert err.count("\n") == 1 and "Traceback" not in err


class TestBadInput:
    def test_missing_file(self, capsys, tmp_path):
        missing = tmp_path / "nope.log"
        status, out, err = run(capsys, "analyze", missing)
        assert status == EXIT_PROBLEM and out == ""
        assert err == f"loginsight: error: cannot read {missing}: No such file or directory\n"

    def test_a_directory(self, capsys, tmp_path):
        status, out, err = run(capsys, "detect", tmp_path)
        assert status == EXIT_PROBLEM and out == ""
        assert err == f"loginsight: error: cannot read {tmp_path}: Is a directory\n"

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_an_unreadable_file(self, capsys, log):
        path = log(GOOD)
        path.chmod(0)
        try:
            status, out, err = run(capsys, "analyze", path)
        finally:
            path.chmod(0o600)
        assert status == EXIT_PROBLEM and out == ""
        assert "Permission denied" in err and "Traceback" not in err

    @pytest.mark.parametrize("command", ["analyze", "detect"])
    def test_a_problem_writes_nothing_to_the_output_folder(self, capsys, tmp_path, command):
        run(capsys, command, tmp_path / "missing.log", "--output", tmp_path / "out")
        assert not (tmp_path / "out").exists()

    @pytest.mark.parametrize("fmt", ["text", "json", "md"])
    def test_empty_file_is_success_with_a_note(self, capsys, log, fmt):
        status, out, err = run(capsys, "analyze", log(""), "--format", fmt)
        assert status == EXIT_OK and err == ""
        if fmt == "text":
            assert out.endswith("No requests found.\n")
        elif fmt == "json":
            assert json.loads(out)["summary"]["total_requests"] == 0
        else:
            assert "Requests: 0" in out

    def test_empty_file_detect(self, capsys, log):
        status, out, err = run(capsys, "detect", log(""))
        assert status == EXIT_OK and err == "" and "No detections found." in out

    def test_empty_file_output_folder(self, capsys, log, tmp_path):
        status, out, _ = run(capsys, "analyze", log(""), "--output", tmp_path / "o")
        assert status == EXIT_OK and len(out.splitlines()) == 5

    def test_blank_lines_only(self, capsys, log):
        status, out, err = run(capsys, "analyze", log("\n\n  \n"))
        assert status == EXIT_OK and err == "" and "0 read" in out

    def test_non_utf8_bytes_do_not_crash(self, capsys, tmp_path):
        path = tmp_path / "bin.log"
        path.write_bytes(GOOD.encode() + b"\xff\xfe\x00 garbage\n")
        status, out, _ = run(capsys, "analyze", path)
        assert status == EXIT_OK and "1 skipped" in out


class TestNothingCouldBeRead:
    """A non-empty file where no line parses is a failure; an empty one is not."""

    @pytest.mark.parametrize("command", ["analyze", "detect"])
    def test_a_file_of_only_junk_fails(self, capsys, log, command):
        path = log("not a log line\n" * 4)
        status, out, err = run(capsys, command, path)
        assert status == EXIT_PROBLEM and out == ""
        assert err == (
            f"loginsight: error: none of the 4 lines in {path} "
            "could be read as an access-log entry (no_match: 4)\n"
        )

    def test_the_message_lists_every_reason(self, capsys, log):
        long_line = "x" * 2_000_000 + "\n"
        status, _, err = run(capsys, "analyze", log("junk\n" + long_line))
        assert status == EXIT_PROBLEM
        assert "(no_match: 1, line_too_long: 1)" in err or "(line_too_long: 1, no_match: 1)" in err

    def test_binary_data_fails(self, capsys, tmp_path):
        path = tmp_path / "bin.log"
        path.write_bytes(bytes(range(256)) * 4)
        status, out, err = run(capsys, "analyze", path)
        assert status == EXIT_PROBLEM and out == "" and "error: none of the" in err

    @pytest.mark.parametrize("fmt", ["text", "json", "md"])
    def test_no_report_is_printed_in_any_format(self, capsys, log, fmt):
        status, out, _ = run(capsys, "analyze", log("junk\n"), "--format", fmt)
        assert status == EXIT_PROBLEM and out == ""

    def test_no_files_are_written_with_an_output_folder(self, capsys, log, tmp_path):
        status, out, err = run(capsys, "detect", log("junk\n"), "--output", tmp_path / "out")
        assert status == EXIT_PROBLEM and out == "" and "error:" in err
        assert not (tmp_path / "out").exists()

    def test_control_characters_in_the_file_name_are_shown_as_escapes(self, capsys, tmp_path):
        path = tmp_path / "bad\x1bname.log"
        path.write_text("junk\n", encoding="utf-8")
        err = run(capsys, "analyze", path)[2]
        assert "\\x1b" in err and "\x1b" not in err

    def test_one_good_line_among_junk_still_succeeds(self, capsys, log):
        status, out, err = run(capsys, "analyze", log("junk\n" * 9 + GOOD))
        assert status == EXIT_OK and "Lines: 10 read, 1 parsed, 9 skipped" in out
        assert "warning: 9 of 10 lines (90%)" in err

    def test_an_empty_file_and_blank_lines_are_still_success(self, capsys, log):
        assert run(capsys, "analyze", log(""))[0] == EXIT_OK
        assert run(capsys, "analyze", log("\n  \n"))[0] == EXIT_OK


class TestSkippedLineWarning:
    def lines(self, good, bad):
        return GOOD * good + "not a log line\n" * bad

    def test_no_warning_when_nothing_is_skipped(self, capsys, log):
        assert run(capsys, "analyze", log(self.lines(10, 0)))[2] == ""

    def test_no_warning_at_exactly_ten_percent(self, capsys, log):
        assert run(capsys, "analyze", log(self.lines(9, 1)))[2] == ""

    def test_warning_just_above_ten_percent(self, capsys, log):
        # 2 of 19 lines is 10.5 percent
        assert "(11%)" in run(capsys, "analyze", log(self.lines(17, 2)))[2]

    def test_warning_above_ten_percent(self, capsys, log):
        status, out, err = run(capsys, "analyze", log(self.lines(8, 2)))
        assert status == EXIT_OK
        assert err == "loginsight: warning: 2 of 10 lines (20%) could not be read\n"
        assert "warning" not in out

    def test_warning_goes_to_stderr_not_into_json(self, capsys, log):
        status, out, err = run(capsys, "detect", log(self.lines(1, 3)), "--format", "json")
        assert status == EXIT_OK and "warning" in err
        assert json.loads(out)["source"]["parse"]["skipped"] == 3

    def test_warning_with_an_output_folder(self, capsys, log, tmp_path):
        _, out, err = run(capsys, "detect", log(self.lines(1, 1)), "--output", tmp_path)
        assert "loginsight: warning" in err and "loginsight: warning" not in out


    def test_parse_statistics_are_always_shown(self, capsys, log):
        out = run(capsys, "detect", log(self.lines(3, 1)))[1]
        assert "Lines: 4 read, 3 parsed, 1 skipped (75.0% parsed)" in out


class TestStreams:
    @pytest.mark.parametrize("fmt", ["text", "json", "md"])
    def test_success_prints_nothing_on_stderr(self, capsys, fmt):
        assert run(capsys, "analyze", DEMO, "--format", fmt)[2] == ""

    def test_errors_print_nothing_on_stdout(self, capsys, tmp_path):
        assert run(capsys, "analyze", tmp_path / "nope")[1] == ""

    def test_stdout_text_ends_with_a_newline(self, capsys):
        assert run(capsys, "detect", DEMO)[1].endswith("\n")


class TestUnexpectedOutputProblems:
    def test_control_characters_in_the_log_are_not_printed_raw(self, capsys, log):
        line = (
            "203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "
            '"GET /s?q=1+UNION+SELECT+x\x1b[2J HTTP/1.1" 200 0\n'
        )
        out = run(capsys, "detect", log(line))[1]
        assert "sqli-union-select" in out
        assert "\x1b" not in out and "\\x1b[2J" in out

    def test_a_terminal_that_cannot_show_a_character(self, capsys, log, monkeypatch):
        class Ascii:
            encoding = "ascii"
            text = ""

            def write(self, data):
                data.encode("ascii")
                self.text += data

            def flush(self):
                pass

        fake = Ascii()
        monkeypatch.setattr(cli.sys, "stdout", fake)
        line = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /caf\u00e9/.env HTTP/1.1" 404 0\n'
        assert main(["detect", str(log(line))]) == EXIT_OK
        assert "caf?/.env" in fake.text

    def test_output_is_flushed(self, log, monkeypatch):
        class Counting:
            encoding = "utf-8"
            flushes = 0

            def write(self, data):
                pass

            def flush(self):
                self.flushes += 1

        fake = Counting()
        monkeypatch.setattr(cli.sys, "stdout", fake)
        main(["analyze", str(log(GOOD))])
        assert fake.flushes >= 1

    def test_interrupt(self, capsys, monkeypatch):
        def interrupted(path):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "parse_file", interrupted)
        status, out, err = run(capsys, "analyze", DEMO)
        assert status == cli.EXIT_INTERRUPTED == 130
        assert out == "" and "interrupted" in err and "Traceback" not in err

    def test_closed_pipe(self, capsys, monkeypatch):
        def closed(text):
            raise BrokenPipeError

        monkeypatch.setattr(cli, "_print", closed)
        status, out, err = run(capsys, "analyze", DEMO)
        assert status == EXIT_OK and err == ""

    def test_closed_pipe_for_real(self, tmp_path):
        script = "import sys, loginsight.cli as c\nsys.exit(c.main(['detect', sys.argv[1]]))\n"
        big = tmp_path / "big.log"
        big.write_text(ATTACK * 3000, encoding="utf-8")
        done = subprocess.run(
            f"{sys.executable} -c \"{script}\" {big} | head -c 10 > /dev/null",
            shell=True, capture_output=True, text=True,
        )  # fmt: skip
        assert "Traceback" not in done.stderr and "BrokenPipe" not in done.stderr


class TestRealInvocations:
    def run_module(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "loginsight", *argv], capture_output=True, text=True
        )

    def test_python_dash_m_analyze(self):
        done = self.run_module("analyze", DEMO)
        assert done.returncode == 0 and "Requests:     500" in done.stdout and done.stderr == ""

    def test_exit_codes_reach_the_shell(self, tmp_path):
        assert self.run_module("analyze", str(tmp_path / "nope")).returncode == 1
        assert self.run_module("analyze").returncode == 2
        assert self.run_module("detect", DEMO).returncode == 0

    def test_no_traceback_for_expected_problems(self, tmp_path):
        for argv in (["analyze", str(tmp_path / "nope")], ["analyze", str(tmp_path)], ["x"]):
            assert "Traceback" not in self.run_module(*argv).stderr

    def test_the_installed_command_runs(self):
        script = Path(sys.executable).parent / "loginsight"
        if not script.exists():
            pytest.skip("the package is not installed with its console script")
        done = subprocess.run([str(script), "--version"], capture_output=True, text=True)
        assert done.stdout == f"loginsight {__version__}\n"


class TestMainModule:
    def test_running_the_package_exits_with_the_status_of_main(self, monkeypatch, capsys):
        import runpy

        monkeypatch.setattr(sys, "argv", ["loginsight", "--version"])
        with pytest.raises(SystemExit) as stop:
            runpy.run_module("loginsight", run_name="__main__")
        assert stop.value.code == EXIT_OK
        assert capsys.readouterr().out == f"loginsight {__version__}\n"

    def test_a_failure_status_is_passed_on(self, monkeypatch, tmp_path):
        import runpy

        monkeypatch.setattr(sys, "argv", ["loginsight", "analyze", str(tmp_path / "nope")])
        with pytest.raises(SystemExit) as stop:
            runpy.run_module("loginsight", run_name="__main__")
        assert stop.value.code == EXIT_PROBLEM


class TestPackaging:
    def test_the_console_script_is_declared(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["scripts"] == {"loginsight": "loginsight.cli:main"}

    def test_the_declared_target_exists(self):
        module, _, name = "loginsight.cli:main".partition(":")
        assert callable(getattr(__import__(module, fromlist=[name]), name))

    def test_main_module_runs_main(self):
        source = (ROOT / "src" / "loginsight" / "__main__.py").read_text(encoding="utf-8")
        assert "sys.exit(main())" in source

    def test_the_cli_keeps_logic_out(self):
        # the command line only wires the library together
        source = (ROOT / "src" / "loginsight" / "cli.py").read_text(encoding="utf-8")
        assert not re.search(r"^import (re|json)$", source, re.MULTILINE)
        assert "Temporary exception" in source  # the direct file access is documented
