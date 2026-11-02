"""``--rules FILE``: the command line can use a custom rules file."""

import json

import pytest

from loginsight.cli import EXIT_OK, EXIT_PROBLEM, EXIT_USAGE, main

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
PROBE = '198.51.100.7 - - [10/Oct/2026:10:00:02 +0000] "GET /secret-area HTTP/1.1" 404 10 "-" "x"\n'
SQLI = (
    "198.51.100.8 - - [10/Oct/2026:10:00:03 +0000] "
    '"GET /s?q=1\'+UNION+SELECT+1 HTTP/1.1" 200 10 "-" "x"\n'
)

CUSTOM = """
[[signature]]
id = "custom-secret-area"
label = "sensitive_file_probe"
severity = "critical"
description = "Requests for the secret area of this site"
pattern = '''^/secret-area'''
"""


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(GOOD + PROBE + SQLI)
    return path


@pytest.fixture
def rules(tmp_path):
    path = tmp_path / "my_rules.toml"
    path.write_text(CUSTOM)
    return path


def run(capsys, *argv):
    status = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def found(capsys, *argv):
    status, out, err = run(capsys, *argv, "--format", "json")
    assert (status, err) == (EXIT_OK, "")
    return [(d["rule_id"], d["severity"]) for d in json.loads(out)["detections"]]


class TestUsingARulesFile:
    def test_the_default_rules_are_used_without_the_option(self, log, capsys):
        assert [rule for rule, _ in found(capsys, "detect", log)] == ["sqli-union-select"]

    def test_a_custom_file_replaces_the_default_rules(self, log, rules, capsys):
        # the custom file has no SQL injection rule, and its own rule fires
        assert found(capsys, "detect", log, "--rules", rules) == [
            ("custom-secret-area", "critical")
        ]

    @pytest.mark.parametrize("command", ["analyze", "detect"])
    def test_both_commands_take_the_option(self, log, rules, capsys, command):
        status, out, err = run(capsys, command, log, "--rules", rules, "--format", "json")
        assert (status, err) == (EXIT_OK, "")
        assert [d["rule_id"] for d in json.loads(out)["detections"]] == ["custom-secret-area"]

    def test_the_other_report_formats_and_the_output_folder_work(
        self, log, rules, tmp_path, capsys
    ):
        status, out, _ = run(capsys, "detect", log, "--rules", rules)
        assert status == EXIT_OK and "custom-secret-area" in out
        status, out, _ = run(capsys, "detect", log, "--rules", rules, "--format", "md")
        assert status == EXIT_OK and "custom-secret-area" in out
        status, _, _ = run(capsys, "detect", log, "--rules", rules, "--output", tmp_path / "o")
        written = json.loads((tmp_path / "o" / "report.json").read_text())
        assert [d["rule_id"] for d in written["detections"]] == ["custom-secret-area"]

    def test_an_empty_rules_file_means_no_signature_detections(self, log, tmp_path, capsys):
        empty = tmp_path / "empty.toml"
        empty.write_text("")
        assert found(capsys, "detect", log, "--rules", empty) == []

    def test_the_behaviour_settings_of_the_file_are_used(self, tmp_path, capsys):
        lines = "".join(
            f'198.51.100.9 - - [10/Oct/2026:10:00:0{n} +0000] "POST /login HTTP/1.1" 401 5 '
            '"-" "x"\n'
            for n in range(3)
        )
        path = tmp_path / "bf.log"
        path.write_text(lines)
        assert found(capsys, "detect", path) == []  # the default needs ten failures
        low = tmp_path / "low.toml"
        low.write_text("[behaviour.brute_force]\nthreshold = 3\nwindow_seconds = 60\n")
        assert found(capsys, "detect", path, "--rules", low) == [
            ("behaviour-brute-force", "medium")
        ]

    def test_a_relative_path_and_a_utf8_bom_work(self, log, tmp_path, capsys, monkeypatch):
        path = tmp_path / "bom.toml"
        path.write_bytes(b"\xef\xbb\xbf" + CUSTOM.encode())
        monkeypatch.chdir(tmp_path)
        assert found(capsys, "detect", log, "--rules", "bom.toml") == [
            ("custom-secret-area", "critical")
        ]


class TestMistakes:
    def test_a_missing_rules_file(self, log, tmp_path, capsys):
        missing = tmp_path / "nope.toml"
        status, out, err = run(capsys, "detect", log, "--rules", missing)
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err == f"loginsight: error: cannot read {missing}: No such file or directory\n"

    def test_a_directory_instead_of_a_file(self, log, tmp_path, capsys):
        status, out, err = run(capsys, "detect", log, "--rules", tmp_path)
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err == f"loginsight: error: cannot read {tmp_path}: Is a directory\n"

    def test_a_file_that_is_not_valid_toml(self, log, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text("this is = = not toml")
        status, out, err = run(capsys, "detect", log, "--rules", bad)
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err.startswith(f"loginsight: error: {bad}: 1 problem:\n  - not valid TOML")
        assert "Traceback" not in err

    def test_an_invalid_pattern_names_the_rule(self, log, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text(CUSTOM.replace("'''^/secret-area'''", "'''(unclosed'''"))
        status, _, err = run(capsys, "detect", log, "--rules", bad)
        assert status == EXIT_PROBLEM
        assert "custom-secret-area" in err and "pattern" in err

    def test_an_unknown_label_is_reported(self, log, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text(CUSTOM.replace("sensitive_file_probe", "made_up"))
        status, _, err = run(capsys, "detect", log, "--rules", bad)
        assert status == EXIT_PROBLEM and "made_up" in err

    def test_every_problem_is_listed(self, log, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text(
            CUSTOM + CUSTOM.replace("custom-secret-area", "second").replace("critical", "huge")
        )
        err = run(capsys, "detect", log, "--rules", bad)[2]
        assert err.count("\n  - ") >= 1 and err.endswith("\n")

    def test_a_file_that_is_not_utf8(self, log, tmp_path, capsys):
        bad = tmp_path / "bin.toml"
        bad.write_bytes(b"\xff\xfe\x00\x01 garbage")
        status, _, err = run(capsys, "detect", log, "--rules", bad)
        # undecodable bytes are replaced when the file is read, so TOML rejects the text
        assert status == EXIT_PROBLEM and "not valid TOML" in err and "Traceback" not in err

    def test_control_characters_in_the_error_are_shown_as_escapes(self, log, tmp_path, capsys):
        bad = tmp_path / "bad\x1bname.toml"
        bad.write_text("= =")
        err = run(capsys, "detect", log, "--rules", bad)[2]
        assert "\x1b" not in err and "\\x1b" in err

    def test_nothing_is_written_when_the_rules_are_bad(self, log, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text("= =")
        out = tmp_path / "out"
        assert run(capsys, "detect", log, "--rules", bad, "--output", out)[0] == EXIT_PROBLEM
        assert not out.exists()

    def test_bad_rules_are_reported_before_a_bad_log(self, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text("= =")
        err = run(capsys, "detect", tmp_path / "missing.log", "--rules", bad)[2]
        assert str(bad) in err and "missing.log" not in err

    def test_the_option_needs_a_value(self, log, capsys):
        status, out, err = run(capsys, "detect", log, "--rules")
        assert (status, out) == (EXIT_USAGE, "")
        assert "expected one argument" in err


def test_the_help_mentions_the_option(capsys):
    status, out, _ = run(capsys, "detect", "--help")
    assert status == EXIT_OK and "--rules" in out
