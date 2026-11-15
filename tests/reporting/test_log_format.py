"""The report says which log format was used to read the file."""

import json
from pathlib import Path

import pytest

from loginsight.cli import EXIT_OK, main
from loginsight.parsing.parser import LOG_FORMATS, parse_text
from loginsight.reporting.report import build_report, render_json, render_markdown
from loginsight.reporting.text import render_text

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
LINE = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n'


def build(log_format=None):
    options = {} if log_format is None else {"log_format": log_format}
    return build_report(parse_text(LINE), [], source_name="a.log", **options)


class TestBuildReport:
    def test_the_default_is_apache(self):
        assert build().log_format == "apache"

    @pytest.mark.parametrize("log_format", LOG_FORMATS)
    def test_the_format_is_kept(self, log_format):
        assert build(log_format).log_format == log_format

    @pytest.mark.parametrize("bad", ["iis", "", "NGINX", None])
    def test_an_unknown_format_is_refused(self, bad):
        with pytest.raises(ValueError, match="log_format"):
            build_report(parse_text(LINE), [], source_name="a.log", log_format=bad)


class TestRenderings:
    @pytest.mark.parametrize("log_format", LOG_FORMATS)
    def test_json_has_it_between_name_and_parse(self, log_format):
        source = json.loads(render_json(build(log_format)))["source"]
        assert list(source) == ["name", "format", "parse"]
        assert source["format"] == log_format

    @pytest.mark.parametrize("log_format", LOG_FORMATS)
    def test_markdown_lists_it_first_in_the_summary(self, log_format):
        text = render_markdown(build(log_format))
        assert f"- Log format: {log_format}\n- Lines read:" in text

    @pytest.mark.parametrize("view", ["analyze", "detect"])
    @pytest.mark.parametrize("log_format", LOG_FORMATS)
    def test_the_text_views_show_it_under_the_file_name(self, view, log_format):
        lines = render_text(build(log_format), view).splitlines()
        assert lines[0] == "File: a.log"
        assert lines[1] == f"Format: {log_format}"
        assert lines[2].startswith("Lines: ")


class TestCommandLine:
    def run(self, capsys, name, *argv):
        assert main(["analyze", str(SAMPLES / name), *argv]) == EXIT_OK
        return capsys.readouterr().out

    def test_the_apache_sample(self, capsys):
        out = self.run(capsys, "demo.log", "--format", "json")
        assert json.loads(out)["source"]["format"] == "apache"

    def test_the_nginx_sample(self, capsys):
        out = self.run(capsys, "demo_nginx.log", "--format", "json")
        assert json.loads(out)["source"]["format"] == "nginx"

    def test_a_log_without_escapes_is_called_apache(self, capsys):
        out = self.run(capsys, "clean.log", "--format", "json")
        assert json.loads(out)["source"]["format"] == "apache"

    def test_text_and_markdown_say_so_too(self, capsys):
        assert "\nFormat: nginx\n" in self.run(capsys, "demo_nginx.log")
        assert "- Log format: nginx\n" in self.run(capsys, "demo_nginx.log", "--format", "md")

    def test_the_report_files_in_an_output_folder(self, tmp_path, capsys):
        self.run(capsys, "demo_nginx.log", "--output", str(tmp_path))
        assert json.loads((tmp_path / "report.json").read_text())["source"]["format"] == "nginx"
        assert "- Log format: nginx" in (tmp_path / "report.md").read_text()

    def test_the_two_samples_differ_only_in_the_format_and_the_decoded_evidence(self, capsys):
        apache = json.loads(self.run(capsys, "demo.log", "--format", "json"))
        nginx = json.loads(self.run(capsys, "demo_nginx.log", "--format", "json"))
        assert apache["source"]["format"] != nginx["source"]["format"]
        assert apache["summary"] == nginx["summary"] and apache["traffic"] == nginx["traffic"]
