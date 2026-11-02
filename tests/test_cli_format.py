"""The command line reads Apache and Nginx logs without being told which one it has."""

import json
from pathlib import Path

import pytest

from loginsight.cli import EXIT_OK, EXIT_PROBLEM, main

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"
APACHE_LINE = (
    '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /p?n=\\"><svg/onload=alert(1)> HTTP/1.1"'
    ' 200 15 "-" "x"\n'
)
NGINX_LINE = APACHE_LINE.replace('\\"', "\\x22")
PLAIN_LINE = (
    '203.0.113.9 - - [10/Oct/2026:10:00:02 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "x"\n'
)


def detections(capsys, path):
    status = main(["detect", str(path), "--format", "json"])
    out, err = capsys.readouterr()
    assert (status, err) == (EXIT_OK, "")
    return json.loads(out)


def test_the_nginx_sample_gives_the_same_detections_as_the_apache_one(capsys):
    apache = detections(capsys, SAMPLES / "demo.log")
    nginx = detections(capsys, SAMPLES / "demo_nginx.log")
    assert nginx["summary"] == apache["summary"]
    assert nginx["source"]["parse"] == apache["source"]["parse"]
    assert len(nginx["detections"]) == len(apache["detections"]) == 34
    keys = ("label", "severity", "rule_id", "ip", "time", "count")
    assert [[d[k] for k in keys] for d in nginx["detections"]] == [
        [d[k] for k in keys] for d in apache["detections"]
    ]


def test_the_evidence_shows_the_decoded_text_for_nginx_and_the_logged_text_for_apache(capsys):
    apache = detections(capsys, SAMPLES / "demo.log")["detections"]
    nginx = detections(capsys, SAMPLES / "demo_nginx.log")["detections"]
    changed = [(a, n) for a, n in zip(apache, nginx, strict=True) if a["evidence"] != n["evidence"]]
    assert changed  # the two sample lines with a quote
    for a, n in changed:
        assert 'name=\\"><svg' in a["evidence"]
        assert 'name="><svg' in n["evidence"]


def test_a_small_nginx_file(tmp_path, capsys):
    path = tmp_path / "n.log"
    path.write_text(NGINX_LINE + PLAIN_LINE)
    report = detections(capsys, path)
    assert report["source"]["parse"]["skipped"] == 0
    assert [d["label"] for d in report["detections"]] == ["xss"]
    assert 'n="><svg' in report["detections"][0]["evidence"]


def test_a_small_apache_file(tmp_path, capsys):
    path = tmp_path / "a.log"
    path.write_text(APACHE_LINE + PLAIN_LINE)
    report = detections(capsys, path)
    assert [d["label"] for d in report["detections"]] == ["xss"]
    assert 'n=\\"><svg' in report["detections"][0]["evidence"]


def test_a_file_without_escapes_is_read_as_before(tmp_path, capsys):
    path = tmp_path / "p.log"
    path.write_text(PLAIN_LINE * 3)
    report = detections(capsys, path)
    assert (report["summary"]["total_requests"], report["detections"]) == (3, [])


def test_a_file_with_only_digit_escapes_is_read_in_apache_mode(tmp_path, capsys):
    # \x16 is written the same by both servers, so nothing is decoded: it stays as logged
    path = tmp_path / "d.log"
    path.write_text(PLAIN_LINE.replace("/index.html", "/p?n=<script>alert(1)</script>\\x16\\x03"))
    report = detections(capsys, path)
    assert [d["label"] for d in report["detections"]] == ["xss"]
    assert "alert(1)</script>\\x16\\x03" in report["detections"][0]["evidence"]


def test_a_mixed_file_follows_the_majority_and_loses_no_line(tmp_path, capsys):
    path = tmp_path / "mixed.log"
    path.write_text(NGINX_LINE * 3 + APACHE_LINE + PLAIN_LINE)
    report = detections(capsys, path)
    assert report["source"]["parse"]["skipped"] == 0
    assert report["summary"]["total_requests"] == 5


@pytest.mark.parametrize("fmt", ["text", "md"])
def test_the_text_view_and_the_markdown_show_decoded_nginx_evidence(tmp_path, capsys, fmt):
    path = tmp_path / "n.log"
    path.write_text(NGINX_LINE)
    assert main(["detect", str(path), "--format", fmt]) == EXIT_OK
    out = capsys.readouterr().out
    assert "xss" in out and "x22" not in out


@pytest.mark.parametrize("command", ["analyze", "detect"])
def test_a_file_in_another_format_is_still_an_error(tmp_path, capsys, command):
    path = tmp_path / "other.log"
    path.write_text("2026-10-10 10:00:01 INFO started\n" * 3)
    assert main([command, str(path)]) == EXIT_PROBLEM
    assert "none of the 3 lines" in capsys.readouterr().err
