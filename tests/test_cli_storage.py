"""The command line reads and writes only through the storage layer."""

import json
import os
import re

import pytest

from loginsight import cli
from loginsight.cli import EXIT_OK, EXIT_PROBLEM, main
from loginsight.storage import MissingKeyError

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
ATTACK = (
    "198.51.100.7 - - [10/Oct/2026:10:00:02 +0000] "
    '"GET /search?q=1\'+UNION+SELECT+password+FROM+users-- HTTP/1.1" 500 120 "-" "x"\n'
)


@pytest.fixture
def virtual(monkeypatch, memory_storage_class, tmp_path):
    """Replace the storage the CLI builds by in-memory ones, one per root folder."""
    roots: dict[str, object] = {}

    def factory(root):
        key = str(root)
        return roots.setdefault(key, memory_storage_class())

    monkeypatch.setattr(cli, "LocalStorage", factory)
    monkeypatch.chdir(tmp_path)
    return roots


def run(capsys, *argv):
    status = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_the_log_is_read_from_the_storage_not_from_the_disk(virtual, memory_storage_class, capsys):
    store = memory_storage_class()
    store.write_bytes("access.log", (GOOD + ATTACK).encode())
    virtual["/nowhere/at/all"] = store
    status, out, err = run(capsys, "detect", "/nowhere/at/all/access.log", "--format", "json")
    assert (status, err) == (EXIT_OK, "")
    assert json.loads(out)["summary"]["total_requests"] == 2
    assert [d["label"] for d in json.loads(out)["detections"]] == ["sql_injection"]


def test_the_report_files_are_written_to_the_storage_not_to_the_disk(
    virtual, memory_storage_class, capsys, tmp_path
):
    store = memory_storage_class()
    store.write_bytes("a.log", GOOD.encode())
    virtual["/nowhere"] = store
    status, out, _ = run(capsys, "analyze", "/nowhere/a.log", "--output", "reports/today")
    assert status == EXIT_OK
    written = virtual["reports/today"]
    assert written.list() == [
        "charts/status.png", "charts/top_paths.png", "charts/traffic.png",
        "report.json", "report.md",
    ]  # fmt: skip
    assert out.splitlines() == [
        os.path.join("reports/today", key)
        for key in ["report.json", "report.md", "charts/status.png", "charts/traffic.png",
                    "charts/top_paths.png"]
    ]  # fmt: skip
    assert list(tmp_path.iterdir()) == []  # nothing on the disk


def test_a_missing_key_gives_the_usual_message(virtual, capsys):
    status, out, err = run(capsys, "analyze", "/virtual/nope.log")
    assert (status, out) == (EXIT_PROBLEM, "")
    assert err == "loginsight: error: cannot read /virtual/nope.log: No such file or directory\n"


def test_a_storage_error_without_a_message_shows_its_class(virtual, monkeypatch, capsys):
    def broken(path):
        raise MissingKeyError("odd")

    monkeypatch.setattr(cli, "_read_file", broken)
    err = run(capsys, "analyze", "x.log")[2]
    assert err == "loginsight: error: cannot read x.log: MissingKeyError\n"


class TestOnTheRealDisk:
    """The same behaviour with the real LocalStorage."""

    def test_a_link_to_a_log_elsewhere_still_works(self, tmp_path, capsys):
        real = tmp_path / "var" / "log" / "nginx"
        real.mkdir(parents=True)
        (real / "access.log").write_text(GOOD + ATTACK)
        links = tmp_path / "links"  # the target is outside the folder that holds the link
        links.mkdir()
        (links / "link.log").symlink_to(real / "access.log")
        status, out, _ = run(capsys, "analyze", links / "link.log", "--format", "json")
        assert status == EXIT_OK and json.loads(out)["summary"]["total_requests"] == 2

    def test_the_report_names_the_link_not_its_target(self, tmp_path, capsys):
        (tmp_path / "real.log").write_text(GOOD)
        (tmp_path / "link.log").symlink_to(tmp_path / "real.log")
        out = run(capsys, "analyze", tmp_path / "link.log", "--format", "json")[1]
        assert json.loads(out)["source"]["name"] == "link.log"  # the name as typed, no folders

    def test_a_relative_path_and_a_name_with_spaces(self, tmp_path, capsys, monkeypatch):
        (tmp_path / "my logs").mkdir()
        (tmp_path / "my logs" / "access log.txt").write_text(GOOD)
        monkeypatch.chdir(tmp_path)
        status, out, _ = run(capsys, "analyze", "my logs/../my logs/access log.txt")
        assert status == EXIT_OK and re.search(r"Requests: +1\n", out)

    def test_the_root_folder_is_a_directory_error(self, capsys):
        status, out, err = run(capsys, "analyze", "/")
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err == "loginsight: error: cannot read /: Is a directory\n"

    def test_a_directory_is_a_directory_error(self, tmp_path, capsys):
        err = run(capsys, "analyze", tmp_path)[2]
        assert err == f"loginsight: error: cannot read {tmp_path}: Is a directory\n"

    def test_an_unreadable_log_is_a_permission_error(self, tmp_path, capsys):
        if os.geteuid() == 0:
            pytest.skip("root can read anything")
        path = tmp_path / "locked.log"
        path.write_text(GOOD)
        path.chmod(0)
        err = run(capsys, "analyze", path)[2]
        assert err == f"loginsight: error: cannot read {path}: Permission denied\n"

    def test_a_byte_order_mark_and_bad_bytes_are_handled_as_before(self, tmp_path, capsys):
        path = tmp_path / "bom.log"
        path.write_bytes(b"\xef\xbb\xbf" + GOOD.encode() + b"\xff\xfe garbage\n")
        status, out, _ = run(capsys, "analyze", path)
        assert status == EXIT_OK and "Lines: 2 read, 1 parsed, 1 skipped" in out

    def test_a_log_with_old_mac_line_endings_is_split_like_before(self, tmp_path, capsys):
        path = tmp_path / "mac.log"
        path.write_bytes((GOOD.rstrip("\n") + "\r" + ATTACK.rstrip("\n") + "\r").encode())
        assert re.search(r"Requests: +2\n", run(capsys, "analyze", path)[1])
