"""The command line reads a log from, and writes a report to, an S3 bucket (mocked here)."""

import json

import pytest

pytest.importorskip("boto3")

from loginsight.cli import EXIT_OK, EXIT_PROBLEM, EXIT_USAGE, main  # noqa: E402
from loginsight.storage import locations  # noqa: E402

GOOD = '203.0.113.5 - - [10/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1500 "-" "x"\n'
ATTACK = (
    "198.51.100.7 - - [10/Oct/2026:10:00:02 +0000] "
    '"GET /search?q=1\'+UNION+SELECT+password+FROM+users-- HTTP/1.1" 500 120 "-" "x"\n'
)


def run(capsys, *argv):
    status = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


@pytest.fixture
def bucket(s3_bucket):
    s3_bucket.put_object(Bucket="logs", Key="2026/access.log", Body=(GOOD + ATTACK).encode())
    return s3_bucket


class TestReadingFromABucket:
    def test_a_log_in_a_bucket_is_analysed_like_a_local_one(self, bucket, tmp_path, capsys):
        (tmp_path / "access.log").write_text(GOOD + ATTACK)
        remote = run(capsys, "detect", "s3://logs/2026/access.log", "--format", "json")
        local = run(capsys, "detect", tmp_path / "access.log", "--format", "json")
        assert remote[0] == local[0] == EXIT_OK and remote[2] == ""
        assert json.loads(remote[1]) == json.loads(local[1])  # same name, numbers, detections
        assert [d["label"] for d in json.loads(remote[1])["detections"]] == ["sql_injection"]

    def test_the_report_names_the_object_not_the_bucket_or_folders(self, bucket, capsys):
        out = run(capsys, "analyze", "s3://logs/2026/access.log", "--format", "json")[1]
        assert json.loads(out)["source"]["name"] == "access.log"

    def test_the_scheme_is_not_case_sensitive(self, bucket, capsys):
        assert run(capsys, "analyze", "S3://logs/2026/access.log")[0] == EXIT_OK

    def test_a_missing_object_gives_the_usual_message(self, bucket, capsys):
        status, out, err = run(capsys, "analyze", "s3://logs/nope.log")
        assert (status, out) == (EXIT_PROBLEM, "")
        assert (
            err == "loginsight: error: cannot read s3://logs/nope.log: No such file or directory\n"
        )

    def test_a_missing_bucket_names_it(self, bucket, capsys):
        status, out, err = run(capsys, "analyze", "s3://no-such-bucket/x.log")
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err.count("\n") == 1 and "no-such-bucket" in err and "NoSuchBucket" in err
        assert "Traceback" not in err

    @pytest.mark.parametrize("location", ["s3://", "s3:///x.log", "s3://logs", "s3://logs/"])
    def test_a_location_without_a_bucket_or_an_object_is_refused_in_one_line(
        self, bucket, capsys, location
    ):
        status, out, err = run(capsys, "analyze", location)
        assert (status, out) == (EXIT_PROBLEM, "") and err.count("\n") == 1
        assert err.startswith("loginsight: error: cannot read " + location)
        assert "invalid location" in err

    def test_a_key_that_leaves_the_prefix_is_refused(self, bucket, capsys):
        status, _, err = run(capsys, "analyze", "s3://logs/../other/x.log")
        assert status == EXIT_PROBLEM and "invalid key" in err

    def test_a_rules_file_can_be_in_a_bucket_too(self, bucket, capsys):
        from loginsight.detection import RuleSet  # noqa: F401

        rules = (
            '[[signature]]\nid = "x"\nlabel = "sql_injection"\nseverity = "low"\n'
            'description = "d"\npattern = "union"\n'
        )
        bucket.put_object(Bucket="logs", Key="rules.toml", Body=rules.encode())
        status, out, _ = run(
            capsys, "detect", "s3://logs/2026/access.log", "--rules", "s3://logs/rules.toml",
            "--format", "json",
        )  # fmt: skip
        assert status == EXIT_OK
        assert [d["rule_id"] for d in json.loads(out)["detections"]] == ["x"]


class TestWritingToABucket:
    def test_the_report_files_are_written_to_the_bucket(self, bucket, capsys):
        status, out, err = run(
            capsys, "detect", "s3://logs/2026/access.log", "--output", "s3://logs/reports/today"
        )
        assert (status, err) == (EXIT_OK, "")
        keys = [
            o["Key"] for o in bucket.list_objects_v2(Bucket="logs", Prefix="reports/")["Contents"]
        ]
        assert sorted(keys) == [
            "reports/today/charts/status.png",
            "reports/today/charts/top_paths.png",
            "reports/today/charts/traffic.png",
            "reports/today/report.json",
            "reports/today/report.md",
        ]
        # what is printed is the place each file went, in the form that can be given back
        assert out.splitlines() == [
            "s3://logs/reports/today/report.json",
            "s3://logs/reports/today/report.md",
            "s3://logs/reports/today/charts/status.png",
            "s3://logs/reports/today/charts/traffic.png",
            "s3://logs/reports/today/charts/top_paths.png",
        ]

    def test_a_trailing_slash_does_not_double_up(self, bucket, capsys):
        out = run(capsys, "analyze", "s3://logs/2026/access.log", "--output", "s3://logs/r/")[1]
        assert out.splitlines()[0] == "s3://logs/r/report.json"

    def test_the_written_report_is_the_one_that_would_have_been_printed(self, bucket, capsys):
        printed = run(capsys, "analyze", "s3://logs/2026/access.log", "--format", "json")[1]
        run(capsys, "analyze", "s3://logs/2026/access.log", "--output", "s3://logs/r")
        stored = bucket.get_object(Bucket="logs", Key="r/report.json")["Body"].read().decode()
        assert stored == printed

    def test_the_whole_bucket_can_be_the_folder(self, bucket, capsys):
        out = run(capsys, "analyze", "s3://logs/2026/access.log", "--output", "s3://logs")[1]
        assert out.splitlines()[0] == "s3://logs/report.json"
        assert bucket.get_object(Bucket="logs", Key="report.json")

    def test_a_report_can_go_to_a_bucket_while_the_log_is_local(self, bucket, tmp_path, capsys):
        (tmp_path / "a.log").write_text(GOOD)
        status = run(capsys, "analyze", tmp_path / "a.log", "--output", "s3://logs/from-local")[0]
        assert status == EXIT_OK and bucket.get_object(Bucket="logs", Key="from-local/report.md")

    def test_a_missing_bucket_is_one_line_and_nothing_is_printed(self, bucket, capsys):
        status, out, err = run(
            capsys, "analyze", "s3://logs/2026/access.log", "--output", "s3://no-such-bucket/r"
        )
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err.count("\n") == 1 and "no-such-bucket" in err and "Traceback" not in err

    def test_a_location_without_a_bucket_is_one_line(self, bucket, capsys):
        status, out, err = run(capsys, "analyze", "s3://logs/2026/access.log", "--output", "s3://")
        assert (status, out) == (EXIT_PROBLEM, "") and "no bucket name" in err


class TestWithoutBoto3:
    def test_the_message_says_how_to_install_it_and_names_nothing_else(self, monkeypatch, capsys):
        from loginsight.storage import s3

        def missing():
            raise s3.StorageError(s3.INSTALL_HINT)

        monkeypatch.setattr(s3, "make_client", missing)
        status, out, err = run(capsys, "analyze", "s3://logs/x.log")
        assert (status, out) == (EXIT_PROBLEM, "")
        assert err == f"loginsight: error: {s3.INSTALL_HINT}\n"

    def test_local_files_never_need_it(self, tmp_path, monkeypatch, capsys):
        from loginsight.storage import s3

        monkeypatch.setattr(s3, "make_client", lambda: pytest.fail("S3 was used"))
        (tmp_path / "a.log").write_text(GOOD)
        assert run(capsys, "analyze", tmp_path / "a.log")[0] == EXIT_OK


class TestTheLocationHelpers:
    @pytest.mark.parametrize(
        ("location", "expected"),
        [
            ("s3://bucket/key", True),
            ("S3://bucket", True),
            ("s3:/bucket/key", False),
            ("/s3://x", False),
            ("logs/s3://x", False),
            ("http://x/y", False),
            ("", False),
        ],
    )
    def test_is_s3(self, location, expected):
        assert locations.is_s3(location) is expected

    @pytest.mark.parametrize(
        ("location", "expected"),
        [
            ("s3://b/k", ("b", "k")),
            ("s3://b/a/b/c.log", ("b", "a/b/c.log")),
            ("s3://b", ("b", "")),
            ("s3://b/", ("b", "")),
        ],
    )
    def test_split(self, location, expected):
        assert locations.split_s3(location) == expected

    def test_a_missing_bucket_is_refused(self):
        with pytest.raises(locations.InvalidKeyError):
            locations.split_s3("s3:///k")

    def test_show_for_the_two_kinds_of_folder(self, tmp_path):
        assert locations.show("s3://b/p", "report.json") == "s3://b/p/report.json"
        assert locations.show("s3://b/p/", "a/b") == "s3://b/p/a/b"
        assert locations.show("s3://b", "k") == "s3://b/k"
        assert locations.show("reports", "r.json") == str(
            __import__("pathlib").Path("reports/r.json")
        )
        with pytest.raises(locations.InvalidKeyError):
            locations.show("s3://b", "../k")

    def test_usage_errors_still_exit_two(self, capsys):
        assert main(["analyze"]) == EXIT_USAGE
        capsys.readouterr()
