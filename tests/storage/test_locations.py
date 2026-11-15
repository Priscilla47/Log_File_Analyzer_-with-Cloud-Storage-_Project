"""locations: a path or an ``s3://`` address turned into a storage and a key."""

import errno

import pytest

from loginsight.storage import InvalidKeyError, MissingKeyError, locations


class TestOpenText:
    def test_a_local_file_is_opened_by_its_path(self, tmp_path):
        (tmp_path / "a.log").write_text("one\ntwo\n")
        with locations.open_text(str(tmp_path / "a.log")) as file:
            assert list(file) == ["one\n", "two\n"]

    def test_a_link_to_a_file_elsewhere_is_followed(self, tmp_path):
        (tmp_path / "real").mkdir()
        (tmp_path / "real" / "a.log").write_text("x\n")
        (tmp_path / "link.log").symlink_to(tmp_path / "real" / "a.log")
        with locations.open_text(str(tmp_path / "link.log")) as file:
            assert list(file) == ["x\n"]

    def test_a_missing_file_raises_when_it_is_opened(self, tmp_path):
        with pytest.raises(MissingKeyError):
            locations.open_text(str(tmp_path / "nope.log"))

    def test_the_root_of_the_file_system_is_a_directory(self):
        with pytest.raises(IsADirectoryError) as raised:
            locations.open_text("/")
        assert raised.value.errno == errno.EISDIR

    def test_a_bucket_alone_is_not_a_file(self):
        with pytest.raises(InvalidKeyError, match="names a bucket, not a file"):
            locations.open_text("s3://logs")

    def test_a_bucket_without_a_name_is_refused(self):
        with pytest.raises(InvalidKeyError, match="no bucket name"):
            locations.open_text("s3:///a.log")

    def test_an_object_in_a_bucket_is_opened(self, s3_bucket):
        s3_bucket.put_object(Bucket="logs", Key="2026/a.log", Body=b"one\r\ntwo\r\n")
        with locations.open_text("s3://logs/2026/a.log") as file:
            assert list(file) == ["one\n", "two\n"]

    def test_the_scheme_is_not_case_sensitive(self, s3_bucket):
        s3_bucket.put_object(Bucket="logs", Key="a.log", Body=b"x\n")
        with locations.open_text("S3://logs/a.log") as file:
            assert list(file) == ["x\n"]

    def test_a_missing_object_raises_when_it_is_opened(self, s3_bucket):
        with pytest.raises(MissingKeyError):
            locations.open_text("s3://logs/nope.log")


class TestReadText:
    """read_text keeps its meaning: the exact text, line endings included."""

    def test_a_local_file_keeps_its_line_endings(self, tmp_path):
        (tmp_path / "a.log").write_bytes(b"a\r\nb\rc\n")
        assert locations.read_text(str(tmp_path / "a.log")) == "a\r\nb\rc\n"

    def test_an_object_keeps_its_line_endings(self, s3_bucket):
        s3_bucket.put_object(Bucket="logs", Key="a.log", Body=b"a\r\nb\n")
        assert locations.read_text("s3://logs/a.log") == "a\r\nb\n"
