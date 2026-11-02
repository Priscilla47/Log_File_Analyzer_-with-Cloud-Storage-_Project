"""What every Storage backend promises. Run against each backend by the ``storage`` fixture."""

import pytest

from loginsight.storage import InvalidKeyError, MissingKeyError

BAD_KEYS = [
    "",
    "/",
    "/etc/passwd",
    "..",
    "../x",
    "a/../b",
    "a/..",
    "./x",
    "a/./b",
    "a//b",
    "a/",
    "back\\slash",
    "nul\0byte",
]


class TestRoundTrip:
    def test_write_then_read(self, storage):
        storage.write_bytes("report.json", b'{"a": 1}\n')
        assert storage.read_text("report.json") == '{"a": 1}\n'

    def test_unicode_survives(self, storage):
        storage.write_bytes("é/日本.txt", "naïve – 日本語\n".encode())
        assert storage.read_text("é/日本.txt") == "naïve – 日本語\n"

    def test_empty_content(self, storage):
        storage.write_bytes("empty", b"")
        assert storage.read_text("empty") == ""
        assert storage.exists("empty")

    def test_binary_content_is_stored_exactly(self, storage):
        data = bytes(range(256))
        storage.write_bytes("bin", data)
        assert storage.read_text("bin") == data.decode("utf-8", errors="replace")

    def test_writing_again_replaces_the_content(self, storage):
        storage.write_bytes("k", b"old and long")
        storage.write_bytes("k", b"new")
        assert storage.read_text("k") == "new"

    def test_nested_keys_need_no_setup(self, storage):
        storage.write_bytes("a/b/c/d.txt", b"x")
        assert storage.read_text("a/b/c/d.txt") == "x"

    def test_line_endings_are_kept(self, storage):
        storage.write_bytes("crlf", b"a\r\nb\n")
        assert storage.read_text("crlf") == "a\r\nb\n"


class TestReadingText:
    def test_a_byte_order_mark_is_dropped(self, storage):
        storage.write_bytes("bom", b"\xef\xbb\xbfhello")
        assert storage.read_text("bom") == "hello"

    def test_invalid_bytes_are_replaced_not_fatal(self, storage):
        storage.write_bytes("bad", b"ok \xff\xfe end")
        assert storage.read_text("bad") == "ok �� end"

    def test_a_missing_key_raises_the_specific_error(self, storage):
        with pytest.raises(MissingKeyError) as raised:
            storage.read_text("nope")
        assert isinstance(raised.value, FileNotFoundError)  # callers that expect it still work

    def test_a_missing_key_in_a_missing_folder(self, storage):
        with pytest.raises(MissingKeyError):
            storage.read_text("no/such/folder/file")


class TestExists:
    def test_false_before_true_after(self, storage):
        assert not storage.exists("k")
        storage.write_bytes("k", b"x")
        assert storage.exists("k")

    def test_a_folder_is_not_a_key(self, storage):
        storage.write_bytes("dir/file", b"x")
        assert not storage.exists("dir")


class TestList:
    def test_empty_storage(self, storage):
        assert storage.list() == []

    def test_sorted_keys_with_folders(self, storage):
        for key in ["b", "a/z", "a/y", "c/d/e"]:
            storage.write_bytes(key, b"x")
        assert storage.list() == ["a/y", "a/z", "b", "c/d/e"]

    def test_prefix_filters(self, storage):
        for key in ["charts/a.png", "charts/b.png", "report.json", "report.md"]:
            storage.write_bytes(key, b"x")
        assert storage.list("charts/") == ["charts/a.png", "charts/b.png"]
        assert storage.list("charts") == ["charts/a.png", "charts/b.png"]
        assert storage.list("report") == ["report.json", "report.md"]
        assert storage.list("nothing") == []

    def test_a_rewritten_key_is_listed_once(self, storage):
        storage.write_bytes("k", b"1")
        storage.write_bytes("k", b"2")
        assert storage.list() == ["k"]

    @pytest.mark.parametrize("prefix", ["..", "../x", "/abs", "a/../b"])
    def test_a_prefix_that_leaves_the_storage_is_refused(self, storage, prefix):
        with pytest.raises(InvalidKeyError):
            storage.list(prefix)


class TestInvalidKeys:
    @pytest.mark.parametrize("key", BAD_KEYS)
    def test_every_operation_refuses_them(self, storage, key):
        with pytest.raises(InvalidKeyError):
            storage.write_bytes(key, b"x")
        with pytest.raises(InvalidKeyError):
            storage.read_text(key)
        with pytest.raises(InvalidKeyError):
            storage.exists(key)
        assert storage.list() == []  # nothing was created by the attempts

    def test_the_error_is_also_a_value_error_and_a_storage_error(self, storage):
        from loginsight.storage import StorageError

        with pytest.raises(ValueError):
            storage.read_text("..")
        with pytest.raises(StorageError):
            storage.read_text("..")

    def test_an_absolute_key_says_it_must_be_relative(self, storage):
        with pytest.raises(InvalidKeyError, match="must be relative"):
            storage.read_text("/etc/passwd")

    def test_a_non_string_key(self, storage):
        for key in (None, 3, b"k", ["k"]):
            with pytest.raises(InvalidKeyError):
                storage.read_text(key)
