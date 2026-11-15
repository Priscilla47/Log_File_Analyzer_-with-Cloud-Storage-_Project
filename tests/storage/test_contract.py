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


class TestOpeningText:
    """``open_text`` gives the lines of ``read_text``, without loading the whole text."""

    @staticmethod
    def lines(storage, key):
        with storage.open_text(key) as file:
            return list(file)

    def test_the_lines_come_one_by_one(self, storage):
        storage.write_bytes("a.log", b"one\ntwo\nthree")
        assert self.lines(storage, "a.log") == ["one\n", "two\n", "three"]

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"a\r\nb\r\n", ["a\n", "b\n"]),
            (b"a\rb\r", ["a\n", "b\n"]),
            (b"a\nb\r\nc\rd", ["a\n", "b\n", "c\n", "d"]),
            (b"", []),
            (b"\n", ["\n"]),
        ],
    )
    def test_every_line_ending_is_one_newline_like_a_file_read_in_text_mode(
        self, storage, data, expected
    ):
        storage.write_bytes("k", data)
        assert self.lines(storage, "k") == expected

    def test_a_byte_order_mark_is_dropped(self, storage):
        storage.write_bytes("bom", b"\xef\xbb\xbfhello\nworld\n")
        assert self.lines(storage, "bom") == ["hello\n", "world\n"]

    def test_invalid_bytes_are_replaced_not_fatal(self, storage):
        storage.write_bytes("bad", b"ok \xff\xfe end\nnext\n")
        assert self.lines(storage, "bad") == ["ok �� end\n", "next\n"]

    def test_unicode_survives(self, storage):
        storage.write_bytes("u", "naïve – 日本語\n".encode())
        assert self.lines(storage, "u") == ["naïve – 日本語\n"]

    def test_a_character_and_a_line_ending_split_across_two_reads_stay_whole(self, storage):
        # lines much longer than any read buffer, with multi-byte characters everywhere and a
        # carriage return and its line feed far apart from other line ends
        data = ("é日" * 9000 + "\r\n" + "ü" * 20001 + "\r\n" + "x" * 8191 + "\r").encode()
        storage.write_bytes("big", data)
        expected = [("é日" * 9000) + "\n", ("ü" * 20001) + "\n", ("x" * 8191) + "\n"]
        assert self.lines(storage, "big") == expected

    def test_many_lines_equal_the_text_with_its_line_endings_translated(self, storage):
        text = "".join(f"line {number} é\r\n" for number in range(5000))
        storage.write_bytes("many", text.encode())
        assert self.lines(storage, "many") == [f"line {n} é\n" for n in range(5000)]
        assert "".join(self.lines(storage, "many")) == storage.read_text("many").replace(
            "\r\n", "\n"
        )

    def test_a_missing_key_raises_when_it_is_opened_not_when_it_is_read(self, storage):
        with pytest.raises(MissingKeyError):
            storage.open_text("nope")
        with pytest.raises(MissingKeyError):
            storage.open_text("no/such/folder/file")

    @pytest.mark.parametrize("key", BAD_KEYS)
    def test_a_bad_key_is_refused(self, storage, key):
        with pytest.raises(InvalidKeyError):
            storage.open_text(key)

    def test_leaving_the_with_block_closes_it(self, storage):
        storage.write_bytes("k", b"x\n")
        with storage.open_text("k") as file:
            pass
        assert file.closed

    def test_it_can_be_read_again_and_while_another_is_open(self, storage):
        storage.write_bytes("k", b"a\nb\n")
        with storage.open_text("k") as first, storage.open_text("k") as second:
            assert next(first) == "a\n" and next(second) == "a\n" and next(first) == "b\n"


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
