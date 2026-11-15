"""What is particular to the S3 backend. The shared promises are in test_contract.py."""

import builtins
import sys

import pytest

pytest.importorskip("boto3")

from loginsight.storage import (  # noqa: E402
    InvalidKeyError,
    MissingKeyError,
    S3Storage,
    StorageError,
    s3,
)


class TestWhereThingsAreStored:
    def test_a_key_becomes_an_object_below_the_prefix(self, s3_bucket):
        S3Storage("logs", "reports/2026", client=s3_bucket).write_bytes("a/b.json", b"{}")
        assert [o["Key"] for o in s3_bucket.list_objects_v2(Bucket="logs")["Contents"]] == [
            "reports/2026/a/b.json"
        ]

    @pytest.mark.parametrize("prefix", ["p", "p/", "/p", "/p/"])
    def test_slashes_around_the_prefix_do_not_matter(self, s3_bucket, prefix):
        S3Storage("logs", prefix, client=s3_bucket).write_bytes("k", b"x")
        assert s3_bucket.get_object(Bucket="logs", Key="p/k")["Body"].read() == b"x"

    def test_no_prefix_means_the_root_of_the_bucket(self, s3_bucket):
        S3Storage("logs", client=s3_bucket).write_bytes("k", b"x")
        assert s3_bucket.get_object(Bucket="logs", Key="k")["Body"].read() == b"x"

    def test_two_prefixes_do_not_see_each_other(self, s3_bucket):
        one = S3Storage("logs", "one", client=s3_bucket)
        two = S3Storage("logs", "two", client=s3_bucket)
        one.write_bytes("k", b"1")
        assert not two.exists("k") and two.list() == [] and one.list() == ["k"]
        with pytest.raises(MissingKeyError):
            two.read_text("k")

    def test_a_prefix_that_is_the_start_of_another_folder_name_is_not_confused_with_it(
        self, s3_bucket
    ):
        s3_bucket.put_object(Bucket="logs", Key="reports2/x", Body=b"x")
        assert S3Storage("logs", "reports", client=s3_bucket).list() == []

    @pytest.mark.parametrize("prefix", ["..", "a/../b", "a//b", "a/./b"])
    def test_a_prefix_that_could_leave_its_folder_is_refused(self, s3_bucket, prefix):
        with pytest.raises(InvalidKeyError):
            S3Storage("logs", prefix, client=s3_bucket)

    @pytest.mark.parametrize("bucket", ["", "a/b", None, 3])
    def test_a_bucket_must_be_a_plain_name(self, bucket):
        with pytest.raises(InvalidKeyError):
            S3Storage(bucket)


class TestListing:
    def test_more_than_one_page_of_keys_is_all_returned(self, s3_bucket):
        store = S3Storage("logs", client=s3_bucket)
        for number in range(2300):  # S3 answers 1,000 keys at a time
            s3_bucket.put_object(Bucket="logs", Key=f"k/{number:05d}", Body=b"")
        keys = store.list()
        assert len(keys) == 2300 and keys == sorted(keys)
        assert keys[0] == "k/00000" and keys[-1] == "k/02299"

    def test_the_pages_are_really_asked_for(self, s3_bucket):
        pages = []
        original = s3_bucket.list_objects_v2

        def counting(**kwargs):
            pages.append(kwargs)
            return original(**kwargs)

        s3_bucket.list_objects_v2 = counting
        for number in range(1100):
            s3_bucket.put_object(Bucket="logs", Key=f"{number:04d}", Body=b"")
        assert len(S3Storage("logs", client=s3_bucket).list()) == 1100
        assert len(pages) == 2

    def test_a_folder_marker_is_not_a_key(self, s3_bucket):
        s3_bucket.put_object(Bucket="logs", Key="charts/", Body=b"")  # what a console creates
        s3_bucket.put_object(Bucket="logs", Key="charts/a.png", Body=b"x")
        assert S3Storage("logs", client=s3_bucket).list() == ["charts/a.png"]

    def test_the_listing_is_sorted_by_key_not_by_arrival(self, s3_bucket):
        store = S3Storage("logs", client=s3_bucket)
        for key in ["b", "a", "C", "a/b"]:
            store.write_bytes(key, b"x")
        assert store.list() == sorted(["b", "a", "C", "a/b"])


class TestErrors:
    def test_a_missing_bucket_is_a_storage_error_that_names_it(self, s3_bucket):
        store = S3Storage("no-such-bucket", client=s3_bucket)
        with pytest.raises(StorageError, match=r"s3://no-such-bucket/k.*NoSuchBucket"):
            store.read_text("k")
        with pytest.raises(StorageError, match="NoSuchBucket"):
            store.write_bytes("k", b"x")
        with pytest.raises(StorageError, match="NoSuchBucket"):
            store.list()
        with pytest.raises(StorageError, match="NoSuchBucket|404|Not Found"):
            store.exists("k")

    def test_a_missing_key_is_not_confused_with_a_missing_bucket(self, s3_bucket):
        store = S3Storage("logs", client=s3_bucket)
        with pytest.raises(MissingKeyError):
            store.read_text("k")
        assert not store.exists("k")

    def test_a_storage_error_is_an_os_error_so_callers_handle_it_like_a_file_problem(
        self, s3_bucket
    ):
        with pytest.raises(OSError):
            S3Storage("no-such-bucket", client=s3_bucket).read_text("k")

    def test_access_denied_is_reported_not_taken_for_a_missing_key(self):
        class Denied(Exception):
            response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}

        class Client:
            def get_object(self, **kwargs):
                raise Denied("An error occurred (AccessDenied): Access Denied")

            def head_object(self, **kwargs):
                raise Denied("An error occurred (403): Forbidden")

        store = S3Storage("logs", client=Client())
        with pytest.raises(StorageError, match="AccessDenied") as raised:
            store.read_text("k")
        assert not isinstance(raised.value, MissingKeyError)
        with pytest.raises(StorageError):
            store.exists("k")  # not False: "no" and "you may not ask" are different answers

    def test_a_network_problem_is_a_storage_error(self):
        class Client:
            def put_object(self, **kwargs):
                raise ConnectionError("Could not connect to the endpoint URL")

        with pytest.raises(StorageError, match="Could not connect"):
            S3Storage("logs", client=Client()).write_bytes("k", b"x")

    def test_the_message_never_holds_credentials(self):
        class Client:
            def get_object(self, **kwargs):
                raise RuntimeError("boom")

        with pytest.raises(StorageError) as raised:
            S3Storage("logs", client=Client()).read_text("k")
        assert "testing" not in str(raised.value)
        assert str(raised.value) == "cannot read s3://logs/k: boom"

    def test_an_invalid_key_never_reaches_the_service(self):
        class Client:
            def __getattr__(self, name):
                raise AssertionError(f"the service was called: {name}")

        store = S3Storage("logs", client=Client())
        for call in (
            lambda: store.read_text("../x"),
            lambda: store.write_bytes("/x", b""),
            lambda: store.exists("a//b"),
            lambda: store.list("../x"),
        ):
            with pytest.raises(InvalidKeyError):
                call()


class TestTheClient:
    def test_building_a_storage_does_not_make_a_client(self, monkeypatch):
        monkeypatch.setattr(s3, "make_client", lambda: pytest.fail("a client was made"))
        S3Storage("logs", "p")

    def test_the_client_is_made_once_when_first_needed(self, monkeypatch, s3_bucket):
        made = []
        monkeypatch.setattr(s3, "make_client", lambda: made.append(1) or s3_bucket)
        store = S3Storage("logs")
        store.write_bytes("k", b"x")
        store.read_text("k")
        assert made == [1]

    def test_the_default_client_uses_the_standard_credentials_and_is_mocked_here(self, s3_bucket):
        store = S3Storage("logs")  # no client given: made from the (fake) environment
        store.write_bytes("k", b"x")
        assert store.read_text("k") == "x"

    def test_without_boto3_the_error_says_how_to_install_it(self, monkeypatch):
        real_import = builtins.__import__

        def refuse(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("No module named 'boto3'")
            return real_import(name, *args, **kwargs)

        monkeypatch.delitem(sys.modules, "boto3", raising=False)
        monkeypatch.setattr(builtins, "__import__", refuse)
        with pytest.raises(StorageError, match=r"pip install 'loginsight\[s3\]'"):
            S3Storage("logs").read_text("k")


class TestContent:
    def test_a_big_object_survives(self, s3_bucket):
        store = S3Storage("logs", client=s3_bucket)
        data = b"line of a log\n" * 400_000  # about 5.6 MB
        store.write_bytes("big.log", data)
        assert store.read_text("big.log") == data.decode()

    def test_the_bytes_are_stored_exactly(self, s3_bucket):
        data = bytes(range(256)) * 10
        S3Storage("logs", client=s3_bucket).write_bytes("k", bytearray(data))
        assert s3_bucket.get_object(Bucket="logs", Key="k")["Body"].read() == data

    def test_writing_again_replaces_in_one_step(self, s3_bucket):
        calls = []
        original = s3_bucket.put_object
        s3_bucket.put_object = lambda **kw: calls.append(kw["Key"]) or original(**kw)
        store = S3Storage("logs", client=s3_bucket)
        store.write_bytes("k", b"old")
        store.write_bytes("k", b"new")
        assert calls == ["k", "k"] and store.read_text("k") == "new"


class TestPrivacyOfTheReport:
    def test_the_storage_object_does_not_keep_or_show_credentials(self, s3_bucket):
        store = S3Storage("logs", "p", client=s3_bucket)
        text = repr(vars(store)) + str(store.__dict__)
        assert "testing" not in text.replace("testing-bucket", "")


class FakeError(Exception):
    def __init__(self, code, text):
        super().__init__(text)
        self.response = {"Error": {"Code": code, "Message": text}}


class TestWhatIsAskedOfTheService:
    def test_the_default_client_is_a_plain_s3_client(self, monkeypatch):
        import types

        asked = []
        fake = types.SimpleNamespace(client=lambda *a, **k: asked.append((a, k)) or "client")
        monkeypatch.setitem(sys.modules, "boto3", fake)
        assert s3.make_client() == "client"
        assert asked == [
            (("s3",), {})
        ]  # nothing but the name: region, keys, endpoint come from boto3

    @pytest.mark.parametrize("data", [bytearray(b"abc"), memoryview(b"abc"), b"abc"])
    def test_the_object_is_given_as_bytes(self, data):
        sent = []

        class Client:
            def put_object(self, **kwargs):
                sent.append(kwargs["Body"])

        S3Storage("logs", client=Client()).write_bytes("k", data)
        assert sent == [b"abc"] and type(sent[0]) is bytes

    def test_the_keys_are_sorted_even_if_the_service_lists_them_in_another_order(self):
        class Paginator:
            def paginate(self, **kwargs):
                return [{"Contents": [{"Key": "b"}, {"Key": "a/z"}]}, {"Contents": [{"Key": "a"}]}]

        class Client:
            def get_paginator(self, name):
                assert name == "list_objects_v2"
                return Paginator()

        assert S3Storage("logs", client=Client()).list() == ["a", "a/z", "b"]

    def test_an_empty_page_has_no_contents_key_and_is_fine(self):
        class Client:
            def get_paginator(self, name):
                return type("P", (), {"paginate": lambda self, **kw: [{"KeyCount": 0}]})()

        assert S3Storage("logs", client=Client()).list() == []

    def test_the_bucket_and_the_prefix_are_what_is_asked_for(self):
        asked = []

        class Paginator:
            def paginate(self, **kwargs):
                asked.append(kwargs)
                return []

        class Client:
            def get_paginator(self, name):
                return Paginator()

        S3Storage("logs", "reports/2026", client=Client()).list("charts/")
        assert asked == [{"Bucket": "logs", "Prefix": "reports/2026/charts/"}]


class TestTheMessages:
    class Client:
        def __init__(self, error):
            self.error = error

        def get_object(self, **kwargs):
            raise self.error

    def test_the_code_is_added_when_the_text_does_not_hold_it(self):
        store = S3Storage("logs", client=self.Client(FakeError("SlowDown", "Please reduce")))
        with pytest.raises(StorageError) as raised:
            store.read_text("k")
        assert str(raised.value) == "cannot read s3://logs/k: SlowDown: Please reduce"

    def test_the_code_is_not_repeated_when_the_text_already_holds_it(self):
        error = FakeError("SlowDown", "An error occurred (SlowDown): Please reduce")
        with pytest.raises(StorageError) as raised:
            S3Storage("logs", client=self.Client(error)).read_text("k")
        assert (
            str(raised.value)
            == "cannot read s3://logs/k: An error occurred (SlowDown): Please reduce"
        )

    def test_the_place_includes_the_prefix(self):
        store = S3Storage("logs", "p/q", client=self.Client(FakeError("SlowDown", "x")))
        with pytest.raises(StorageError, match=r"s3://logs/p/q/k: "):
            store.read_text("k")

    def test_an_error_with_no_code_still_gives_its_text(self):
        with pytest.raises(StorageError) as raised:
            S3Storage("logs", client=self.Client(RuntimeError("boom"))).read_text("k")
        assert str(raised.value) == "cannot read s3://logs/k: boom"


class TestWithoutBoto3EveryOperation:
    @pytest.mark.parametrize(
        "call",
        [
            lambda store: store.read_text("k"),
            lambda store: store.write_bytes("k", b"x"),
            lambda store: store.list(),
            lambda store: store.exists("k"),
        ],
        ids=["read", "write", "list", "exists"],
    )
    def test_each_operation_says_how_to_install_it_instead_of_wrapping_the_message(
        self, monkeypatch, call
    ):
        def missing():
            raise StorageError(s3.INSTALL_HINT)

        monkeypatch.setattr(s3, "make_client", missing)
        with pytest.raises(StorageError) as raised:
            call(S3Storage("logs"))
        assert str(raised.value) == s3.INSTALL_HINT


class FakeBody:
    """A streaming body that counts what was asked of it, and can fail part-way."""

    def __init__(self, data, fail_after=None, error=None):
        self.data, self.position, self.reads, self.closed = data, 0, [], False
        self.fail_after, self.error = fail_after, error

    def read(self, amount=None):
        self.reads.append(amount)
        if self.fail_after is not None and self.position >= self.fail_after:
            raise self.error
        amount = len(self.data) if amount is None else amount
        chunk = self.data[self.position : self.position + amount]
        self.position += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, body):
        self.body = body

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3's own names
        return {"Body": self.body}


class TestStreaming:
    def test_the_object_is_read_in_pieces_not_all_at_once(self):
        body = FakeBody(b"line\n" * 100_000)
        with S3Storage("logs", client=FakeClient(body)).open_text("a.log") as file:
            assert next(file) == "line\n"
        assert max(body.reads) <= 1 << 20 and None not in body.reads
        assert body.position < 1 << 20  # a few lines read, the half megabyte after them was not

    def test_closing_early_closes_the_connection_and_reads_no_more(self):
        body = FakeBody(b"x\n" * 1_000_000)
        with S3Storage("logs", client=FakeClient(body)).open_text("a.log") as file:
            next(file)
        assert body.closed and body.position < 1 << 20

    def test_a_failure_while_reading_is_a_storage_error_with_a_message(self):
        body = FakeBody(b"ok\n" * 10, fail_after=10, error=ConnectionResetError("reset by peer"))
        with S3Storage("logs", client=FakeClient(body)).open_text("a.log") as file:
            with pytest.raises(StorageError, match=r"cannot read s3://logs/a.log: reset by peer"):
                list(file)

    def test_a_storage_error_raised_while_reading_is_not_wrapped_again(self):
        body = FakeBody(b"ok\n" * 10, fail_after=0, error=StorageError("already readable"))
        with S3Storage("logs", client=FakeClient(body)).open_text("a.log") as file:
            with pytest.raises(StorageError, match="^already readable$"):
                list(file)

    def test_a_failure_to_open_is_a_storage_error(self, s3_bucket):
        storage = S3Storage("no-such-bucket", client=s3_bucket)
        with pytest.raises(StorageError, match="no-such-bucket"):
            storage.open_text("a.log")

    def test_reading_the_whole_text_still_keeps_every_byte(self):
        body = FakeBody(b"a\r\nb\rc\n")
        assert S3Storage("logs", client=FakeClient(body)).read_text("k") == "a\r\nb\rc\n"
        assert body.closed

    def test_a_failure_while_reading_the_whole_text_is_a_storage_error(self):
        body = FakeBody(b"ok", fail_after=0, error=OSError("broken pipe"))
        with pytest.raises(StorageError, match="cannot read s3://logs/k: broken pipe"):
            S3Storage("logs", client=FakeClient(body)).read_text("k")
