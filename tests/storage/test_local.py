"""LocalStorage: what is specific to the file system."""

import os

import pytest

from loginsight.storage import InvalidKeyError, LocalStorage, MissingKeyError, Storage
from loginsight.storage import local as local_module


@pytest.fixture
def root(tmp_path):
    folder = tmp_path / "root"
    folder.mkdir()
    return folder


def files_under(folder):
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


class TestMapping:
    def test_a_key_is_a_file_below_the_root(self, root):
        LocalStorage(root).write_bytes("a/b.txt", b"hi")
        assert (root / "a" / "b.txt").read_bytes() == b"hi"

    def test_the_root_may_be_a_string_and_need_not_exist_yet(self, tmp_path):
        store = LocalStorage(str(tmp_path / "new" / "deep"))
        assert store.list() == [] and not store.exists("k")
        store.write_bytes("k", b"x")
        assert (tmp_path / "new" / "deep" / "k").read_bytes() == b"x"

    def test_a_relative_root_is_pinned_when_created(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        store = LocalStorage("rel")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        store.write_bytes("k", b"x")
        assert (tmp_path / "rel" / "k").is_file() and files_under(elsewhere) == []

    def test_it_satisfies_the_protocol_shape(self, root):
        store: Storage = LocalStorage(root)
        assert callable(store.read_text) and callable(store.write_bytes)


class TestStayingInsideTheRoot:
    def test_a_symbolic_link_out_of_the_root_is_refused(self, root, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret")
        (root / "link").symlink_to(outside, target_is_directory=True)
        store = LocalStorage(root)
        with pytest.raises(InvalidKeyError):
            store.read_text("link/secret.txt")
        with pytest.raises(InvalidKeyError):
            store.write_bytes("link/new.txt", b"x")
        assert files_under(outside) == ["secret.txt"]

    def test_a_link_to_a_file_outside_is_refused_and_not_listed(self, root, tmp_path):
        (tmp_path / "secret.txt").write_text("secret")
        (root / "file-link").symlink_to(tmp_path / "secret.txt")
        store = LocalStorage(root)
        with pytest.raises(InvalidKeyError):
            store.read_text("file-link")
        with pytest.raises(InvalidKeyError):
            store.exists("file-link")
        assert store.list() == []

    def test_a_link_that_stays_inside_works(self, root):
        (root / "real").write_text("ok")
        (root / "alias").symlink_to(root / "real")
        assert LocalStorage(root).read_text("alias") == "ok"

    def test_a_dangling_link_is_missing_if_it_points_inside(self, root):
        (root / "dangling").symlink_to(root / "gone")
        with pytest.raises(MissingKeyError):
            LocalStorage(root).read_text("dangling")

    def test_a_sibling_folder_with_the_same_prefix_is_outside(self, tmp_path):
        (tmp_path / "root").mkdir()
        (tmp_path / "root-evil").mkdir()
        (tmp_path / "root" / "link").symlink_to(tmp_path / "root-evil", target_is_directory=True)
        with pytest.raises(InvalidKeyError):
            LocalStorage(tmp_path / "root").write_bytes("link/x", b"x")
        assert files_under(tmp_path / "root-evil") == []


class TestAtomicWrites:
    def test_a_failed_write_leaves_no_temporary_file(self, root, monkeypatch):
        def broken(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(local_module.os, "replace", broken)
        with pytest.raises(OSError, match="disk full"):
            LocalStorage(root).write_bytes("k", b"x")
        assert list(root.iterdir()) == []

    def test_a_failed_write_keeps_the_old_content(self, root, monkeypatch):
        store = LocalStorage(root)
        store.write_bytes("k", b"old")

        def broken(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(local_module.os, "replace", broken)
        with pytest.raises(OSError):
            store.write_bytes("k", b"new")
        monkeypatch.undo()
        assert store.read_text("k") == "old" and files_under(root) == ["k"]

    def test_an_interrupt_in_the_middle_also_cleans_up(self, root, monkeypatch):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(local_module.os, "replace", interrupted)
        with pytest.raises(KeyboardInterrupt):
            LocalStorage(root).write_bytes("k", b"x")
        assert list(root.iterdir()) == []

    def test_the_temporary_file_is_never_listed(self, root, monkeypatch):
        seen = []
        real_replace = os.replace

        def spy(source, target):
            seen.append(LocalStorage(root).list())
            real_replace(source, target)

        monkeypatch.setattr(local_module.os, "replace", spy)
        LocalStorage(root).write_bytes("k", b"x")
        assert seen == [[]]

    def test_two_writes_do_not_share_a_temporary_name(self, root, monkeypatch):
        names = []
        real_replace = os.replace

        def spy(source, target):
            names.append(os.path.basename(source))
            real_replace(source, target)

        monkeypatch.setattr(local_module.os, "replace", spy)
        store = LocalStorage(root)
        store.write_bytes("k", b"1")
        store.write_bytes("k", b"2")
        assert len(set(names)) == 2 and all(n.startswith(".") and n.endswith(".tmp") for n in names)

    def test_a_folder_in_the_way_of_a_file_raises_an_os_error(self, root):
        (root / "k").mkdir()
        with pytest.raises(OSError):
            LocalStorage(root).write_bytes("k", b"x")
        assert files_under(root) == []

    def test_a_file_in_the_way_of_a_folder_raises_an_os_error(self, root):
        (root / "dir").write_text("a file")
        with pytest.raises(OSError):
            LocalStorage(root).write_bytes("dir/k", b"x")
        assert (root / "dir").read_text() == "a file"

    def test_a_read_only_folder_raises_and_writes_nothing(self, root):
        if os.geteuid() == 0:
            pytest.skip("root can write anywhere")
        root.chmod(0o500)
        try:
            with pytest.raises(PermissionError):
                LocalStorage(root).write_bytes("k", b"x")
        finally:
            root.chmod(0o700)
        assert files_under(root) == []


class TestReadingErrors:
    def test_a_directory_is_an_os_error_not_a_missing_key(self, root):
        (root / "dir").mkdir()
        with pytest.raises(IsADirectoryError):
            LocalStorage(root).read_text("dir")

    def test_the_missing_key_error_has_the_usual_message_parts(self, root):
        with pytest.raises(MissingKeyError) as raised:
            LocalStorage(root).read_text("nope")
        assert raised.value.strerror == "No such file or directory"
        assert raised.value.filename == "nope"

    def test_an_unreadable_file_raises_permission_error(self, root):
        if os.geteuid() == 0:
            pytest.skip("root can read anything")
        path = root / "locked"
        path.write_text("x")
        path.chmod(0)
        with pytest.raises(PermissionError):
            LocalStorage(root).read_text("locked")


class TestList:
    def test_directories_and_hidden_temporary_files_are_not_keys(self, root):
        (root / "empty-dir").mkdir()
        (root / ".abc.tmp").write_text("leftover")
        (root / ".hidden").write_text("a real hidden file")
        (root / "k").write_text("x")
        assert LocalStorage(root).list() == [".hidden", "k"]

    def test_a_file_that_only_ends_in_tmp_is_a_key(self, root):
        (root / "report.tmp").write_text("x")
        (root / "dir").mkdir()
        (root / "dir" / "a.tmp").write_text("x")
        assert LocalStorage(root).list() == ["dir/a.tmp", "report.tmp"]

    def test_a_dangling_link_is_not_listed(self, root):
        (root / "dangling").symlink_to(root / "gone")
        (root / "k").write_text("x")
        assert LocalStorage(root).list() == ["k"]

    def test_a_missing_root_lists_nothing(self, tmp_path):
        assert LocalStorage(tmp_path / "absent").list("charts") == []
