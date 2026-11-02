"""A storage backed by a folder on the local file system."""

import errno
import os
import uuid
from pathlib import Path

from loginsight.storage.base import InvalidKeyError, MissingKeyError, check_key, check_prefix


class LocalStorage:
    """Keys are paths below ``root``. Nothing outside ``root`` can be read or written."""

    def __init__(self, root) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        """The file for ``key``, refusing anything that ends up outside the root.

        The path is resolved, so a symbolic link inside the root that points elsewhere is
        caught as well as ``..``.
        """
        path = (self.root / check_key(key)).resolve()
        if not path.is_relative_to(self.root):
            raise InvalidKeyError(f"invalid key {key!r}: it leaves the storage")
        return path

    def read_text(self, key: str) -> str:
        path = self._path(key)
        try:
            return path.read_bytes().decode("utf-8-sig", errors="replace")
        except FileNotFoundError as error:
            raise MissingKeyError(errno.ENOENT, os.strerror(errno.ENOENT), key) from error

    def write_bytes(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # A hidden name in the same folder, so the final rename stays on one file system.
        temporary = path.parent / f".{uuid.uuid4().hex}.tmp"
        try:
            with open(temporary, "xb") as file:
                file.write(data)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def list(self, prefix: str = "") -> list[str]:
        check_prefix(prefix)
        keys = []
        for path in self.root.rglob("*"):
            if not path.is_file() or (path.name.startswith(".") and path.name.endswith(".tmp")):
                continue
            if not path.resolve().is_relative_to(self.root):
                continue  # a link to a file elsewhere is not part of this storage
            key = path.relative_to(self.root).as_posix()
            if key.startswith(prefix):
                keys.append(key)
        return sorted(keys)

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()
