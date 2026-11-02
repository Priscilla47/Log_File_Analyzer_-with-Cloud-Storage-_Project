"""An in-memory Storage, used to prove that code depends on the interface and not on files."""

from loginsight.storage import MissingKeyError, check_key, check_prefix


class MemoryStorage:
    def __init__(self):
        self.files: dict[str, bytes] = {}

    def read_text(self, key):
        try:
            return self.files[check_key(key)].decode("utf-8-sig", errors="replace")
        except KeyError:
            raise MissingKeyError(2, "No such file or directory", key) from None

    def write_bytes(self, key, data):
        self.files[check_key(key)] = bytes(data)

    def list(self, prefix=""):
        check_prefix(prefix)
        return sorted(key for key in self.files if key.startswith(prefix))

    def exists(self, key):
        return check_key(key) in self.files
