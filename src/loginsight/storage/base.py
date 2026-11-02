"""The storage interface: where logs are read from and reports are written to.

Everything outside this package talks to a :class:`Storage`, never to the file system directly,
so another backend (a cloud bucket, for example) can be added without touching parsing,
analysis, detection or reporting.

A name is a *key*: a relative path made of non-empty parts joined by ``/``. It is never an
absolute path and never contains ``.`` or ``..``, so a key cannot point outside the storage.
"""

from typing import Protocol


class StorageError(OSError):
    """Base class for storage failures."""


class MissingKeyError(StorageError, FileNotFoundError):
    """The key asked for does not exist."""


class InvalidKeyError(StorageError, ValueError):
    """The key is not allowed: empty, absolute, or trying to leave the storage."""


def check_key(key: str) -> str:
    """Return ``key`` if it is a valid key, otherwise raise :class:`InvalidKeyError`."""
    if not isinstance(key, str) or not key:
        raise InvalidKeyError(f"invalid key {key!r}: it must be a non-empty string")
    if "\0" in key or "\\" in key:
        raise InvalidKeyError(f"invalid key {key!r}: it contains a forbidden character")
    if key.startswith("/"):
        raise InvalidKeyError(f"invalid key {key!r}: it must be relative")
    for part in key.split("/"):
        if part in ("", ".", ".."):
            raise InvalidKeyError(f"invalid key {key!r}: it has an empty, '.' or '..' part")
    return key


def check_prefix(prefix: str) -> str:
    """Return ``prefix`` if listing with it is safe: empty, or the start of a valid key."""
    if prefix:
        check_key(prefix.rstrip("/") or "/")
    return prefix


class Storage(Protocol):
    """What a backend must offer. Keys are checked with :func:`check_key`."""

    def read_text(self, key: str) -> str:
        """The content of ``key`` as text: UTF-8, a leading byte order mark dropped and
        invalid bytes replaced, so reading never fails on a badly encoded file.

        Raises :class:`MissingKeyError` if the key does not exist.
        """
        ...

    def write_bytes(self, key: str, data: bytes) -> None:
        """Store ``data`` under ``key``, replacing what was there. The write is atomic: a
        reader sees the old content or the new one, never half of it, and a failure leaves
        no partial file behind. Missing "folders" are created."""
        ...

    def list(self, prefix: str = "") -> list[str]:
        """The sorted keys that start with ``prefix`` (all of them for the empty prefix)."""
        ...

    def exists(self, key: str) -> bool:
        """Whether ``key`` exists."""
        ...
