"""Where logs are read from and reports are written to, behind one small interface."""

from loginsight.storage.base import (
    InvalidKeyError,
    MissingKeyError,
    Storage,
    StorageError,
    check_key,
    check_prefix,
)
from loginsight.storage.local import LocalStorage

__all__ = [
    "InvalidKeyError",
    "LocalStorage",
    "MissingKeyError",
    "Storage",
    "StorageError",
    "check_key",
    "check_prefix",
]
