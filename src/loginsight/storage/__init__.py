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
from loginsight.storage.s3 import S3Storage

__all__ = [
    "InvalidKeyError",
    "LocalStorage",
    "MissingKeyError",
    "S3Storage",
    "Storage",
    "StorageError",
    "check_key",
    "check_prefix",
]
