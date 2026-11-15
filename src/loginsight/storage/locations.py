"""Turning what a person typed (a path, or ``s3://bucket/...``) into a storage and a key.

The command line takes a file to read and a folder to write. Both may be on the local disk or
in an S3 bucket, and this is the only place that knows the difference.
"""

import errno
import os
from pathlib import Path

from loginsight.storage.base import InvalidKeyError, Storage, check_key
from loginsight.storage.local import LocalStorage
from loginsight.storage.s3 import S3Storage

S3_SCHEME = "s3://"


def is_s3(location: str) -> bool:
    """Whether ``location`` names something in an S3 bucket (it starts with ``s3://``)."""
    return location.lower().startswith(S3_SCHEME)


def split_s3(location: str) -> tuple[str, str]:
    """The bucket and the path inside it of ``s3://bucket/path``; the path may be empty.

    Raises :class:`InvalidKeyError` for a location with no bucket.
    """
    rest = location[len(S3_SCHEME) :]
    bucket, _, path = rest.partition("/")
    if not bucket:
        raise InvalidKeyError(f"invalid location {location!r}: it has no bucket name")
    return bucket, path


def storage_for_folder(location: str) -> Storage:
    """The storage for a folder: a directory on this computer, or ``s3://bucket/prefix``."""
    if is_s3(location):
        bucket, prefix = split_s3(location)
        return S3Storage(bucket, prefix)
    return LocalStorage(location)


def read_text(location: str) -> str:
    """The text of the file at ``location``, through the storage layer.

    A local path is resolved first, so a link such as ``/var/log/access.log`` that points
    elsewhere works and the storage is confined to the folder that really holds the file. An
    S3 location must name an object (``s3://bucket/path/access.log``).
    """
    if is_s3(location):
        bucket, key = split_s3(location)
        if not key:
            raise InvalidKeyError(f"invalid location {location!r}: it names a bucket, not a file")
        return S3Storage(bucket).read_text(key)
    path = Path(location).resolve()
    if not path.name:  # the root of the file system
        raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), location)
    return LocalStorage(path.parent).read_text(path.name)


def show(location: str, key: str) -> str:
    """How to write the place ``key`` ended up in ``folder`` for a person to read."""
    if is_s3(location):
        return location.rstrip("/") + "/" + check_key(key)
    return str(Path(location) / key)
