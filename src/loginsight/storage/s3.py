"""A storage backed by an Amazon S3 bucket (or anything that speaks the S3 API).

It needs the optional ``boto3`` package (``pip install 'loginsight[s3]'``). Credentials are
never handled here: boto3 finds them the usual way, in the environment variables
(``AWS_ACCESS_KEY_ID`` and friends), the shared credentials file, a named profile
(``AWS_PROFILE``) or the machine's role. Nothing secret is ever read from, or written to, the
repository or a log line.

Keys follow the same rules as every other backend (:func:`check_key`), below an optional
``prefix`` that works like a folder inside the bucket.
"""

import errno
import io
import os
from collections.abc import Callable
from typing import Any, TextIO

from loginsight.storage.base import (
    InvalidKeyError,
    MissingKeyError,
    StorageError,
    check_key,
    check_prefix,
)

INSTALL_HINT = "S3 storage needs boto3. Install it with:  pip install 'loginsight[s3]'"

# Answers that mean "there is no such object", as opposed to "you may not look" or "no network".
_MISSING = {"NoSuchKey", "404", "NotFound"}


def _code(error: Exception) -> str:
    """The error code of a boto3 ``ClientError``, or an empty string for any other error."""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


class _Body(io.RawIOBase):
    """An S3 response body as a binary stream, so the text of an object can be read lazily.

    A failure while reading is turned into a :class:`StorageError` by ``fail``, like every
    other failure of the service.
    """

    def __init__(self, body: Any, fail: Callable[[Exception], StorageError]) -> None:
        super().__init__()
        self._body = body
        self._fail = fail

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        try:
            data = self._body.read(len(buffer))
        except StorageError:
            raise
        except Exception as error:
            raise self._fail(error) from error
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        try:
            self._body.close()
        finally:
            super().close()


def make_client() -> Any:
    """A boto3 S3 client with the default credentials, or a :class:`StorageError` saying that
    boto3 is not installed."""
    try:
        import boto3
    except ImportError:
        raise StorageError(INSTALL_HINT) from None
    return boto3.client("s3")


class S3Storage:
    """Keys are object names in ``bucket``, below ``prefix``.

    ``client`` is a boto3 S3 client; by default one is made with the standard credentials the
    first time it is needed, so building a storage never touches the network. Every failure of
    the service becomes a :class:`StorageError` with a readable message (a missing key a
    :class:`MissingKeyError`), so callers handle S3 like they handle a folder.
    """

    def __init__(self, bucket: str, prefix: str = "", client: Any = None) -> None:
        if not isinstance(bucket, str) or not bucket or "/" in bucket:
            raise InvalidKeyError(f"invalid bucket name {bucket!r}: it must be a name, no '/'")
        self.bucket = bucket
        self.prefix = check_key(prefix.strip("/")) + "/" if prefix.strip("/") else ""
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = make_client()
        return self._client

    def _name(self, key: str) -> str:
        return self.prefix + check_key(key)

    def _fail(self, action: str, key: str, error: Exception) -> StorageError:
        code = _code(error)
        reason = f"{code}: {error}" if code and code not in str(error) else str(error)
        where = f"s3://{self.bucket}/{self.prefix}{key}".rstrip("/")
        return StorageError(f"cannot {action} {where}: {reason}")

    def _get(self, key: str) -> Any:
        """The streaming body of the object ``key``."""
        name = self._name(key)
        try:
            return self.client.get_object(Bucket=self.bucket, Key=name)["Body"]
        except StorageError:
            raise
        except Exception as error:
            if _code(error) in _MISSING:
                raise MissingKeyError(errno.ENOENT, os.strerror(errno.ENOENT), key) from error
            raise self._fail("read", key, error) from error

    def read_text(self, key: str) -> str:
        body = _Body(self._get(key), lambda error: self._fail("read", key, error))
        with body:
            return body.readall().decode("utf-8-sig", errors="replace")

    def open_text(self, key: str) -> TextIO:
        body = _Body(self._get(key), lambda error: self._fail("read", key, error))
        return io.TextIOWrapper(io.BufferedReader(body), encoding="utf-8-sig", errors="replace")

    def write_bytes(self, key: str, data: bytes) -> None:
        name = self._name(key)
        try:
            # one request: S3 shows the old object or the new one, never half of one
            self.client.put_object(Bucket=self.bucket, Key=name, Body=bytes(data))
        except StorageError:
            raise
        except Exception as error:
            raise self._fail("write", key, error) from error

    def list(self, prefix: str = "") -> list[str]:
        check_prefix(prefix)
        found = []
        try:
            pages = self.client.get_paginator("list_objects_v2").paginate(
                Bucket=self.bucket, Prefix=self.prefix + prefix
            )
            for page in pages:
                for item in page.get("Contents", []):
                    key = item["Key"][len(self.prefix) :]
                    try:
                        check_key(key)
                    except InvalidKeyError:
                        continue  # a "folder" marker such as 'charts/' is not a key
                    found.append(key)
        except StorageError:
            raise
        except Exception as error:
            raise self._fail("list", prefix, error) from error
        return sorted(found)

    def exists(self, key: str) -> bool:
        name = self._name(key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=name)
        except StorageError:
            raise
        except Exception as error:
            if _code(error) in _MISSING:
                return False
            raise self._fail("look for", key, error) from error
        return True
