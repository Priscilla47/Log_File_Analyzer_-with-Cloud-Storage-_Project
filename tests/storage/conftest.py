import pytest

from loginsight.storage import LocalStorage


@pytest.fixture(params=["local", "memory", "s3", "s3-with-prefix"])
def storage(request, tmp_path, memory_storage_class):
    """Every backend must pass the same contract tests."""
    if request.param == "local":
        return LocalStorage(tmp_path / "root")
    if request.param == "memory":
        return memory_storage_class()
    from loginsight.storage import S3Storage

    client = request.getfixturevalue("s3_bucket")
    if request.param == "s3":
        return S3Storage("logs", client=client)
    # a prefix is a folder inside the bucket: the same contract holds, and a neighbour is invisible
    client.put_object(Bucket="logs", Key="other/neighbour.txt", Body=b"not mine")
    client.put_object(Bucket="logs", Key="reports2/not-in-prefix", Body=b"not mine either")
    return S3Storage("logs", "reports/2026/", client=client)
