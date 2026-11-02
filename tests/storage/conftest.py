import pytest

from loginsight.storage import LocalStorage


@pytest.fixture(params=["local", "memory"])
def storage(request, tmp_path, memory_storage_class):
    """Every backend must pass the same contract tests."""
    if request.param == "local":
        return LocalStorage(tmp_path / "root")
    return memory_storage_class()
