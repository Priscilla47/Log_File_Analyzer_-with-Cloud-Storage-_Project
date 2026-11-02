import importlib.util
from pathlib import Path

import pytest

from loginsight.storage import LocalStorage

_spec = importlib.util.spec_from_file_location(
    "storage_memory", Path(__file__).parent / "memory.py"
)
memory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(memory)


@pytest.fixture(params=["local", "memory"])
def storage(request, tmp_path):
    """Every backend must pass the same contract tests."""
    if request.param == "local":
        return LocalStorage(tmp_path / "root")
    return memory.MemoryStorage()
