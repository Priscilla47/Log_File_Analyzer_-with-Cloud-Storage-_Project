import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def memory_storage_class():
    """The in-memory Storage test double (loaded by path, as tests are not importable)."""
    spec = importlib.util.spec_from_file_location(
        "storage_memory", Path(__file__).parent / "storage" / "memory.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MemoryStorage
