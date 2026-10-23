from importlib import import_module
from importlib.metadata import metadata, version

import pytest

import loginsight


def test_version_is_a_non_empty_string():
    assert isinstance(loginsight.__version__, str)
    assert loginsight.__version__


def test_version_matches_installed_metadata():
    assert loginsight.__version__ == version("loginsight")


@pytest.mark.parametrize(
    "name",
    ["parsing", "analysis", "detection", "storage", "reporting", "dashboard"],
)
def test_subpackage_is_importable(name):
    assert import_module(f"loginsight.{name}")


def test_licence_metadata_is_mit():
    assert metadata("loginsight")["License-Expression"] == "MIT"
