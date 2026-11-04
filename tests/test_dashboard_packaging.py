"""The dashboard is optional: the core install must not need Streamlit."""

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # the project supports Python 3.10, which has tomli instead
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def requirement(items, name):
    found = [item for item in items if re.match(rf"{name}\b", item)]
    assert found, f"{name} is not listed"
    return found[0]


def test_streamlit_is_not_a_core_dependency():
    assert not [d for d in PROJECT["dependencies"] if d.lower().startswith("streamlit")]


def test_the_dashboard_extra_holds_streamlit_with_a_range():
    extra = PROJECT["optional-dependencies"]["dashboard"]
    assert len(extra) == 1
    assert re.fullmatch(r"streamlit>=\d+(\.\d+)*,<\d+", extra[0]), extra


def test_the_dev_extra_uses_the_same_range_so_the_tests_run_the_page():
    optional = PROJECT["optional-dependencies"]
    assert requirement(optional["dev"], "streamlit") == optional["dashboard"][0]


def test_the_reason_for_the_range_is_written_down():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text[text.index("dashboard = [") :]
    before = text[: text.index("dashboard = [")].rsplit("\n\n", 1)[-1]
    assert "Streamlit" in before and "1." in before  # a comment naming why and the tested version
    assert "streamlit" in block


def test_the_app_file_is_part_of_the_package():
    assert (ROOT / "src" / "loginsight" / "dashboard" / "app.py").is_file()
