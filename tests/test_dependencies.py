"""The core install must stay light: no pandas, only what the code really uses."""

import subprocess
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # the project supports Python 3.10, which has tomli instead
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "data" / "samples" / "demo.log"

SCRIPT = """
import sys
from loginsight.cli import main

code = main(["analyze", sys.argv[1], "--output", sys.argv[2]])
print(code, "pandas" in sys.modules)
"""


def test_a_full_run_does_not_import_pandas(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(DEMO), str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert result.stdout.split()[-2:] == ["0", "False"]


def test_pandas_is_not_a_declared_dependency():
    with open(ROOT / "pyproject.toml", "rb") as handle:
        project = tomllib.load(handle)["project"]
    declared = project["dependencies"]
    assert not any(name.lower().startswith("pandas") for name in declared)
