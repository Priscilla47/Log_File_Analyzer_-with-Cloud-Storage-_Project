"""Guards that keep the development tools in step with each other."""

import re
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
CONFIG = (ROOT / ".pre-commit-config.yaml").read_text()
PYPROJECT = (ROOT / "pyproject.toml").read_text()


def hook_version(repo):
    """The version a repository is pinned to in the pre-commit config."""
    match = re.search(rf"repo:\s*\S*{re.escape(repo)}\s*\n\s*rev:\s*v?([0-9][0-9.]*)", CONFIG)
    assert match, f"{repo} is not pinned in .pre-commit-config.yaml"
    return Version(match.group(1))


def dev_requirement(name):
    """The version range the dev extra allows for a package."""
    match = re.search(rf'"{re.escape(name)}([<>=!~][^"]*)"', PYPROJECT)
    assert match, f"{name} is not listed in pyproject.toml"
    return SpecifierSet(match.group(1))


def test_the_ruff_version_in_pre_commit_is_allowed_by_the_dev_extra():
    # Otherwise a commit can pass locally and fail in CI, or the other way round.
    assert hook_version("ruff-pre-commit") in dev_requirement("ruff")


def test_the_dev_extra_does_not_allow_a_new_ruff_minor_version_unseen():
    # A new ruff minor version can add rules, so it must be adopted deliberately: raise the
    # limit here and the pre-commit pin together.
    spec = str(dev_requirement("ruff"))
    assert "<" in spec, "ruff has no upper bound in the dev extra"
    assert Version("99.0.0") not in dev_requirement("ruff")


def test_pre_commit_is_part_of_the_dev_extra():
    assert dev_requirement("pre-commit")


def test_slow_and_end_to_end_tests_stay_out_of_the_default_run():
    assert "-m 'not slow and not e2e'" in PYPROJECT
    assert '"e2e:' in PYPROJECT and '"slow:' in PYPROJECT


def test_every_end_to_end_test_is_marked_and_the_ci_job_runs_them():
    source = (ROOT / "tests" / "test_end_to_end.py").read_text()
    assert "pytestmark = pytest.mark.e2e" in source
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert 'pytest -m "slow or e2e"' in workflow


def test_the_readme_says_how_to_run_each_group_of_tests():
    readme = (ROOT / "README.md").read_text()
    for command in ("pytest ", "pytest -m slow", "pytest -m e2e"):
        assert command in readme, command
