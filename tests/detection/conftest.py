"""Shared setup for the detection tests: the per-rule test cases in ``rule_cases.toml``.

A test asks for a case by naming one of these arguments, and pytest runs it once for every
case in the file, so no test module needs to import the data:

* ``match_case``: ``(rule_id, target)`` for every request a rule must catch;
* ``no_match_case``: ``(rule_id, target)`` for every near miss a rule must leave alone;
* ``match_variant``: ``(rule_id, how, text)``, each ``match_case`` written four ways (as
  written, case swapped, URL-encoded once, URL-encoded twice; the encoded forms only when the
  target holds no percent sign already);
* ``probe_path_case``: the ``match_case`` entries of the probe rules that have no query string;
* ``default_rule_id``: the id of every rule in the default rules file.
"""

from pathlib import Path
from urllib.parse import quote

import pytest

try:  # the standard library reads TOML from Python 3.11
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - only on Python 3.10
    import tomli as tomllib

from loginsight.detection.ruleset import load_rules

CASES_FILE = Path(__file__).with_name("rule_cases.toml")


def load_rule_cases() -> dict:
    """The contents of ``rule_cases.toml``: ``{rule_id: {"match": [...], "no_match": [...]}}``."""
    return tomllib.loads(CASES_FILE.read_text(encoding="utf-8"))


def variants(target: str) -> dict[str, str]:
    """``target`` as written, with the case swapped, and URL-encoded once and twice."""
    found = {"as written": target, "swapped case": target.swapcase()}
    if "%" not in target:
        found["encoded"] = quote(target, safe="")
        found["encoded twice"] = quote(quote(target, safe=""), safe="")
    return found


def _case_params(key: str) -> list:
    return [
        pytest.param((rule_id, target), id=f"{rule_id}|{target[:50]}")
        for rule_id, table in load_rule_cases().items()
        for target in table.get(key, [])
    ]


def pytest_generate_tests(metafunc):
    names = metafunc.fixturenames
    if "match_case" in names:
        metafunc.parametrize("match_case", _case_params("match"))
    if "match_variant" in names:
        metafunc.parametrize(
            "match_variant",
            [
                pytest.param((rule_id, how, text), id=f"{rule_id}|{how}|{target[:36]}")
                for rule_id, table in load_rule_cases().items()
                for target in table.get("match", [])
                for how, text in variants(target).items()
            ],
        )
    if "probe_path_case" in names:
        probe_cases = [
            case
            for case in _case_params("match")
            if case.values[0][0].startswith("probe-") and "?" not in case.values[0][1]
        ]
        metafunc.parametrize("probe_path_case", probe_cases)
    if "no_match_case" in names:
        metafunc.parametrize("no_match_case", _case_params("no_match"))
    if "default_rule_id" in names:
        metafunc.parametrize("default_rule_id", [rule.id for rule in load_rules().signatures])


@pytest.fixture(scope="session")
def rule_cases() -> dict:
    return load_rule_cases()
