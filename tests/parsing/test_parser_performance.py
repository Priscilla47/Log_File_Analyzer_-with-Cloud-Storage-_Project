"""Speed check for the log parser on a large file.

Slow, so it is excluded from the normal run. Run it with ``pytest -m slow -s`` to see the
measured throughput.
"""

import importlib.util
import time
from pathlib import Path

import pytest

from loginsight.parsing.parser import parse_file

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_logs.py"

LINES = 100_000
# Deliberately generous: this guards against big regressions, not against a slow machine.
MIN_LINES_PER_SECOND = 10_000

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def big_log(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("generate_logs", SCRIPT)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    lines, _ = generator.generate(seed=42, lines=LINES)
    path = tmp_path_factory.mktemp("perf") / "big.log"
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def test_parser_handles_100k_lines_fast_enough(big_log):
    started = time.perf_counter()
    result = parse_file(big_log)
    elapsed = time.perf_counter() - started

    throughput = LINES / elapsed
    print(f"\nparsed {LINES:,} lines in {elapsed:.2f}s: {throughput:,.0f} lines/s")

    assert result.stats.parsed == LINES
    assert result.stats.skipped == 0
    assert len(result.entries) == LINES
    assert throughput >= MIN_LINES_PER_SECOND
