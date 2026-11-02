"""The timing tests measure CPU time, so they do not depend on what else the computer is doing."""

import re
import time
from pathlib import Path

TESTS = Path(__file__).parent


def test_no_test_measures_wall_clock_time():
    offenders = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r"\btime\.(perf_counter|time|monotonic)(_ns)?\(", line):
                offenders.append(f"{path.relative_to(TESTS)}:{number}")
    assert not offenders, (
        f"use time.process_time() (CPU time) instead of the wall clock: {offenders}"
    )


def test_cpu_time_does_not_count_time_spent_waiting():
    started = time.process_time()
    time.sleep(0.3)
    assert time.process_time() - started < 0.1


def test_cpu_time_counts_work():
    started = time.process_time()
    sum(n * n for n in range(2_000_000))
    assert time.process_time() - started > 0.01
