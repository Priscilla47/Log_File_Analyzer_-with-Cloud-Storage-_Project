"""The timing tests measure CPU time, so they do not depend on what else the computer is doing."""

import ast
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).parent

# Clocks that run while the process waits for the processor: a test using one fails on a busy
# computer although the code is fine. ``time.process_time`` is the one to use.
WALL_CLOCKS = {
    "time": {"time", "time_ns", "perf_counter", "perf_counter_ns", "monotonic", "monotonic_ns"},
    "timeit": {"default_timer"},
}


def wall_clock_uses(source: str) -> list[int]:
    """The line numbers in ``source`` that read a wall clock, however it is imported or named."""
    tree = ast.parse(source)
    modules: dict[str, str] = {}  # the name a module is known by here -> the module
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in WALL_CLOCKS:
                    modules[alias.asname or alias.name] = alias.name
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in WALL_CLOCKS:
            if any(alias.name in WALL_CLOCKS[node.module] for alias in node.names):
                lines.add(node.lineno)  # from time import perf_counter [as p]
        elif isinstance(node, ast.Attribute):
            owner = node.value
            if isinstance(owner, ast.Name) and owner.id in modules:
                if node.attr in WALL_CLOCKS[modules[owner.id]]:
                    lines.add(
                        node.lineno
                    )  # time.perf_counter, t.perf_counter, timeit.default_timer
    return sorted(lines)


def test_no_test_file_or_helper_measures_wall_clock_time():
    offenders = []
    for path in sorted(TESTS.rglob("*.py")):
        if path == Path(__file__):
            continue
        offenders += [
            f"{path.relative_to(TESTS)}:{number}"
            for number in wall_clock_uses(path.read_text(encoding="utf-8"))
        ]
    assert not offenders, (
        f"use time.process_time() (CPU time) instead of the wall clock: {offenders}"
    )


@pytest.mark.parametrize(
    "source",
    [
        "import time\nstarted = time.perf_counter()",
        "import time\nx = time.time()",
        "import time\nx = time.monotonic_ns()",
        "import time as t\nx = t.perf_counter()",
        "import time, os\nx = time.perf_counter ()",
        "from time import perf_counter\nx = perf_counter()",
        "from time import sleep, monotonic as m\nx = m()",
        "import timeit\nx = timeit.default_timer()",
        "import timeit as ti\nx = ti.default_timer",
        "import time\n\ndef f():\n    return [time.time() for _ in range(3)]",
    ],
)
def test_the_guard_finds_every_way_of_reading_a_wall_clock(source):
    assert wall_clock_uses(source)


@pytest.mark.parametrize(
    "source",
    [
        "import time\nstarted = time.process_time()",
        "import time\ntime.sleep(1)",
        "from time import sleep, process_time\nprocess_time()",
        "import timeit\nx = timeit.timeit",
        'text = "time.perf_counter()"  # only mentioned in a string',
        "class Clock:\n    def perf_counter(self): ...\nClock().perf_counter()",
        "import datetime\nx = datetime.datetime(2026, 1, 1)",
    ],
)
def test_the_guard_leaves_cpu_time_and_other_code_alone(source):
    assert wall_clock_uses(source) == []


def test_the_guard_reports_the_line():
    assert wall_clock_uses("import time\n\n\nx = 1\ny = time.perf_counter()\n") == [5]


def test_cpu_time_does_not_count_time_spent_waiting():
    started = time.process_time()
    time.sleep(0.3)
    assert time.process_time() - started < 0.1


def test_cpu_time_counts_work():
    started = time.process_time()
    sum(n * n for n in range(2_000_000))
    assert time.process_time() - started > 0.01
