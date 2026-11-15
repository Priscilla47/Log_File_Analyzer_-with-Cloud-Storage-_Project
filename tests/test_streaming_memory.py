"""Reading a log a line at a time needs much less memory than holding it as one text.

Slow, so it is excluded from the normal run. Run it with ``pytest -m slow -s`` to see the
measured peaks. Each way of reading runs in its own process, because a process's peak memory
only ever goes up.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_logs.py"
LINES = 150_000

pytestmark = pytest.mark.slow

# What each process does: read the log one way, then report the peak memory and the result.
PROGRAM = """
import json, resource, sys
from loginsight.workflow import read_lines, read_text
path, way = sys.argv[1:3]
if way == "text":
    with open(path, encoding="utf-8-sig", errors="replace") as file:
        reading = read_text(file.read())
else:
    reading = read_lines(lambda: open(path, encoding="utf-8-sig", errors="replace"))
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"peak_kb": peak, "requests": len(reading.entries),
                  "detections": len(reading.detections), "format": reading.log_format}))
"""


@pytest.fixture(scope="module")
def big_log(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("generate_logs", SCRIPT)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    lines, _ = generator.generate(seed=7, lines=LINES, attack_ratio=0.05)
    path = tmp_path_factory.mktemp("memory") / "big.log"
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def peak(path, way):
    done = subprocess.run(
        [sys.executable, "-c", PROGRAM, str(path), way],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(done.stdout)


def test_a_streamed_log_needs_clearly_less_memory_and_gives_the_same_result(big_log):
    text, streamed = peak(big_log, "text"), peak(big_log, "lines")
    size = big_log.stat().st_size / 1e6
    print(
        f"\n{size:.1f} MB log: as one text {text['peak_kb'] / 1024:.0f} MB, "
        f"line by line {streamed['peak_kb'] / 1024:.0f} MB"
    )
    assert {k: v for k, v in streamed.items() if k != "peak_kb"} == {
        k: v for k, v in text.items() if k != "peak_kb"
    }
    assert streamed["requests"] == LINES
    # measured: about 0.54 (273 MB against 147 MB); the margin is for other Pythons and allocators
    assert streamed["peak_kb"] < 0.75 * text["peak_kb"]
