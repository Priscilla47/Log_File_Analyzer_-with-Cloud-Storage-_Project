"""Tests that the committed sample data matches what the generator produces."""

import importlib.util
import ipaddress
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from loginsight.parsing.parser import parse_file, parse_line

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"

DEMO = ["--seed", "42", "--lines", "500", "--attack-ratio", "0.1"]
CLEAN = ["--seed", "7", "--lines", "300", "--attack-ratio", "0"]
START = ["--start", "2026-01-01T00:00:00Z"]

# The exact commands the sample README documents, so the two cannot drift apart.
DEMO_COMMAND = (
    "python scripts/generate_logs.py "
    + " ".join([*DEMO, *START])
    + " --output data/samples/demo.log --labels data/samples/demo.labels.jsonl"
)
CLEAN_COMMAND = (
    "python scripts/generate_logs.py "
    + " ".join([*CLEAN, *START])
    + " --output data/samples/clean.log"
)

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

MARKERS = {
    "sql_injection": ("'", "union", "drop", "sleep", "%27"),
    "xss": ("<", "%3c", "javascript:"),
    "path_traversal": ("..", "%2e%2e"),
    "command_injection": (";", "|", "$(", "&&", "%60"),
    "sensitive_file_probe": (".env", ".git", "wp-config", "backup", ".aws", "phpinfo", "id_rsa"),
}


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def labels():
    rows = (SAMPLES / "demo.labels.jsonl").read_text().splitlines()
    return [json.loads(row) for row in rows]


# --- the committed files are what the documented commands produce ---------------------


def test_demo_files_are_reproduced_byte_for_byte(generator, tmp_path):
    log, labels_file = tmp_path / "demo.log", tmp_path / "demo.labels.jsonl"
    assert generator.main([*DEMO, *START, "--output", str(log), "--labels", str(labels_file)]) == 0
    assert log.read_bytes() == (SAMPLES / "demo.log").read_bytes()
    assert labels_file.read_bytes() == (SAMPLES / "demo.labels.jsonl").read_bytes()


def test_clean_file_is_reproduced_byte_for_byte(generator, tmp_path):
    log = tmp_path / "clean.log"
    assert generator.main([*CLEAN, *START, "--output", str(log)]) == 0
    assert log.read_bytes() == (SAMPLES / "clean.log").read_bytes()


def test_the_readme_documents_the_commands_used_here():
    readme = (SAMPLES / "README.md").read_text()
    assert DEMO_COMMAND in readme
    assert CLEAN_COMMAND in readme


def test_the_readme_states_that_the_data_is_synthetic():
    assert "synthetic" in (SAMPLES / "README.md").read_text().lower()


@pytest.mark.parametrize("name", ["demo.log", "demo.labels.jsonl", "clean.log"])
def test_each_sample_stays_under_200_kb(name):
    assert (SAMPLES / name).stat().st_size < 200 * 1024


def test_the_five_line_parser_sample_is_still_there():
    assert len((SAMPLES / "access_sample.log").read_text().splitlines()) == 5


# --- parsing --------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "count"), [("demo.log", 500), ("clean.log", 300)])
def test_samples_parse_without_skipping_a_line(name, count):
    stats = parse_file(SAMPLES / name).stats
    assert stats.total_lines == count
    assert stats.skipped == 0
    assert stats.parsed == count


# --- labels ---------------------------------------------------------------------------


def test_every_label_points_inside_the_log(labels):
    assert labels
    numbers = [item["line"] for item in labels]
    assert all(1 <= number <= 500 for number in numbers)
    assert len(set(numbers)) == len(numbers)


def test_the_clean_sample_has_no_labels(generator):
    assert not (SAMPLES / "clean.labels.jsonl").exists()
    _, generated = generator.generate(seed=7, lines=300, attack_ratio=0)
    assert generated == []


def test_labelled_lines_look_like_their_class(labels):
    entries = parse_file(SAMPLES / "demo.log").entries
    checked = 0
    for item in labels:
        entry = entries[item["line"] - 1]
        assert entry.ip == item["ip"]
        if item["label"] in MARKERS:
            target = entry.target.lower()
            assert any(marker in target for marker in MARKERS[item["label"]]), entry.target
            checked += 1
    assert checked >= 20


def test_brute_force_lines_are_failed_logins_from_one_address(labels):
    entries = parse_file(SAMPLES / "demo.log").entries
    burst = [entries[i["line"] - 1] for i in labels if i["label"] == "brute_force"]
    assert len(burst) >= 20
    assert len({e.ip for e in burst}) == 1
    assert all(e.method == "POST" and e.path == "/login" and e.status == 401 for e in burst)
    assert max(e.time for e in burst) - min(e.time for e in burst) < timedelta(minutes=2)


def test_harmless_look_alikes_are_present_and_unlabelled(labels):
    entries = parse_file(SAMPLES / "demo.log").entries
    labelled = {item["line"] for item in labels}
    look_alikes = [
        n
        for n, e in enumerate(entries, start=1)
        if re.search(r"select\+shoes|file=report\.pdf|drop\+shipping|union\+jack", e.target)
    ]
    assert look_alikes
    assert labelled.isdisjoint(look_alikes)


# --- addresses ------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["demo.log", "clean.log"])
def test_every_address_is_in_a_documentation_range(name):
    for line in (SAMPLES / name).read_text().splitlines():
        address = ipaddress.ip_address(parse_line(line).ip)
        assert any(address in network for network in DOCUMENTATION_NETWORKS), line


def test_label_addresses_are_documentation_addresses(labels):
    for item in labels:
        address = ipaddress.ip_address(item["ip"])
        assert any(address in network for network in DOCUMENTATION_NETWORKS), item
