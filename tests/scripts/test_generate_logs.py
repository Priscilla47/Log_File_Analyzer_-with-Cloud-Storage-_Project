"""Tests for the synthetic log generator in scripts/generate_logs.py."""

import importlib.util
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginsight.parsing.parser import parse_file, parse_line

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate_logs.py"

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
ALL_LABELS = {
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
    "sensitive_file_probe",
    "brute_force",
    "scanner",
}


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("generate_logs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def big(gen):
    """2000 lines at the default ratio, parsed once and shared by several tests."""
    lines, labels = gen.generate(seed=42, lines=2000, attack_ratio=0.1)
    return lines, labels, [parse_line(line) for line in lines]


def labelled_lines(lines, labels, label):
    return [parse_line(lines[item["line"] - 1]) for item in labels if item["label"] == label]


# --- determinism ----------------------------------------------------------------------


def test_same_arguments_give_identical_output(gen):
    assert gen.generate(seed=5, lines=300) == gen.generate(seed=5, lines=300)


def test_different_seed_gives_different_output(gen):
    assert gen.generate(seed=1, lines=300)[0] != gen.generate(seed=2, lines=300)[0]


def test_output_does_not_depend_on_global_random_state(gen):
    import random

    random.seed(1)
    first = gen.generate(seed=9, lines=200)
    random.seed(2)
    assert gen.generate(seed=9, lines=200) == first


def test_command_line_runs_are_byte_identical(gen, tmp_path):
    outputs = []
    for name in ("a", "b"):
        log, labels = tmp_path / f"{name}.log", tmp_path / f"{name}.jsonl"
        args = ["--seed", "42", "--lines", "400", "--output", str(log), "--labels", str(labels)]
        assert gen.main(args) == 0
        outputs.append((log.read_bytes(), labels.read_bytes()))
    assert outputs[0] == outputs[1]


# --- shape of the log -----------------------------------------------------------------


@pytest.mark.parametrize("count", [0, 1, 7, 100, 1000])
def test_exact_line_count(gen, count):
    lines, _ = gen.generate(lines=count)
    assert len(lines) == count


def test_every_line_parses_with_nothing_skipped(gen, tmp_path):
    lines, _ = gen.generate(seed=3, lines=1500)
    path = tmp_path / "gen.log"
    path.write_text("".join(f"{x}\n" for x in lines))
    result = parse_file(path)
    assert result.stats.skipped == 0
    assert result.stats.parsed == 1500


@pytest.mark.parametrize("seed", [1, 2, 3, 42, 99])
def test_every_line_parses_for_several_seeds(gen, seed):
    lines, _ = gen.generate(seed=seed, lines=800, attack_ratio=0.3)
    for line in lines:
        parse_line(line)


def test_only_documentation_addresses_appear(big):
    for entry in big[2]:
        address = ipaddress.ip_address(entry.ip)
        assert any(address in network for network in DOCUMENTATION_NETWORKS), entry.ip


def test_timestamps_never_go_backwards(big):
    times = [entry.time for entry in big[2]]
    assert times == sorted(times)


def test_start_time_is_respected(gen):
    start = datetime(2030, 5, 17, 8, 30, tzinfo=timezone.utc)
    entries = [parse_line(x) for x in gen.generate(lines=200, start=start)[0]]
    assert entries[0].time >= start
    assert entries[0].time - start < timedelta(minutes=1)


def test_naive_start_is_treated_as_utc(gen):
    aware = gen.generate(seed=1, lines=50, start=datetime(2026, 3, 1, tzinfo=timezone.utc))
    naive = gen.generate(seed=1, lines=50, start=datetime(2026, 3, 1))
    assert aware == naive


def test_timestamps_use_english_month_names_whatever_the_locale(gen):
    moment = datetime(2026, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
    assert gen._timestamp(moment) == "03/Feb/2026:04:05:06 +0000"


# --- normal traffic -------------------------------------------------------------------


def test_normal_traffic_is_mostly_successful_gets(gen):
    lines, labels = gen.generate(seed=42, lines=2000, attack_ratio=0)
    entries = [parse_line(x) for x in lines]
    statuses = Counter(e.status for e in entries)
    assert statuses[200] / 2000 > 0.7
    assert statuses[304] > 0
    assert sum(e.method == "GET" for e in entries) / 2000 > 0.8
    assert labels == []


@pytest.mark.parametrize("seed", [1, 7, 42])
def test_error_rates_in_normal_traffic_stay_low(gen, seed):
    lines, _ = gen.generate(seed=seed, lines=2000, attack_ratio=0)
    entries = [parse_line(x) for x in lines]
    not_found = sum(e.status == 404 for e in entries) / len(entries)
    server_errors = sum(e.status >= 500 for e in entries) / len(entries)
    assert 0 < not_found < 0.03
    assert server_errors < 0.005


def test_normal_traffic_has_varied_agents_and_referers(big):
    entries = big[2]
    assert len({e.user_agent for e in entries}) >= 4
    assert len({e.referer for e in entries}) >= 3


def test_hard_negatives_are_present_and_not_labelled(big):
    lines, labels, entries = big
    labelled = {item["line"] for item in labels}
    suspicious_looking = [
        number
        for number, entry in enumerate(entries, start=1)
        if "select+shoes" in entry.target or "file=report.pdf" in entry.target
    ]
    assert suspicious_looking
    assert not labelled.intersection(suspicious_looking)


def test_attackers_use_addresses_normal_visitors_never_use(big):
    _, labels, entries = big
    attackers = {item["ip"] for item in labels}
    labelled = {item["line"] for item in labels}
    normal_ips = {e.ip for n, e in enumerate(entries, start=1) if n not in labelled}
    assert normal_ips
    assert normal_ips.isdisjoint(attackers)


# --- labels ---------------------------------------------------------------------------


def test_labels_are_well_formed_and_point_at_real_lines(big):
    lines, labels, entries = big
    seen = set()
    for item in labels:
        assert set(item) == {"line", "label", "kind", "ip"}
        assert 1 <= item["line"] <= len(lines)
        assert item["line"] not in seen
        seen.add(item["line"])
        assert item["label"] in ALL_LABELS
        assert item["kind"] in {"signature", "behavioural"}
        assert entries[item["line"] - 1].ip == item["ip"]
    assert [item["line"] for item in labels] == sorted(seen)


def test_kind_matches_the_label(big):
    for item in big[1]:
        expected = "behavioural" if item["label"] in {"brute_force", "scanner"} else "signature"
        assert item["kind"] == expected


def test_all_seven_attack_classes_appear(big):
    assert {item["label"] for item in big[1]} == ALL_LABELS


def test_zero_ratio_gives_no_labels_and_an_empty_file(gen, tmp_path):
    lines, labels = gen.generate(lines=500, attack_ratio=0)
    assert labels == []
    log, labels_path = tmp_path / "clean.log", tmp_path / "clean.jsonl"
    args = ["--lines", "300", "--attack-ratio", "0", "--output", str(log)]
    assert gen.main([*args, "--labels", str(labels_path)]) == 0
    assert labels_path.read_text() == ""
    assert len(log.read_text().splitlines()) == 300


@pytest.mark.parametrize(
    ("count", "ratio"), [(1000, 0.1), (1000, 0.25), (2000, 0.05), (1000, 0.5), (1500, 1.0)]
)
def test_attack_ratio_is_respected(gen, count, ratio):
    _, labels = gen.generate(lines=count, attack_ratio=ratio)
    assert abs(len(labels) / count - ratio) <= 0.03
    assert len(labels) == round(count * ratio)


def test_a_log_made_only_of_attacks_is_possible(gen):
    lines, labels = gen.generate(lines=60, attack_ratio=1.0)
    assert len(lines) == len(labels) == 60


def test_labels_file_is_json_lines(gen, tmp_path):
    log, labels_path = tmp_path / "x.log", tmp_path / "x.jsonl"
    gen.main(["--lines", "300", "--output", str(log), "--labels", str(labels_path)])
    rows = [json.loads(row) for row in labels_path.read_text().splitlines()]
    assert len(rows) == 30
    assert rows[0].keys() == {"line", "label", "kind", "ip"}


# --- attacks look like what they are labelled ----------------------------------------


@pytest.mark.parametrize(
    ("label", "markers"),
    [
        ("sql_injection", ("'", "union", "drop", "sleep", "%27")),
        ("xss", ("<", "%3c", "javascript:")),
        ("path_traversal", ("..", "%2e%2e")),
        ("command_injection", (";", "|", "$(", "&&", "%60")),
        (
            "sensitive_file_probe",
            (".env", ".git", "wp-config", "backup", ".aws", "phpinfo", "id_rsa", "database.yml"),
        ),  # noqa: E501
    ],
)
def test_signature_lines_contain_their_telltale(big, label, markers):
    lines, labels, _ = big
    entries = labelled_lines(lines, labels, label)
    assert entries
    for entry in entries:
        assert any(marker in entry.target.lower() for marker in markers), entry.target


def test_signature_attacks_are_single_lines_with_their_own_address(big):
    """Unlike bursts, a signature attack is one line, so no address repeats within a class."""
    _, labels, _ = big
    for label in ("sql_injection", "xss", "path_traversal", "command_injection"):
        rows = [item for item in labels if item["label"] == label]
        assert len(rows) >= 5
        assert all(item["kind"] == "signature" for item in rows)


def bursts(labels, label):
    by_ip = defaultdict(list)
    for item in labels:
        if item["label"] == label:
            by_ip[item["ip"]].append(item["line"])
    return by_ip


def test_brute_force_comes_from_one_address_with_failed_logins(big):
    lines, labels, entries = big
    groups = bursts(labels, "brute_force")
    assert groups
    for ip, numbers in groups.items():
        assert len(numbers) >= 20
        burst = [entries[n - 1] for n in numbers]
        assert all(e.ip == ip for e in burst)
        assert all(e.method == "POST" and e.path == "/login" and e.status == 401 for e in burst)
        assert max(e.time for e in burst) - min(e.time for e in burst) < timedelta(minutes=2)


def test_scanner_hits_many_missing_paths_from_one_address(big):
    _, labels, entries = big
    groups = bursts(labels, "scanner")
    assert groups
    for ip, numbers in groups.items():
        burst = [entries[n - 1] for n in numbers]
        assert len(numbers) >= 40
        assert all(e.ip == ip and e.status == 404 for e in burst)
        assert len({e.path for e in burst}) == len(burst) >= 40
        assert max(e.time for e in burst) - min(e.time for e in burst) < timedelta(minutes=1)


def test_a_small_log_skips_bursts_it_has_no_room_for(gen):
    _, labels = gen.generate(lines=50, attack_ratio=0.5)
    present = {item["label"] for item in labels}
    assert "scanner" not in present
    assert len(labels) == 25


# --- command line ---------------------------------------------------------------------


def test_main_writes_both_files(gen, tmp_path):
    log, labels = tmp_path / "out.log", tmp_path / "out.labels.jsonl"
    args = ["--seed", "42", "--lines", "1000", "--attack-ratio", "0.1"]
    args += ["--start", "2026-01-01T00:00:00Z", "--output", str(log), "--labels", str(labels)]
    assert gen.main(args) == 0
    assert len(log.read_text().splitlines()) == 1000
    assert len(labels.read_text().splitlines()) == 100


def test_labels_file_is_optional(gen, tmp_path):
    log = tmp_path / "only.log"
    assert gen.main(["--lines", "20", "--output", str(log)]) == 0
    assert log.exists()
    assert list(tmp_path.iterdir()) == [log]


def test_output_is_required(gen):
    with pytest.raises(SystemExit) as info:
        gen.main(["--lines", "5"])
    assert info.value.code == 2


@pytest.mark.parametrize(
    "bad",
    [
        ["--attack-ratio", "1.5"],
        ["--attack-ratio", "-0.1"],
        ["--attack-ratio", "lots"],
        ["--lines", "-3"],
        ["--lines", "many"],
        ["--start", "yesterday"],
    ],
)
def test_bad_arguments_exit_with_a_usage_error(gen, tmp_path, bad):
    with pytest.raises(SystemExit) as info:
        gen.main([*bad, "--output", str(tmp_path / "x.log")])
    assert info.value.code == 2


def test_generate_validates_its_arguments(gen):
    with pytest.raises(ValueError):
        gen.generate(attack_ratio=2)
    with pytest.raises(ValueError):
        gen.generate(lines=-1)


def test_defaults_match_the_documented_usage(gen):
    assert gen.DEFAULT_SEED == 42
    assert gen.DEFAULT_LINES == 1000
    assert gen.DEFAULT_ATTACK_RATIO == 0.1
