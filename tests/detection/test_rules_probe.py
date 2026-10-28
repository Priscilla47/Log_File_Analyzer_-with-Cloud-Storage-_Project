"""Tests for the default sensitive-file and admin-page probe rules.

Each rule has requests it must catch (written by hand, not copied from the sample data
generator) and near misses that share its words but are not probes. The rules look only at
the path, never at the query string.
"""

import importlib.util
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from loginsight.detection.models import Severity
from loginsight.detection.ruleset import load_rules
from loginsight.detection.signatures import detect_signatures, normalise
from loginsight.parsing.models import LogEntry
from loginsight.parsing.parser import parse_file, parse_line

ROOT = Path(__file__).resolve().parents[2]
WHEN = datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc)
ALL_RULES = {rule.id: rule for rule in load_rules().signatures}
PROBES = {rule_id: rule for rule_id, rule in ALL_RULES.items() if rule_id.startswith("probe-")}

SEVERITIES = {
    "probe-env-file": Severity.HIGH,
    "probe-secret-file": Severity.HIGH,
    "probe-vcs-dir": Severity.HIGH,
    "probe-backup-archive": Severity.MEDIUM,
    "probe-diagnostics": Severity.MEDIUM,
    "probe-admin-panel": Severity.LOW,
}

ATTACKS = {
    "probe-env-file": [
        "/.env.production",
        "/.env.local",
        "/app/.env",
        "/api/v1/.env.staging",
        "/.ENV",
        "/.env.bak",
        "/.env?cache=1",
        "/.env/",
        "/.env;.jpg",
        "/%2eenv",
    ],
    "probe-secret-file": [
        "/.aws/config",
        "/.ssh/id_rsa",
        "/id_ed25519.pub",
        "/.ssh/authorized_keys",
        "/.htpasswd",
        "/admin/.htaccess",
        "/config/secrets.yml",
        "/credentials.json",
        "/wp-config.php~",
        "/wp-config.old",
        "/wp-config.php.save",
        "/configuration.php.orig",
        "/.npmrc",
        "/.pgpass",
        "/.bash_history",
        "/.git-credentials",
        "/.htpasswd?v=2",
        "/.htpasswd;x=1",
        "/.npmrc?x",
    ],
    "probe-vcs-dir": [
        "/.git/HEAD",
        "/.git",
        "/old/.git/config",
        "/.svn/entries",
        "/.hg/store",
        "/.bzr/branch",
        "/.DS_Store",
        "/images/.DS_Store",
        "/.git;/config",
        "/CVS/Entries",
        "/cvs/root",
        "/CVS/Repository",
        "/CVS/Entries?x=1",
        "/CVS/Entries;x",
        "/CVS/Root/",
        "/.DS_Store?v=1",
        "/.DS_Store;x",
        "/.git?x",
    ],
    "probe-backup-archive": [
        "/backup.sql",
        "/db.sql",
        "/dump.sql.gz",
        "/site.tar.gz",
        "/www.zip",
        "/database.sql",
        "/db_backup_2025-10-27.tgz",
        "/site-backup.rar",
        "/wwwroot.7z",
        "/public_html.zip",
        "/index.php.bak",
        "/config.old",
        "/index.php.orig",
        "/.index.php.swp",
        "/index.php~",
        "/BACKUP.ZIP",
        "/backup.zip;jsessionid=1",
        "/index.php.save",
        "/index.php.backup",
        "/index.php.bak?x=1",
        "/config.old;x",
        "/index.php~?x=1",
        "/index.php~;x",
        "/bak.zip",
        "/htdocs.zip",
        "/export.sql",
        "/site.tar",
        "/site.bz2",
        "/db.dump",
        "/db.sql?dl=1",
        "/db.sql;x",
    ],
    "probe-diagnostics": [
        "/phpinfo",
        "/info.php",
        "/server-status",
        "/server-info",
        "/server-status?auto",
        "/actuator/env",
        "/actuator/heapdump",
        "/_profiler/",
        "/elmah.axd",
        "/debug/pprof/",
        "/phpinfo.php5",
        "/trace.axd",
        "/_debugbar/open",
    ],
    "probe-admin-panel": [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-admin/install.php",
        "/xmlrpc.php",
        "/phpmyadmin",
        "/phpMyAdmin/index.php",
        "/phpmyadmin-4.9.0/",
        "/pma/",
        "/myadmin/",
        "/adminer.php",
        "/manager/html",
    ],
}

# Requests that share a rule's words but are not probes.
NEAR_MISSES = {
    "probe-env-file": [
        "/environment",
        "/blog/using-env-files",
        "/.envelope",
        "/.environment",
        "/env",
    ],
    "probe-secret-file": [
        "/credentials",
        "/credentials-policy",
        "/secret-santa",
        "/ssh-keys-guide",
        "/id_card",
    ],
    "probe-vcs-dir": [
        "/.github/workflows/ci.yml",
        "/.gitignore",
        "/git/intro",
        "/svn-vs-git",
        "/cvs/intro",
        "/cvs-tutorial",
        "/github/readme",
    ],
    "probe-backup-archive": [
        "/products/backup-power-supply",
        "/downloads/app-v2.zip",
        "/files/report.zip",
        "/files/photos.tar.gz",
        "/old/spring-sale",
        "/backup",
        "/backup.html",
        "/db",
        "/sitemap.xml",
        "/~user/page.html",
    ],
    "probe-diagnostics": [
        "/blog/what-is-phpinfo",
        "/docs/server-status-codes",
        "/server-side-rendering",
        "/actuator/health",
        "/actuator/info",
    ],
    "probe-admin-panel": [
        "/admin-guide",
        "/blog/phpmyadmin-tutorial",
        "/docs/xmlrpc-explained",
        "/pma-results",
        "/wp-content/uploads/a.jpg",
        "/wp-json/wp/v2/posts",
    ],
}

# The query string is never looked at by these rules: a probe-like word there is a different
# problem (file inclusion), which the path traversal rules handle.
QUERY_ONLY = [
    "/index.php?file=.env",
    "/x?f=/.git/config",
    "/x?next=/wp-login.php",
    "/x?download=backup.zip",
    "/x?page=phpinfo.php",
    "/x?u=/.aws/credentials",
    "/x?path=/phpmyadmin",
    "/search?q=.env",
    "/s?q=id_rsa",
    "/s?q=wp-config.php.bak",
]

HARMLESS = [
    "/static/app.js",
    "/downloads/annual-report-2025.pdf",
    "/products/backup-power-supply",
    "/login",
    "/admin-guide",
    "/environment",
    "/blog/using-env-files",
    "/robots.txt",
    "/favicon.ico",
    "/",
    "/home",
    "/api/users/42",
    "/static/css/app.css",
    "/img/logo.png",
    "/products/12",
    "/search?q=select+shoes",
    "/sitemap.xml",
    "/admin",
    "/admin/",
    "/administrator",
    "/api/db/status",
    "/photos/site-visit.jpg",
    "/img/backup-icon.png",
    "/blog/my-backup-strategy",
    "/info",
    "/information.php",
    "/status",
    "/manager",
    "/manager/status",
    "/wp",
    "/cpanel",
]

# Attacks written in a way these rules cannot see, pinned so a later fix has to move them.
KNOWN_GAPS = [
    ("probe-backup-archive", "/backup.zip%00.jpg"),  # the NUL is removed, leaving backup.zip.jpg
    ("probe-env-file", "/.env."),  # a trailing dot, which Windows servers ignore
    ("probe-env-file", "/.env%20"),  # a trailing space
    ("probe-backup-archive", "/backup.sql."),
]


def fired(target):
    text = normalise(target)
    return sorted(rule_id for rule_id, rule in ALL_RULES.items() if rule.compiled.search(text))


def probes_fired(target):
    return [rule_id for rule_id in fired(target) if rule_id.startswith("probe-")]


def matches(rule_id, target):
    return bool(ALL_RULES[rule_id].compiled.search(normalise(target)))


def entry_for(target):
    path, _, query = target.partition("?")
    return LogEntry(
        ip="203.0.113.7",
        time=WHEN,
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=404,
        size=0,
        request=f"GET {target} HTTP/1.1",
    )


def variants(target):
    found = {"as written": target, "swapped case": target.swapcase()}
    if "%" not in target:
        found["encoded"] = quote(target, safe="")
        found["encoded twice"] = quote(quote(target, safe=""), safe="")
    return found


CASES = [(rule_id, target) for rule_id, targets in ATTACKS.items() for target in targets]
VARIANT_CASES = [
    pytest.param(rule_id, name, text, id=f"{rule_id}|{name}|{target[:36]}")
    for rule_id, target in CASES
    for name, text in variants(target).items()
]


# --- the rule set ---------------------------------------------------------------------


def test_there_are_six_probe_rules_with_the_agreed_severities():
    assert {rule_id: rule.severity for rule_id, rule in PROBES.items()} == SEVERITIES


def test_every_probe_rule_is_a_sensitive_file_probe_with_a_real_description():
    assert all(rule.label == "sensitive_file_probe" for rule in PROBES.values())
    assert all(len(rule.description) > 25 for rule in PROBES.values())


def test_every_probe_rule_has_enough_attack_and_near_miss_examples():
    assert set(ATTACKS) == set(PROBES) == set(NEAR_MISSES)
    for rule_id in PROBES:
        assert len(ATTACKS[rule_id]) >= 4, rule_id
        assert len(NEAR_MISSES[rule_id]) >= 3, rule_id


def test_the_attack_examples_are_not_copied_from_the_sample_data_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert {target for _, target in CASES}.isdisjoint(generator._SENSITIVE_PAYLOADS)


# --- attacks are caught ---------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "name", "target"), VARIANT_CASES)
def test_each_probe_is_caught_by_its_rule_however_it_is_written(rule_id, name, target):
    assert matches(rule_id, target), (name, normalise(target))


@pytest.mark.parametrize(("rule_id", "target"), CASES)
def test_the_rule_fires_through_the_whole_engine_with_its_severity(rule_id, target):
    found = detect_signatures([entry_for("/ok"), entry_for(target)], load_rules())
    ours = [d for d in found if d.rule_id == rule_id]
    assert len(ours) == 1
    assert (ours[0].first_index, ours[0].label) == (1, "sensitive_file_probe")
    assert ours[0].severity is SEVERITIES[rule_id]
    assert ours[0].evidence == f"GET {target} HTTP/1.1"[:200]


def test_the_examples_from_the_issue_have_the_severities_in_the_table():
    expected = {
        "/.env.production": ("probe-env-file", Severity.HIGH),
        "/.git/HEAD": ("probe-vcs-dir", Severity.HIGH),
        "/backup.sql": ("probe-backup-archive", Severity.MEDIUM),
        "/wp-login.php": ("probe-admin-panel", Severity.LOW),
    }
    for target, (rule_id, severity) in expected.items():
        found = detect_signatures([entry_for(target)], load_rules())
        assert any(d.rule_id == rule_id and d.severity is severity for d in found), target


# --- harmless requests are left alone -------------------------------------------------


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_no_probe_rule(target):
    assert probes_fired(target) == []


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_no_rule_at_all(target):
    assert fired(target) == []


@pytest.mark.parametrize(
    ("rule_id", "target"), [(r, t) for r, targets in NEAR_MISSES.items() for t in targets]
)
def test_each_rules_near_misses_do_not_fire_that_rule(rule_id, target):
    assert not matches(rule_id, target)


@pytest.mark.parametrize("target", QUERY_ONLY)
def test_a_probe_word_in_the_query_string_alone_fires_no_probe_rule(target):
    assert probes_fired(target) == []


@pytest.mark.parametrize("target", [t for ts in ATTACKS.values() for t in ts if "?" not in t][:40])
def test_a_probe_hidden_in_the_query_of_another_page_is_not_a_probe(target):
    assert probes_fired("/index.php?file=" + target) == []


def test_there_are_plenty_of_harmless_examples():
    assert len(HARMLESS) + sum(len(v) for v in NEAR_MISSES.values()) >= 60


# --- several rules, one request -------------------------------------------------------


def test_a_backed_up_config_file_fires_both_the_secret_and_the_backup_rule():
    assert probes_fired("/wp-config.php.bak") == ["probe-backup-archive", "probe-secret-file"]


def test_a_traversal_that_names_a_probe_file_in_the_query_is_only_a_traversal():
    found = fired("/get?f=../../.env")
    assert "traversal-dotdot" in found
    assert not any(rule_id.startswith("probe-") for rule_id in found)  # the query is not a path


# --- known gaps -----------------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "target"), KNOWN_GAPS)
@pytest.mark.xfail(strict=True, reason="known gap: needs decoding or parsing beyond the spec")
def test_known_gap_is_not_caught_yet(rule_id, target):
    assert matches(rule_id, target)


# --- the labelled sample logs ---------------------------------------------------------


def labels_of(path):
    rows = [json.loads(row) for row in path.read_text().splitlines()]
    return {row["line"] - 1: row["label"] for row in rows}


def test_the_clean_sample_log_raises_nothing_with_every_rule():
    entries = parse_file(ROOT / "data" / "samples" / "clean.log").entries
    assert detect_signatures(entries, load_rules()) == []


def test_the_demo_log_finds_every_labelled_probe_as_a_sensitive_file_probe():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labels_of(ROOT / "data" / "samples" / "demo.labels.jsonl")
    wanted = [line for line, label in labels.items() if label == "sensitive_file_probe"]
    assert len(wanted) >= 3
    found = {
        d.first_index
        for d in detect_signatures(entries, load_rules())
        if d.label == "sensitive_file_probe"
    }
    assert set(wanted) <= found


def test_the_demo_log_flags_no_unlabelled_line_with_the_full_rule_set():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labels_of(ROOT / "data" / "samples" / "demo.labels.jsonl")
    flagged = {d.first_index for d in detect_signatures(entries, load_rules())}
    assert flagged - set(labels) == set()


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6])
def test_generated_logs_find_every_probe_and_flag_no_normal_line(generator, seed):
    lines, labels = generator.generate(seed=seed, lines=3000, attack_ratio=0.1)
    entries = [parse_line(line) for line in lines]
    truth = {item["line"] - 1: item["label"] for item in labels}
    by_line = {}
    for detection in detect_signatures(entries, load_rules()):
        by_line.setdefault(detection.first_index, set()).add(detection.label)
    probes = [line for line, label in truth.items() if label == "sensitive_file_probe"]
    assert probes
    assert [line for line in probes if "sensitive_file_probe" not in by_line.get(line, ())] == []
    assert [line for line in by_line if line not in truth] == []


@pytest.mark.parametrize("seed", range(10))
def test_generated_clean_logs_raise_nothing_with_every_rule(generator, seed):
    lines, _ = generator.generate(seed=seed, lines=2000, attack_ratio=0)
    assert detect_signatures([parse_line(line) for line in lines], load_rules()) == []


def test_a_scanner_burst_also_trips_the_admin_rule_on_its_labelled_lines_which_is_expected(
    generator,
):
    # The scanner class is detected by behaviour (#41). The scanner's paths include
    # /phpmyadmin and /wp-login.php, so these probe detections land on scanner-labelled lines.
    lines, labels = generator.generate(seed=42, lines=3000, attack_ratio=0.2)
    truth = {item["line"] - 1: item["label"] for item in labels}
    entries = [parse_line(line) for line in lines]
    on_scanner = [
        d for d in detect_signatures(entries, load_rules()) if truth.get(d.first_index) == "scanner"
    ]
    assert on_scanner
    assert {d.rule_id for d in on_scanner} <= set(PROBES)
    assert "probe-admin-panel" in {d.rule_id for d in on_scanner}


# --- hostile input --------------------------------------------------------------------

HOSTILE = [
    "/" + "db-" * 680,
    "/" + "a." * 1000,
    "/" * 2040,
    "/" + "x" * 2040,
    "/.env" + ".a" * 500,
    "/" + "backup." * 290,
    "/" + "a.b~" * 500,
    "/." * 1000,
    "/db.bak." * 220,
    "/" + "x.sql" * 400,
    "x" * 2040,
    "/p?" + "/.env" * 400,
    "/" + "a" * 2000 + ".zip",
    "/" + "db" * 1000 + ".zip",
    "/" + "www." * 400,
    "/.git" * 400,
]


@pytest.mark.parametrize("text", HOSTILE, ids=[f"hostile-{n}" for n in range(len(HOSTILE))])
def test_hostile_paths_are_matched_against_every_rule_quickly(text):
    started = time.perf_counter()
    fired(text)
    assert time.perf_counter() - started < 0.25
