# Sample data

Every file here is **synthetic**. None of it comes from a real server: there are no real
visitors, no real addresses and no personal data. All client addresses are taken from the
ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
`2001:db8::/32`).

| File | What it is |
| --- | --- |
| `access_sample.log` | Five hand-written lines in Combined format. Used by the parser tests. |
| `demo.log` | 500 generated lines, about 10% of them attacks. |
| `demo.labels.jsonl` | Ground truth for `demo.log`: which lines are attacks, and which kind. |
| `clean.log` | 300 generated lines with no attacks, to check that nothing is flagged by mistake. |

## How they were made

The files are produced by [`scripts/generate_logs.py`](../../scripts/generate_logs.py). The
output depends only on the arguments, so the commands below regenerate the files **byte for
byte**. Run them from the repository root:

```
python scripts/generate_logs.py --seed 42 --lines 500 --attack-ratio 0.1 --start 2026-01-01T00:00:00Z --output data/samples/demo.log --labels data/samples/demo.labels.jsonl
python scripts/generate_logs.py --seed 7 --lines 300 --attack-ratio 0 --start 2026-01-01T00:00:00Z --output data/samples/clean.log
```

A test regenerates both files and compares them with the committed ones, so a change to the
generator that is not followed by regenerating the samples is caught.

## Labels format

`demo.labels.jsonl` is JSON Lines: one object per attack line. Lines that are not listed are
normal traffic.

```json
{"line": 19, "label": "path_traversal", "kind": "signature", "ip": "203.0.113.61"}
```

| Field | Meaning |
| --- | --- |
| `line` | 1-based line number in the log file |
| `label` | `sql_injection`, `xss`, `path_traversal`, `command_injection`, `sensitive_file_probe`, `brute_force` or `scanner` |
| `kind` | `signature` for a single attack line, `behavioural` for a burst of lines from one address |
| `ip` | the address that sent the line |

With 500 lines and a 10% attack ratio there is room for the five single-line attacks and one
brute-force burst, but not for a scanner burst, which needs about 40 lines. Larger logs
contain every class.

The logs also contain harmless requests that look a little suspicious, such as
`/search?q=select+shoes`. They are deliberately not labelled, so detection rules can be
checked for false alarms.
