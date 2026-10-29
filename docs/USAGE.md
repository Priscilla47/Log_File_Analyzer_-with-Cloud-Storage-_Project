# Using LogInsight

LogInsight reads an Apache or Nginx access log (Common or Combined format) and tells you how much traffic you had and which requests look like attacks. This page shows how to install it and run it. For how it works inside, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

You need Python 3.10 or newer. From a clone of the repository:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `loginsight` command. Check it:

```
$ loginsight --version
```

The repository comes with a small synthetic log, `data/samples/demo.log`, so you can try everything without a real server. All the commands on this page use it.

## The two commands

```
loginsight analyze FILE [--format text|json|md] [--output DIR] [--top N] [--bucket minute|hour]
loginsight detect  FILE [--format text|json|md] [--output DIR] [--min-severity low|medium|high|critical]
```

`python -m loginsight ...` does the same as `loginsight ...`.

### analyze: what happened

`analyze` shows how many requests there were, from how many addresses, the share of errors, the most requested paths and busiest addresses, and the traffic over time.

```
$ loginsight analyze data/samples/demo.log
```

- `--top N` sets how many top addresses and paths are listed (default 10, at least 1).
- `--bucket minute|hour` sets the size of the traffic periods (default `hour`).

```
$ loginsight analyze data/samples/demo.log --top 5 --bucket minute
```

### detect: what looks like an attack

`detect` lists every detection, most serious first.

```
$ loginsight detect data/samples/demo.log
```

`--min-severity` hides detections below a level. This shows only `high` and `critical` ones:

```
$ loginsight detect data/samples/demo.log --min-severity high
```

Finding attacks is not an error: the command exits with 0 whether or not it found any.

## Output formats

`--format` chooses what is printed:

| Format | What you get |
| --- | --- |
| `text` (default) | a readable summary for the terminal |
| `json` | the full report as JSON, for other programs |
| `md` | the full report as Markdown, for people |

```
$ loginsight detect data/samples/demo.log --format json
$ loginsight analyze data/samples/demo.log --format md
```

The JSON and Markdown reports hold the same information whichever command made them. Only the text view differs: `analyze` shows the statistics, `detect` shows the detections.

### Saving the report

With `--output DIR` nothing is printed except the paths of the files written to `DIR` (created if it does not exist):

```
$ loginsight detect data/samples/demo.log --output reports/demo
```

| File | Content |
| --- | --- |
| `report.json` | everything, as JSON |
| `report.md` | everything, as Markdown, linking the charts |
| `charts/status.png` | responses by status class |
| `charts/traffic.png` | requests and errors over time |
| `charts/top_paths.png` | the most requested paths |

The same log always gives byte-identical files: they hold no creation time and no folder names, only the name of the log file.

## Exit codes and messages

| Code | Meaning |
| --- | --- |
| 0 | success, including a log with no requests and a log with attacks in it |
| 1 | a problem with a file: it is missing, unreadable or a directory, or the output folder cannot be written. One line on standard error, no traceback |
| 2 | wrong usage, such as an unknown option or `--top 0` |

Lines that cannot be read are skipped and counted, and the counts are always shown. If more than 10 percent of the lines were skipped, a warning is printed on standard error, so it never ends up inside JSON output.

## Reading a detection

Each detection answers: what, how bad, who, when and why.

| Field | Meaning |
| --- | --- |
| `label` | the kind of attack: `sql_injection`, `xss`, `path_traversal`, `command_injection`, `sensitive_file_probe`, `brute_force` or `scanner` |
| `severity` | `low`, `medium`, `high` or `critical` |
| `rule_id` | the rule that matched, for example `sqli-union-select`; rules are in `src/loginsight/detection/rules/default.toml` |
| `ip` | the address that sent the request |
| `time` | when the request, or the first request of a burst, was made |
| `count` | how many log lines are involved: 1 for a single request, more for a burst from one address |
| `evidence` | the request line, or a sentence such as "12 failed logins in 94 s" |
| `also_matched` | other rules that matched the same request (only the most serious is listed as the detection) |

A detection means a request matched a rule, not that an attack succeeded. Check the status code of the request in your log: a `404` or `403` answer to a probe usually means it failed.

The rules look at the path and query string of a request only, after undoing URL encoding. They do not look at request bodies, headers or cookies, which an access log does not hold.

## Making your own sample data

`scripts/generate_logs.py` makes a synthetic log and a file saying which lines are attacks. The same arguments always give the same files:

```bash
python scripts/generate_logs.py --seed 1 --lines 2000 --attack-ratio 0.05 --output my.log --labels my.labels.jsonl
```

All addresses come from ranges reserved for documentation, so the logs hold no real data. See [`data/samples/README.md`](../data/samples/README.md) for the arguments and the format of the labels file.

## Changing the rules

Rules are data. To change them, copy `src/loginsight/detection/rules/default.toml`, edit the copy and load it from Python:

```python
from loginsight.detection import detect, load_rules
from loginsight.parsing.parser import parse_file

rules = load_rules("my_rules.toml")
detections = detect(parse_file("data/samples/demo.log").entries, rules)
```

The file explains every field at the top. A mistake in a rule file is reported with the rule's name, for example an unknown label or a pattern that is not a valid regular expression. The command line does not take a rules file yet.
