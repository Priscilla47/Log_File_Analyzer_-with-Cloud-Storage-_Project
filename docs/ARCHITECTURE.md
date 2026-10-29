# Architecture

This describes LogInsight as it is built today. Parts that do not exist yet (storage and the dashboard) are marked **planned**. For how to run the tool see [USAGE.md](USAGE.md); for how the folders are organised see [STRUCTURE.md](STRUCTURE.md).

## Overview

Data flows in one direction, from a raw log file to a report:

```
 log file ──► parsing ──► log entries ──┬──► analysis  ──► statistics ──┐
                                        │                               ├──► reporting ──► files / text
                                        └──► detection ──► detections ──┘
```

The command line drives this pipeline and contains no analysis logic of its own. The dashboard (**planned**) will drive the same pipeline. File access will go through a storage layer (**planned**); until it exists, the command line reads the log and writes the report files directly, and that is the one place that does.

## Components

All modules are in `src/loginsight/`.

### Parsing (`parsing/`)
- `parser.py` reads Common and Combined log formats: `parse_line`, and `parse_file` which returns a `ParseResult`. It is deliberately tolerant: a line it cannot read is skipped and counted, never fatal, because real logs are messy. Lines are limited to 8192 characters, a missing time zone is taken as UTC, and a byte order mark and invalid bytes do not stop a read.
- `models.py` defines `LogEntry` (IP, time, method, path, query, protocol, status, size, referer, user agent, raw request), `ParseStats` (lines read, parsed and skipped, by reason, and the first few problems) and `ParseResult`.

### Analysis (`analysis/`)
Pure functions that take log entries and return statistics. They do no file or network access, which makes them easy to test with small, known inputs.
- `summary.py`: `summarize` gives totals, unique IPs, top IPs and paths, status classes and codes, methods, bytes and the error rate.
- `timeseries.py`: `requests_per_bucket` (requests and errors per minute or hour, gaps included) and `busiest_window`.
- `analyzer.py`: `analyze_entries`, a pandas variant that returns a table with one row per entry together with basic statistics.

### Detection (`detection/`)
Classifies suspicious activity with explainable rules. There are two kinds:

- **Signature rules** (`signatures.py`) match known attack patterns in the request path and query string: SQL injection, cross-site scripting, path traversal, command injection and probes for sensitive files such as `/.env`.
- **Behavioural rules** (`behaviour.py`) look across requests from one IP address over a time window: many failed logins are brute force, and many different missing pages, or a known scanning tool in the user agent, are scanning.

`models.py` defines `Detection` (rule, label, severity, address, time, position, count, evidence), `Severity` and `SignatureRule`. `ruleset.py` loads and checks the rules file. `pipeline.py` has `detect()`, the one function the rest of the code calls.

Every detection says which rule matched and quotes its evidence, so a result can always be explained and checked.

#### The rules file
Rules are data in `detection/rules/default.toml`, not code. There are 23 signature rules (6 SQL injection, 5 XSS, 3 path traversal, 3 command injection, 6 sensitive-file probes) and the settings of the two behavioural rules. A signature rule looks like this:

```toml
[[signature]]
id = "probe-env-file"
label = "sensitive_file_probe"
severity = "high"
description = "..."
pattern = '''regular expression'''
```

The loader checks every rule (known label, known severity, a pattern that compiles and is under 500 characters, unique ids) and reports all problems together, naming the rule. To add a rule, add an entry and a case in `tests/detection/rule_cases.toml` (requests it must match and requests it must leave alone); a test fails if a rule has no case.

Before a pattern is matched, the path and query are **normalised**: cut to 2048 characters, percent-decoding removed up to three times, `+` turned into a space, NUL characters removed, whitespace collapsed and everything lower-cased. This defeats the usual disguises (`%2e%2e%2f`, double encoding, odd spacing). Known gaps, such as overlong UTF-8 and `%u` escapes, are listed in `signatures.py` and pinned as expected failures in the tests.

#### De-duplication
A request can match several rules (`UNION SELECT` inside a `<script>` tag, for example). `detect()` keeps **one detection per request**: the most serious rule wins, ties go to the rule that comes first in the rules file, and the others are named in `also_matched`. Behavioural detections describe an address over time, so they are never merged with a signature detection, even on the same line. The result is sorted by severity (highest first), then position, then rule id, so the same input always gives the same output.

#### Measuring quality
`tests/detection/benchmark.py` scores the detections against the labels the sample generator writes, as **recall** (how many labelled attacks were found) and **precision** (how many detections were real) for each of the seven attack classes. Signature classes are scored per line, behavioural ones per burst. The tests require at least 0.95 for both on several generated logs and on the demo log, and require that clean logs raise nothing. The measured score is currently 1.000 for every class.

That number comes from synthetic logs made by a simple generator. It shows that the rules do what they were written to do and that nothing has regressed. It is **not** a promise about real traffic. The benchmark also cannot see rules the generator never exercises (9 of the 23); those are covered by the per-rule cases.

### Reporting (`reporting/`)
- `report.py`: `build_report` gathers statistics, traffic over time and detections into a `Report`; `render_json` and `render_markdown` turn it into text. It is pure: no file access, no clock, no absolute paths, so the same log always gives byte-identical output. Text taken from the log is escaped in Markdown so it cannot break a table or add formatting.
- `writers.py`: `write_report` writes `report.json`, `report.md` and the charts into a folder, through temporary files so a failure never leaves half a report.
- `charts.py`: the three PNG charts (status classes, traffic, top paths), drawn with matplotlib's object API so there is no global state.
- `text.py`: the plain-text views the command line prints. Control characters from the log are shown as visible escapes so a log line cannot send commands to a terminal.

The JSON layout is `tool`, `source` (name and parse statistics), `summary`, `traffic` (bucket size and buckets) and `detections`, in that order.

### Interfaces
- **CLI (`cli.py`, `__main__.py`):** `loginsight analyze` and `loginsight detect`, with a choice of output format. Exit code 0 is success, 1 a problem with a file, 2 wrong usage.
- **Dashboard (`dashboard/`), planned:** a web interface to explore the same results interactively, with filters and per-IP detail.

### Storage (`storage/`), planned
A small interface for reading and writing files (read, write, list, exists). The first implementation will use the local file system. Cloud backends are added later by implementing the same interface, with no change to the rest of the code. The package exists but is empty.

## Design decisions

- **Rule-based detection, not machine learning.** Rules are readable, testable, need no training data, and every alert can be explained. Statistical anomaly detection may be added later as an optional extra.
- **A pure core.** Parsing, analysis, detection and report building take data in and return data out. Only the writers and the command line touch the outside world.
- **Storage behind an interface (planned).** The tool works on local files today, and cloud storage becomes a new backend instead of a rewrite.
- **Tolerant parsing.** Bad lines are counted and reported, so one corrupt line never stops an analysis.
- **Reproducible output.** Reports hold no timestamps of their own, so they can be compared byte for byte.
- **Synthetic sample data.** Demos and tests use generated logs with known attacks, which also lets detection quality be measured as precision and recall.

## Testing strategy

- Unit tests for each package, with one positive and one negative case for every detection rule.
- Labelled synthetic logs act as ground truth for measuring detection quality.
- Mutation checks, run on a throw-away copy of the project, were used to find tests that would not notice a deliberate bug.
- Golden files fix the exact JSON and Markdown output for a tiny log.
- An end-to-end test runs the real command on the sample logs and checks the files it writes.
- A test runs every command written in the usage guide, and another checks that the links in the documentation work.
