# Project structure

This document explains how the repository is laid out and why. Parsing, analysis, detection, reporting and the command line are built; `storage/` and `dashboard/` are empty packages waiting for their turn (see the roadmap in the README).

```
.
├── src/loginsight/
│   ├── parsing/       turns raw log lines into structured entries
│   ├── analysis/      computes statistics from entries
│   ├── detection/     classifies attacks with rules (the rules are in detection/rules/)
│   ├── storage/       reads and writes files (local now, cloud later): not built yet
│   ├── reporting/     builds the report and writes JSON, Markdown, text and charts
│   ├── dashboard/     the web interface: not built yet
│   ├── cli.py         the command-line interface
│   └── __main__.py    makes `python -m loginsight` work
├── tests/             automated tests, in folders that mirror the packages
├── data/samples/      small synthetic logs for demos and tests
├── scripts/           helper scripts (not part of the installed package)
├── docs/              documentation
└── README.md
```

## Why it is organised this way

### A `src/` layout
The package lives in `src/loginsight/` instead of at the repository root. This forces tests and scripts to use the *installed* package, the way a real user would, and avoids the classic bug where code works from the project folder but breaks once installed.

### One package per responsibility
Each folder has a single job and a clear input and output:

| Package | Input | Output |
|---|---|---|
| `parsing` | raw text lines | `LogEntry` objects plus parse statistics |
| `analysis` | log entries | statistics (totals, top IPs, traffic over time) |
| `detection` | log entries | detections (label, severity, rule, evidence) |
| `storage` | a path or key | file contents, or a written file |
| `reporting` | statistics and detections | JSON, Markdown, text, PNG |

Keeping them separate means each can be understood, tested and changed on its own. For example, adding a new attack rule touches only `detection`.

### The command line and the dashboard are thin
`cli.py` and (later) `dashboard/` contain no analysis logic. They only collect input, call the other packages, and show the result. That way both interfaces always give the same answers, and the logic that matters is tested once, in the core.

### Storage is its own package
Anything that touches files or, later, cloud buckets is meant to go through `storage/`. The package is still empty, so for now the command line reads the log and `reporting/writers.py` writes the report files directly; both will be switched to `storage/` when it exists. The rest of the code never opens a file. This is what makes it possible to add cloud storage later without rewriting the analysis, and it lets tests run entirely offline.

### Sample data is synthetic
`data/samples/` holds small generated logs, with no real IP addresses or personal data. This keeps the repository safe to publish and gives the tests known, reproducible inputs.

### Scripts are separate from the package
Helper scripts, such as the one that generates sample logs, live in `scripts/`. They are tools for developing the project, not part of what gets installed.

### Tests mirror the package
`tests/` follows the same structure as `src/loginsight/`, so it is always obvious where the tests for a given module are. Tests that cross packages sit at the top: `test_cli.py` for the command line, `test_end_to_end.py` for the whole path from a log file to the report files, and `test_docs.py` for the documentation.
