# LogInsight

A web server access-log analyzer. Point it at an Apache or Nginx access log in the Common or Combined format and it tells you how much traffic you had, what failed, and who is behaving suspiciously.

> **Status:** early development. Parsing, analysis, attack detection, reports and the command line work. The web dashboard and cloud storage are still to come.

## What it does

- **Parse** the Common and Combined log formats, which are the default access-log formats of Apache and Nginx, without choking on malformed lines. Dedicated Nginx support and format auto-detection are planned.
- **Analyse** traffic: totals, top IPs and paths, status codes, data volume, traffic over time.
- **Detect attacks** with readable rules: SQL injection, XSS, path traversal, command injection, probes for sensitive files, brute-force logins and scanning. Each detection comes with a severity and the evidence that triggered it.
- **Two interfaces** over one core library: a command-line tool (ready) and a web dashboard (planned).
- **Pluggable storage** (planned): local files first, cloud storage later.

## Why

I started this while learning about cloud and log analysis and never finished it. This repository is the finished version, built step by step in the open.

## Quick start

```bash
pip install -e .
loginsight analyze data/samples/demo.log
loginsight detect data/samples/demo.log --min-severity high
```

Add `--output reports/demo` to write `report.json`, `report.md` and charts instead of printing. The [usage guide](docs/USAGE.md) lists every option, the output formats and the exit codes.

## Development setup

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the tests and the linter:

```bash
pytest          # fast tests
pytest -m slow  # long-running checks
ruff check .    # lint
```

Optionally, run the same checks automatically before every commit:

```bash
pre-commit install            # once per clone
pre-commit run --all-files    # run on everything now
```

## Roadmap

1. Project structure and documentation: done
2. Log parsing and statistics: done
3. Attack detection: done
4. Command-line tool: done
5. Web dashboard
6. Cloud storage backends

## Project layout

The layout and the reasoning behind it are in the `docs/` folder:

- [Goals](docs/GOALS.md): what the project is for, and what it is not
- [Usage](docs/USAGE.md): install, commands, output formats, how to read a detection
- [Architecture](docs/ARCHITECTURE.md): how it is built, the rules file, the report format
- [Project structure](docs/STRUCTURE.md): how the folders are organised and why

## License

Released under the [MIT License](LICENSE).
