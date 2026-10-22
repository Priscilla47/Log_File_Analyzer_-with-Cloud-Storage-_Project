# Architecture

This is the planned architecture of LogInsight. It will be updated to match the code as each part is built. For how the folders are organised, see [STRUCTURE.md](STRUCTURE.md).

## Overview

Data flows in one direction, from a raw log file to a report:

```
 log file
    │
    ▼
 storage ──► parsing ──► log entries ──┬──► analysis  ──► statistics ──┐
                                       │                               ├──► reporting ──► storage
                                       └──► detection ──► detections ──┘
```

The command-line tool and the dashboard both drive this same pipeline. Neither contains any analysis logic of its own.

## Components

### Parsing
Reads Common and Combined log formats (Nginx support is planned). The parser is deliberately tolerant: a line it cannot read is skipped and counted, never fatal, because real logs are messy. Each good line becomes a `LogEntry` holding the IP, timestamp, method, path, query string, status, size, referer and user agent. The result also includes parse statistics (how many lines were read and how many were skipped).

### Analysis
Pure functions that take log entries and return statistics: totals, unique IPs, top IPs and paths, status-code classes, data volume, and traffic over time. They do no file or network access, which makes them easy to test with small, known inputs.

### Detection
Classifies suspicious activity with explainable rules. There are two kinds:

- **Signature rules** match known attack patterns in the request path and query string (SQL injection, XSS, path traversal, command injection, probes for sensitive files such as `/.env`).
- **Behavioural rules** look across requests from the same IP over a time window (many failed logins suggest brute force, many distinct 404s suggest scanning).

Every detection contains a label, a severity, the rule that matched, and the evidence line, so a result can always be explained and checked. Rules are stored as data rather than code, so adding one means adding an entry and a test case.

### Storage
A small interface for reading and writing files (read, write, list, exists). The first implementation uses the local file system. Cloud backends are added later by implementing the same interface, with no change to the rest of the code.

### Reporting
Turns statistics and detections into outputs: JSON for machines, Markdown for people, and PNG charts.

### Interfaces
- **CLI:** commands to analyse a log and list detections, with choice of output format.
- **Dashboard:** a web interface to explore the same results interactively, with filters and per-IP detail.

## Design decisions

- **Rule-based detection, not machine learning.** Rules are readable, testable, need no training data, and every alert can be explained. Statistical anomaly detection may be added later as an optional extra.
- **A pure core.** Analysis and detection take data in and return data out. Only storage touches the outside world.
- **Storage behind an interface.** The tool works on local files today, and cloud storage becomes a new backend instead of a rewrite.
- **Tolerant parsing.** Bad lines are counted and reported, so one corrupt line never stops an analysis.
- **Synthetic sample data.** Demos and tests use generated logs with known attacks, which also lets detection quality be measured as precision and recall.

## Testing strategy

- Unit tests for each package, with one positive and one negative case for every detection rule.
- Labelled synthetic logs act as ground truth for measuring detection quality.
- An end-to-end test runs a sample log through the command-line tool and checks the report files.
