# Goals

LogInsight analyses web server access logs (Apache and Nginx) and tells you what happened: how much traffic you had, what failed, and who is behaving suspiciously.

This page says what the project is for, and just as important, what it is not. For the design see [ARCHITECTURE.md](ARCHITECTURE.md), and for the folder layout see [STRUCTURE.md](STRUCTURE.md).

> **Status:** early development. This describes where the project is going. The [README](../README.md) shows what exists today.

## What it does

- **Parses logs tolerantly.** It reads the Common and Combined log formats. A line it cannot read is counted and reported, never fatal, because real logs are messy.
- **Computes traffic statistics.** Totals, top IPs and paths, status codes, data volume and traffic over time.
- **Classifies attacks with explainable rules.** SQL injection, XSS, path traversal, command injection, probes for sensitive files, brute-force logins and scanning. Every detection carries a label, a severity, the rule that matched and the evidence line.
- **Offers two interfaces over one core.** A command-line tool and a web dashboard, both driving the same library.
- **Keeps storage pluggable.** The same analysis runs on local files first, and cloud storage comes later as another backend.

## What it is not (version 1)

- **Not a real-time tool.** It analyses files you give it. It does not tail or stream live logs.
- **Not a SIEM, an IDS or a WAF.** It reports on past traffic. It does not collect logs from many machines, correlate across systems, or block anything.
- **Not a general log analyser.** It handles web server access logs only, not application, system or error logs.

## Principles

- **Explainable over clever.** Detection is rule-based, so you can read a rule, test it and extend it, and every alert can be traced to the line that caused it.
- **One core, many interfaces.** The command line and the dashboard hold no analysis logic. They collect input and show results, so both always give the same answers.
- **Honest numbers.** Detection quality is measured against labelled synthetic logs, where the attacks are known, and reported as precision and recall.
- **Safe by default.** Sample data is synthetic and contains no real addresses. Nothing is sent anywhere unless you configure a cloud storage backend yourself.

## Roadmap

The README lists the same steps:

1. Project structure and documentation
2. Log parsing and statistics
3. Attack detection
4. Command-line tool
5. Web dashboard
6. Cloud storage backends

Statistical anomaly detection may follow as an optional extra, as described in [ARCHITECTURE.md](ARCHITECTURE.md). It would add to the rules and never replace them.
