# LogInsight

A web server access-log analyzer. Point it at an Apache or Nginx log and it tells you how much traffic you had, what failed, and who is behaving suspiciously.

> **Status:** early development. The project is being rebuilt from an earlier prototype, so most of what is described below is planned, not finished yet.

## What it is meant to do

- **Parse** Common and Combined log formats without choking on malformed lines.
- **Analyse** traffic: totals, top IPs and paths, status codes, data volume, traffic over time.
- **Detect attacks** with readable rules: SQL injection, XSS, path traversal, command injection, probes for sensitive files, brute-force logins and scanning. Each detection comes with a severity and the evidence that triggered it.
- **Two interfaces** over one core library: a command-line tool and a web dashboard.
- **Pluggable storage:** local files first, cloud storage later.

## Why

I started this while learning about cloud and log analysis and never finished it. This repository is the finished version, built step by step in the open.

## Roadmap

1. Project structure and documentation
2. Log parsing and statistics
3. Attack detection
4. Command-line tool
5. Web dashboard
6. Cloud storage backends

## Project layout

The layout and the reasoning behind it will be documented in `docs/`.
