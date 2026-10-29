# Log report: tiny.log

## Summary

- Lines read: 5 (4 parsed, 1 skipped)
- Requests: 4
- Unique IP addresses: 2
- Data sent: 2.4 KiB
- Error rate (4xx and 5xx): 50.0%
- First request: 2026-10-10T10:00:01+00:00
- Last request: 2026-10-10T11:05:40+00:00

**Top IP addresses**

| IP | Requests |
| --- | --- |
| 198.51.100.7 | 2 |
| 203.0.113.5 | 2 |

**Top paths**

| Path | Requests |
| --- | --- |
| /about | 1 |
| /index.html | 1 |
| /missing | 1 |
| /search | 1 |

## Status codes

| Class | Requests |
| --- | --- |
| 1xx | 0 |
| 2xx | 2 |
| 3xx | 0 |
| 4xx | 1 |
| 5xx | 1 |
| other | 0 |

| Code | Requests |
| --- | --- |
| 200 | 2 |
| 404 | 1 |
| 500 | 1 |

## Traffic

Requests per hour, over 2 periods. The busiest started at 2026-10-10T10:00:00+00:00 with 2 requests.

| Start (UTC) | Requests | Errors |
| --- | --- | --- |
| 2026-10-10T10:00:00+00:00 | 2 | 0 |
| 2026-10-10T11:00:00+00:00 | 2 | 2 |

## Detections

| Severity | Rule | IP | Time | Count | Evidence |
| --- | --- | --- | --- | --- | --- |
| high | sqli-union-select | 198.51.100.7 | 2026-10-10T11:05:30+00:00 | 1 | GET /search?q=1'+UNION+SELECT+password+FROM+users-- HTTP/1.1 |

## Parse problems

1 of 5 lines could not be read (no_match: 1).

| Line | Reason | Text |
| --- | --- | --- |
| 5 | no\_match | this line is not a log line |
