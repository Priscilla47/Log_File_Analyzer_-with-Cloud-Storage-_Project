# Cloud storage (Amazon S3)

LogInsight can read a log from, and write its report to, an Amazon S3 bucket instead of the local disk. This page shows how to turn it on, how to give it credentials without putting any in the repository, and what it needs permission to do. The same works with any service that speaks the S3 API (set `AWS_ENDPOINT_URL`).

## Install

S3 support needs the optional `boto3` package, so the base install stays small:

```bash
pip install -e ".[s3]"
```

Without it, a command that names an `s3://` location stops with one line that says how to install it. Local files never need it.

## Use it

Anywhere a command takes a log file, `--rules` file or `--output` folder, an `s3://bucket/path` location works:

```
loginsight detect s3://my-logs/2026/11/access.log
loginsight analyze s3://my-logs/2026/11/access.log --output s3://my-reports/2026-11-15
loginsight analyze /var/log/nginx/access.log --output s3://my-reports/today
```

- A **log** location names one object: `s3://bucket/key`. A bucket alone is refused.
- An **output** location is a "folder": `s3://bucket` or `s3://bucket/prefix`. The files (`report.json`, `report.md` and `charts/...`) are written below it and their full `s3://` locations are printed, so they can be given back to another command.
- The report names the object by its last part only (`access.log`), never the bucket or the folders.
- A missing bucket, a missing object, a refused request or a network problem gives **one line** on standard error and exit code 1, with no traceback. Nothing is printed or half-written.

From Python:

```python
from loginsight.storage import S3Storage

storage = S3Storage("my-logs", prefix="2026/11")  # keys are below the prefix
text = storage.read_text("access.log")
storage.write_bytes("report.json", b"{}")
```

An `S3Storage` follows the same promises as `LocalStorage` (the tests run one shared contract against both): the same key rules (no leading `/`, no `.` or `..`), reading (`read_text`, or `open_text` a line at a time) drops a byte order mark and replaces invalid bytes, a write replaces the whole object in one request so a reader never sees half of it, and `list` returns sorted keys.

## Credentials

LogInsight never asks for, stores or prints a credential. boto3 finds them the standard way, in this order:

1. environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN` for temporary ones);
2. a named profile in `~/.aws/credentials`: `AWS_PROFILE=reports loginsight ...`;
3. the role of the machine or container it runs on (the best choice on a server: there is no key to leak).

Set `AWS_DEFAULT_REGION` (or `AWS_REGION`) if your bucket is not in the region your profile names. Keep keys out of the repository, out of shell history (use a profile, not `export` on the command line) and out of CI logs.

## Permissions

Give the user or role the least it needs, for only the buckets involved:

| To | Needs |
| --- | --- |
| read a log | `s3:GetObject` on `arn:aws:s3:::my-logs/*` |
| write a report | `s3:PutObject` on `arn:aws:s3:::my-reports/*` |
| `S3Storage.list` and `exists` from Python | `s3:ListBucket` on `arn:aws:s3:::my-logs` |

Logs often hold addresses and other people's requests: keep the buckets private, turn on the bucket's default encryption, and do not make the report bucket public.

## Trying it without an account

The tests use [moto](https://github.com/getmoto/moto), which pretends to be S3 inside the test run, so `pytest` needs no account and never touches the network (the tests also set fake credentials so a real one can never be picked up by accident). To try the commands for real without AWS, run any S3-compatible server locally and point `AWS_ENDPOINT_URL` at it.

## What is not covered

Other providers (Google Cloud Storage, Azure Blob Storage), presigned URLs, and multipart upload of very large reports: a report is small and goes in one request. A log is read as a stream, a line at a time, so it does not have to fit in memory as one text (the parsed requests do; see [PERFORMANCE.md](PERFORMANCE.md)). Reading it twice, once to find its format and once to parse it, costs two requests, and the first stops early.
