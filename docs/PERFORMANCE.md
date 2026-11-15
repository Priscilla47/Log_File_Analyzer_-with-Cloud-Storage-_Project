# How big a log the dashboard takes

The dashboard reads the whole uploaded file into memory, so it has a limit: **50 MB**, counted the way Streamlit counts, in decimal megabytes (50,000,000 bytes). A bigger log is for the command line. This page records what a log at the limit costs, and how that was found.

## The limit is in decimal megabytes

Streamlit's `--server.maxUploadSize` is in megabytes of 1,000,000 bytes. The dashboard used to count 50 × 1024 × 1024 bytes, which is 52.4 MB. A real upload of a 52.1 MB log showed Streamlit's own red error on the uploader, so our message about the limit was never reached, and the page stated a limit it did not keep. The limit is now `50 * 1,000,000` bytes in `dashboard/data.py`, sizes in the messages are written in the same unit (rounded up, so a file over the limit never reads as "50.0 MB"), and a test pins both.

## What a log at the limit costs

- **Log:** 49,839,576 bytes (just under the limit), 237,000 requests, 4,553 detections from 408 addresses. Made with `scripts/generate_logs.py --seed 7 --lines 237000 --attack-ratio 0.05`.
- **Machine:** Intel Core i7-1255U laptop (12 threads), 32 GB, Linux; Python 3.12.3, Streamlit 1.66.1, Google Chrome 148 driven by Playwright, the dashboard started with `loginsight dashboard`. One user, nothing else heavy running.

| What | Result |
| --- | --- |
| Reading the log (`data.read_upload`, in a Python process) | 12.8 s of CPU, the same on three runs |
| Memory of that process (peak) | about 470 MB |
| Memory of the Streamlit server with the log shown | about 400 MB |
| Choose the file, until the page is complete (Chrome) | 19.6 s and 20.5 s on two cold runs; 1.8 s when the same file was already read (Streamlit keeps the reading) |
| Changing the traffic period, until the page is idle | 0.2 to 0.3 s |
| Changing a severity filter, until the page is idle | 0.16 to 1.5 s on four runs; a first run measured 7.7 s once and it did not repeat in the three runs after it |
| Building the report for a period the first time | about 1 s; then 0 |

So a log at the limit takes about twenty seconds to appear on this machine and is then quick to work with; the file is read once, and each click afterwards only filters what was read. The memory is about eight times the size of the file, which is why the limit exists: ten people each uploading 50 MB would need about 4 GB.

## Repeating it

1. Make a log: `python scripts/generate_logs.py --seed 7 --lines 237000 --attack-ratio 0.05 --output big.log`.
2. Check its size is under 50,000,000 bytes (`ls -l big.log`).
3. Start `loginsight dashboard`, choose the file, and time it with the browser's developer tools or a script (see [BROWSER_CHECK.md](BROWSER_CHECK.md) for how the browser was driven).
4. For the reading alone, time `loginsight.dashboard.data.read_upload(raw, "big.log", limit=data.UPLOAD_LIMIT_BYTES)` in a Python process.

The command line does not have this limit; reading a big file there is the next piece of work (issue #84).
