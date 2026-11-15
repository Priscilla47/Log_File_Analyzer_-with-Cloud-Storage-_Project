# Checking the dashboard in a real browser

The dashboard's tests run the page without a browser: a fake Streamlit that records every call, and Streamlit's own test helper that runs the page headless and exposes what it would draw. Neither shows what a person sees. This page records the check made in a real browser, what it found, and how to repeat it.

## What was checked

- **Date:** 15 November 2026. **Browser:** Google Chrome 148 (Linux), driven by Playwright. **Streamlit:** 1.66.1, Python 3.12.
- **How:** `loginsight dashboard --port 23901` was started, and a script opened it, chose a file, looked at every section, changed the traffic period, opened a filter and chose an address. Screens were taken in a light and a dark theme, at 1400 pixels wide and at a phone width of 420 pixels.
- **Files:** `data/samples/demo.log` (500 requests, 34 detections), `data/samples/clean.log` (no detections), a log with a real escape character, a NUL and spreadsheet-formula-looking text in it, a text file that is not a log, an empty file, and a log dated 1970.

## Results

| Section | Result |
| --- | --- |
| Empty page, upload | works; the message to choose a file shows |
| Headline numbers | correct and equal to the command line's |
| Status chart | bars in the colour-blind-safe blue, labelled axes |
| Paths chart | sideways bars, busiest first, labels readable |
| Detections table | severity as a coloured square and a word, filters present, rows readable, evidence shown as text (the escape character and the formula-looking text appear as plain text) |
| One address | the numbers, the two small tables and the address's detections |
| A text file | one error message, no charts |
| An empty file | the "no requests" message |
| A clean log | "No attacks were detected" and no filters |
| Dark theme and a phone width | readable; the table scrolls sideways at the phone width |
| Errors | no Streamlit exception on any page; the browser console had warnings from the chart library only (see the first problem) |

## Problems found, and what was done

1. **The traffic chart was empty for the demo log.** It was grouped by the hour, the log covers ten minutes, so there was one point and a line through one point draws nothing (the console said `Infinite extent for field "Time (UTC)"`). No test could see this. **Fixed twice:** the period now starts from the length of the log (minutes up to 3 hours, hours up to 3 days, days beyond), and a log with one period only is drawn as bars with a note.
2. **"First seen" and "Last seen" were cut off** (`2026-01-01 00:09:...`), because a full date and time does not fit a number card. **Fixed:** they are now two lines of text under the numbers.
3. **Not fixed, cosmetic:** the labels at the two ends of the time-range slider (`2026-01-01 00:00:06`) stick out a little over the margin of the page at both ends. They belong to Streamlit's slider; shortening the format would not remove it.
4. **Not fixed, known:** with many detections the table scrolls inside its box, as a table of that height does in Streamlit, and the table can be downloaded as CSV from its toolbar (cells that look like formulas are quoted for that reason).

## Repeating it

```bash
pip install playwright           # and use the Chrome that is installed: channel="chrome"
loginsight dashboard --port 23901 &
```

then drive `http://127.0.0.1:23901` with a script that sets the file input (`page.set_input_files("input[type=file]", "data/samples/demo.log")`), waits for the text `Responses by status class`, and reads `[data-testid=stException]` (there should be none) and `[data-testid=stVegaLiteChart]` (three charts). The check is not part of the automated tests: it needs a browser and a display driver, which the tests do not assume.
