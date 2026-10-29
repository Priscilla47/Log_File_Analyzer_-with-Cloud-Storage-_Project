"""Write a :class:`Report` to a folder as JSON, Markdown and PNG charts."""

import os
import uuid
from collections.abc import Iterable
from pathlib import Path

from loginsight.reporting.charts import plot_status_codes, plot_top_paths, plot_traffic
from loginsight.reporting.report import CHART_FILES, Report, render_json, render_markdown

FORMATS = ("json", "md", "charts")


def _write_text(path: Path, text: str) -> Path:
    """Write ``text`` as UTF-8 with Unix line endings, replacing any file already there.

    Like the charts, it goes through a hidden temporary file and one rename, so a failure
    never leaves half a report behind.
    """
    temporary = path.parent / f".{uuid.uuid4().hex}.tmp"
    try:
        with open(temporary, "x", encoding="utf-8", newline="\n") as file:
            file.write(text)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path


def write_report(report: Report, directory, formats: Iterable[str] = FORMATS) -> list[Path]:
    """Write the report into ``directory`` (created if missing) and return the paths written.

    ``formats`` picks from ``"json"`` (``report.json``), ``"md"`` (``report.md``) and
    ``"charts"`` (``charts/status.png``, ``charts/traffic.png``, ``charts/top_paths.png``).
    The Markdown links the charts only when they are written too. An unknown format raises
    :class:`ValueError` before anything is written. Files are written in a fixed order.
    """
    wanted = set(formats)
    unknown = wanted - set(FORMATS)
    if unknown:
        raise ValueError(
            f"unknown format {sorted(unknown)[0]!r}; expected some of: {', '.join(FORMATS)}"
        )

    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in wanted:
        written.append(_write_text(folder / "report.json", render_json(report)))
    if "md" in wanted:
        text = render_markdown(report, charts="charts" in wanted)
        written.append(_write_text(folder / "report.md", text))
    if "charts" in wanted:
        status, traffic, top_paths = (folder / path for path in CHART_FILES.values())
        written.append(plot_status_codes(report.summary.status_classes, status))
        written.append(plot_traffic(report.buckets, traffic))
        written.append(plot_top_paths(report.summary.top_paths, top_paths))
    return written
