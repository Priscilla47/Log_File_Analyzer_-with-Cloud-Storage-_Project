"""Write a :class:`Report` as JSON, Markdown and PNG charts, to a storage or to a folder."""

from collections.abc import Iterable
from pathlib import Path

from loginsight.reporting.charts import status_codes_png, top_paths_png, traffic_png
from loginsight.reporting.report import CHART_FILES, Report, render_json, render_markdown
from loginsight.storage import LocalStorage, Storage

FORMATS = ("json", "md", "charts")


def _check_formats(formats: Iterable[str]) -> set[str]:
    wanted = set(formats)
    unknown = wanted - set(FORMATS)
    if unknown:
        raise ValueError(
            f"unknown format {sorted(unknown)[0]!r}; expected some of: {', '.join(FORMATS)}"
        )
    return wanted


def write_to_storage(
    report: Report, storage: Storage, formats: Iterable[str] = FORMATS
) -> list[str]:
    """Write the report into ``storage`` and return the keys written, in a fixed order.

    ``formats`` picks from ``"json"`` (``report.json``), ``"md"`` (``report.md``) and
    ``"charts"`` (``charts/status.png``, ``charts/traffic.png``, ``charts/top_paths.png``).
    The Markdown links the charts only when they are written too. An unknown format raises
    :class:`ValueError` before anything is written. Each file is written with the storage's
    own atomic write, as UTF-8 with Unix line endings.
    """
    wanted = _check_formats(formats)
    written = []
    if "json" in wanted:
        storage.write_bytes("report.json", render_json(report).encode("utf-8"))
        written.append("report.json")
    if "md" in wanted:
        text = render_markdown(report, charts="charts" in wanted)
        storage.write_bytes("report.md", text.encode("utf-8"))
        written.append("report.md")
    if "charts" in wanted:
        status, traffic, top_paths = CHART_FILES.values()
        storage.write_bytes(status, status_codes_png(report.summary.status_classes))
        storage.write_bytes(traffic, traffic_png(report.buckets))
        storage.write_bytes(top_paths, top_paths_png(report.summary.top_paths))
        written.extend([status, traffic, top_paths])
    return written


def write_report(report: Report, directory, formats: Iterable[str] = FORMATS) -> list[Path]:
    """Write the report into ``directory`` (created if missing) and return the paths written.

    The same as :func:`write_to_storage` on a :class:`LocalStorage` for that folder.
    """
    wanted = _check_formats(formats)
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    keys = write_to_storage(report, LocalStorage(folder), wanted)
    return [folder / key for key in keys]
