"""PNG charts for the analysis results.

Each function takes plain data (not a DataFrame), writes one PNG file to the path it is given
and returns that path. Figures are built with matplotlib's object API and never touch
``pyplot``, so there is no global state: nothing to close, no figure left open if a write
fails, no GUI backend, and nothing written to the current folder.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path

from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.dates import AutoDateLocator, ConciseDateFormatter
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator

from loginsight.analysis.timeseries import TimeBucket

FIGURE_SIZE = (8, 4.5)  # inches
DPI = 100  # so every chart is 800 x 450 pixels
MAX_LABEL_LENGTH = 40  # longer path labels are cut and end with an ellipsis

_MAIN_CLASSES = ("2xx", "3xx", "4xx", "5xx")
_OPTIONAL_CLASSES = ("1xx", "other")  # drawn only when they have requests
_CLASS_ORDER = ("1xx", "2xx", "3xx", "4xx", "5xx", "other")
_CLASS_COLOURS = {
    "1xx": "#7f7f7f",
    "2xx": "#2ca02c",
    "3xx": "#1f77b4",
    "4xx": "#ff7f0e",
    "5xx": "#d62728",
    "other": "#9467bd",
}


def _new_figure(title: str):
    figure = Figure(figsize=FIGURE_SIZE, dpi=DPI, layout="constrained")
    FigureCanvasAgg(figure)
    ax = figure.subplots()
    ax.set_title(title)
    return figure, ax


def _no_data(title: str) -> Figure:
    figure, ax = _new_figure(title)
    ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=16, color="#777777")
    ax.set_axis_off()
    return figure


def _save(figure: Figure, output) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, format="png")
    return path


def _label(path: str) -> str:
    """A y-axis label for a request path: shortened, and safe to draw as plain text."""
    if not path:
        return "(no path)"  # a malformed request has no path
    if len(path) > MAX_LABEL_LENGTH:
        path = path[: MAX_LABEL_LENGTH - 1] + "…"
    return path.replace("$", r"\$")  # matplotlib would read $...$ as math


def plot_status_codes(status_classes: Mapping[str, int], output) -> Path:
    """Bar chart of requests per status class (``"2xx"``, ``"4xx"`` and so on).

    The four main classes are always drawn. ``"1xx"`` and ``"other"`` appear only when they
    have requests. An unknown class or a negative count raises :class:`ValueError`.
    """
    for name, count in status_classes.items():
        if name not in _CLASS_ORDER:
            raise ValueError(f"unknown status class {name!r}")
        if count < 0:
            raise ValueError(f"negative count for {name}: {count}")

    if not any(status_classes.values()):
        return _save(_no_data("Responses by status class"), output)

    names = [
        name for name in _CLASS_ORDER if name in _MAIN_CLASSES or status_classes.get(name, 0) > 0
    ]
    counts = [status_classes.get(name, 0) for name in names]

    figure, ax = _new_figure("Responses by status class")
    bars = ax.bar(names, counts, color=[_CLASS_COLOURS[name] for name in names])
    ax.bar_label(bars)
    ax.set_xlabel("Status class")
    ax.set_ylabel("Requests")
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    return _save(figure, output)


def plot_traffic(buckets: Sequence[TimeBucket], output) -> Path:
    """Line chart of requests per bucket, with the errors as a second line."""
    if not buckets:
        return _save(_no_data("Traffic over time"), output)

    starts = [bucket.start for bucket in buckets]
    figure, ax = _new_figure("Traffic over time")
    # A marker keeps a single bucket visible, because a one-point line draws nothing.
    ax.plot(starts, [b.requests for b in buckets], label="Requests", marker="o", markersize=3)
    ax.plot(
        starts,
        [b.errors for b in buckets],
        label="Errors",
        color=_CLASS_COLOURS["5xx"],
        marker="o",
        markersize=3,
    )
    locator = AutoDateLocator()
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(ConciseDateFormatter(locator))
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Time (UTC)")
    ax.set_ylabel("Requests")
    ax.set_ylim(bottom=0)
    ax.legend()
    return _save(figure, output)


def plot_top_paths(top_paths: Sequence[tuple[str, int]], output) -> Path:
    """Horizontal bar chart of the most requested paths, busiest first (at the top)."""
    if not top_paths:
        return _save(_no_data("Most requested paths"), output)

    figure, ax = _new_figure("Most requested paths")
    bars = ax.barh([_label(path) for path, _ in top_paths], [count for _, count in top_paths])
    ax.bar_label(bars, padding=3)
    ax.invert_yaxis()
    ax.set_xlabel("Requests")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    return _save(figure, output)
