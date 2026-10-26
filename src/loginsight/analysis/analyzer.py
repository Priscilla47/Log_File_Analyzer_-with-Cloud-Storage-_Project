"""DataFrame-based statistics over parsed log entries."""

from dataclasses import fields

import pandas as pd

from loginsight.parsing.models import LogEntry

_COLUMNS = [field.name for field in fields(LogEntry)]


def analyze_entries(entries):
    """Build a DataFrame from ``entries`` and compute basic statistics.

    ``entries`` is a list of :class:`LogEntry` objects. Plain dicts are accepted too. The
    DataFrame has one row per entry in input order, and for ``LogEntry`` input its ``time``
    column is converted to UTC so entries logged in different time zones can be compared and
    grouped. An empty input gives an empty DataFrame with the ``LogEntry`` columns and zero
    statistics.

    Returns ``(df, stats)``. Everything in ``stats`` is a plain Python value, so it can be
    written as JSON.
    """
    entries = list(entries)
    rows = [e.to_dict() if isinstance(e, LogEntry) else e for e in entries]
    if not rows:
        df = pd.DataFrame(columns=_COLUMNS)
    else:
        df = pd.DataFrame(rows)
        if any(isinstance(e, LogEntry) for e in entries):
            df["time"] = pd.to_datetime(df["time"], utc=True)

    stats = {
        "total_requests": int(len(df)),
        "unique_ips": int(df["ip"].nunique()),
        "most_common_ips": df["ip"].value_counts().head(5).to_dict(),
        "most_requested_paths": df["path"].value_counts().head(5).to_dict(),
        "status_code_counts": df["status"].value_counts().to_dict(),
        "total_data_transferred_MB": float(round(df["size"].sum() / 1024 / 1024, 2)),
    }

    return df, stats
