"""The dashboard page, as a function of the Streamlit module it is given.

Streamlit is passed in instead of imported, so the page's logic (what to show for no file, a
good file, a bad one) can be tested with a fake that records the calls. ``app.py`` is the only
file that imports Streamlit and does nothing but hand it over.
"""

from typing import Any

from loginsight.dashboard import data, filters
from loginsight.dashboard.profile import ip_profile
from loginsight.parsing.models import LogEntry
from loginsight.reporting.report import GAPS_NOTE, Report


def _charts(st: Any, charts: data.Charts) -> None:
    """The three charts, each under its own title, from the tables in ``charts``."""
    st.subheader("Responses by status class")
    st.bar_chart(
        charts.status,
        x="Status class",
        y="Requests",
        x_label="Status class",
        y_label="Requests",
        color=data.COLOUR_MAIN,
    )
    st.subheader("Traffic over time")
    st.line_chart(
        charts.traffic,
        x="Time (UTC)",
        y=["Requests", "Errors"],
        x_label="Time (UTC)",
        y_label="Requests",
        color=[data.COLOUR_MAIN, data.COLOUR_ERRORS],
    )
    if not charts.gaps_filled:
        st.caption(GAPS_NOTE)
    st.subheader("Most requested paths")
    st.bar_chart(
        charts.top_paths,
        x="Path",
        y="Requests",
        x_label="Path",
        y_label="Requests",
        color=data.COLOUR_MAIN,
        horizontal=True,
        sort="-Requests",
    )


def _detections(st: Any, report: Report, scope: str) -> None:
    """The detections under four filters, each value with the number of detections it has."""
    st.subheader("Detections")
    everything = report.detections
    if not everything:
        st.success("No attacks were detected in this log.")
        return
    severity_counts = filters.severity_counts(everything)
    label_counts = filters.label_counts(everything)
    ip_counts = filters.ip_counts(everything)
    left, middle, right = st.columns(3)
    severities = left.multiselect(
        "Severity",
        list(severity_counts),
        format_func=lambda severity: f"{severity} ({severity_counts[severity]})",
        key=f"filter_severity:{scope}",
        placeholder="All severities",
    )
    labels = middle.multiselect(
        "Class",
        list(label_counts),
        format_func=lambda label: f"{label} ({label_counts[label]})",
        key=f"filter_class:{scope}",
        placeholder="All classes",
    )
    ip = right.selectbox(
        "Address",
        list(ip_counts),
        index=None,
        format_func=lambda address: f"{address} ({ip_counts[address]})",
        key=f"filter_ip:{scope}",
        placeholder="All addresses",
    )
    start = end = None
    full = filters.time_bounds(everything)
    if full is not None:
        chosen = st.slider(
            "Time range (UTC)",
            min_value=full[0],
            max_value=full[1],
            value=full,
            step=filters.SLIDER_STEP,
            format="YYYY-MM-DD HH:mm:ss",
            key=f"filter_time:{scope}",
        )
        start, end = filters.range_to_filter(full, tuple(chosen))
    shown = filters.filter_detections(
        everything,
        severities=severities or None,
        labels=labels or None,
        ip=ip,
        start=start,
        end=end,
    )
    st.caption(f"Showing {len(shown)} of {len(everything)} detections.")
    if not shown:
        st.info("No detection matches these filters.")
        return
    st.dataframe(filters.detections_table(shown), hide_index=True)


def _address(st: Any, report: Report, entries: list[LogEntry], scope: str) -> None:
    """Everything one chosen address did."""
    st.subheader("One address")
    ip = st.selectbox(
        "Address",
        data.ip_choices(report),
        index=None,
        key=f"address:{scope}",
        placeholder="Choose an address",
        help=f"Addresses with detections first, then the busiest, at most {data.MAX_IP_CHOICES}.",
    )
    if ip is None:
        st.caption("Choose an address to see everything it did.")
        return
    profile = ip_profile(entries, report.detections, ip)
    if not profile.known:
        st.info("This address does not appear in the log.")
        return
    cards = data.profile_cards(profile)
    for column, card in zip(st.columns(len(cards)), cards, strict=True):
        column.metric(card.label, card.value, help=card.help)
    left, right = st.columns(2)
    left.caption("Responses it received")
    left.dataframe(data.profile_status_table(profile), hide_index=True)
    right.caption("Paths it asked for")
    right.dataframe(data.profile_paths_table(profile), hide_index=True)
    if profile.detections:
        st.caption("Detections that name this address")
        st.dataframe(filters.detections_table(profile.detections), hide_index=True)
    else:
        st.caption("No detections name this address.")


def show_page(st: Any) -> None:
    """Draw the whole page with ``st``, the Streamlit module (or anything with its calls)."""
    st.set_page_config(page_title=data.APP_TITLE, layout="wide")
    st.title(data.APP_TITLE)
    limit = data.UPLOAD_LIMIT_BYTES
    upload = st.file_uploader(
        "Access log",
        key="log_file",
        help=f"An Apache or Nginx access log, up to {data.limit_text(limit, decimals=False)}.",
    )
    if upload is None:
        st.info(data.EMPTY_MESSAGE)
        return
    bucket = st.radio(
        "Group the traffic by",
        data.BUCKETS,
        index=data.BUCKETS.index(data.DEFAULT_BUCKET),
        horizontal=True,
        key="bucket",
    )
    outcome = data.analyze_upload(upload.getvalue(), upload.name, limit=limit, bucket=bucket)
    if outcome.error is not None:
        st.error(outcome.error)
        return
    for warning in outcome.warnings:
        st.warning(warning)
    if outcome.notice is not None:
        st.info(outcome.notice)
    for column, card in zip(st.columns(len(outcome.cards)), outcome.cards, strict=True):
        column.metric(card.label, card.value, help=card.help)
    for fact in outcome.facts:
        st.text(fact)
    if outcome.charts is not None:
        _charts(st, outcome.charts)
    report = outcome.report
    if report is not None and report.summary.total_requests:
        scope = upload.file_id
        _detections(st, report, scope)
        _address(st, report, outcome.entries, scope)
