"""The dashboard page, as a function of the Streamlit module it is given.

Streamlit is passed in instead of imported, so the page's logic (what to show for no file, a
good file, a bad one) can be tested with a fake that records the calls. ``app.py`` is the only
file that imports Streamlit and does nothing but hand it over.
"""

from typing import Any

from loginsight.dashboard import data


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
    outcome = data.analyze_upload(upload.getvalue(), upload.name, limit=limit)
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
