"""The dashboard page. Only layout lives here: what to show comes from ``data.py``."""

import streamlit as st

from loginsight.dashboard.data import APP_TITLE, EMPTY_MESSAGE

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.file_uploader("Access log", key="log_file")
st.info(EMPTY_MESSAGE)
