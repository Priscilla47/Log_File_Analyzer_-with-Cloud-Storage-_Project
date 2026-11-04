"""The dashboard page, as Streamlit runs it. Everything it does is in ``render.show_page``."""

import streamlit as st

from loginsight.dashboard.render import show_page

show_page(st)
