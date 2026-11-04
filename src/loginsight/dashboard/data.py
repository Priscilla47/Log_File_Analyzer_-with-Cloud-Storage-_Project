"""What the dashboard shows, computed without Streamlit.

The page (``app.py``) only draws what this module hands it, so everything that can be wrong
can be tested without a browser. It never imports Streamlit.
"""

APP_TITLE = "LogInsight"
EMPTY_MESSAGE = (
    "Choose an Apache or Nginx access log to see what happened and what looks like an attack."
)
