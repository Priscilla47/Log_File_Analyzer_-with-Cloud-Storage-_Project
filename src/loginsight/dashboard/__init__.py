"""The web dashboard: a second interface over the same analysis as the command line.

It needs Streamlit, which is an optional extra (``pip install 'loginsight[dashboard]'``).
Nothing in this package imports Streamlit except ``app.py``, which only the ``streamlit``
command loads, so the rest of LogInsight works without it.
"""
