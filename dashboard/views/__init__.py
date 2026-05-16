"""dashboard.views — Individual page modules for the Streamlit dashboard.

Named ``views`` (not ``pages``) to prevent Streamlit Cloud's automatic
multi-page discovery, which scans any folder literally named ``pages/`` next
to the entry-point script and produces blank auto-routes that bypass our
custom sidebar navigation in app.py.
"""

__all__ = [
    "overview",
    "threat_feed",
    "ioc_explorer",
    "trends",
    "report_page",
    "summarizer_page",
]
