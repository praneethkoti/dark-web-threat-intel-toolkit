"""
Streamlit Dashboard — Main Entry Point.

Launch with::

    streamlit run dashboard/app.py

Or via CLI::

    python cli.py dashboard

Provides a multi-page web interface for exploring threat intelligence
data collected by the toolkit.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from config import settings, setup_logging
from pipeline.db_loader import DatabaseLoader

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title=settings.get("dashboard.page_title", "Threat Intelligence Dashboard"),
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Shared DB connection (cached across reruns) ──────────────────────────────

@st.cache_resource
def get_db() -> DatabaseLoader:
    """
    Return a shared DatabaseLoader instance.

    On Streamlit Cloud there is no persistent disk, so we fall back to the
    committed demo DB (data/dashboard_demo.db) when the default database path
    either doesn't exist or is empty. This guarantees the public dashboard
    always has data to display without requiring a pipeline run.
    """
    primary_path = Path(settings.get("project.database_path", "data/threat_intel.db"))
    if not primary_path.is_absolute():
        primary_path = PROJECT_ROOT / primary_path

    demo_path = PROJECT_ROOT / "data" / "dashboard_demo.db"

    # Use the demo DB if the primary one is absent or has no posts yet
    use_path = primary_path
    if not primary_path.exists() and demo_path.exists():
        use_path = demo_path
    elif primary_path.exists() and demo_path.exists():
        import sqlite3 as _sqlite3
        try:
            count = _sqlite3.connect(str(primary_path)).execute(
                "SELECT COUNT(*) FROM raw_posts"
            ).fetchone()[0]
            if count == 0:
                use_path = demo_path
        except Exception:
            use_path = demo_path

    db = DatabaseLoader(db_path=use_path)
    db.init_schema()
    return db


# ── Sidebar navigation ───────────────────────────────────────────────────────

st.sidebar.title("🛡️ Threat Intel Dashboard")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    options=[
        "📊 Overview",
        "📋 Threat Feed",
        "🔍 IOC Explorer",
        "📈 Trends",
        "📄 Report Generator",
        "🤖 AI Summarizer",
    ],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.caption(f"v{settings.get('project.version', '1.0.0')}")

# ── Page routing ──────────────────────────────────────────────────────────────

db = get_db()

if page == "📊 Overview":
    from dashboard.views.overview import render
    render(db)
elif page == "📋 Threat Feed":
    from dashboard.views.threat_feed import render
    render(db)
elif page == "🔍 IOC Explorer":
    from dashboard.views.ioc_explorer import render
    render(db)
elif page == "📈 Trends":
    from dashboard.views.trends import render
    render(db)
elif page == "📄 Report Generator":
    from dashboard.views.report_page import render
    render(db)
elif page == "🤖 AI Summarizer":
    from dashboard.views.summarizer_page import render
    render(db)
