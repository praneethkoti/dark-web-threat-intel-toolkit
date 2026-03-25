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
    """Return a shared DatabaseLoader instance."""
    db = DatabaseLoader()
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
    from dashboard.pages.overview import render
    render(db)
elif page == "📋 Threat Feed":
    from dashboard.pages.threat_feed import render
    render(db)
elif page == "🔍 IOC Explorer":
    from dashboard.pages.ioc_explorer import render
    render(db)
elif page == "📈 Trends":
    from dashboard.pages.trends import render
    render(db)
elif page == "📄 Report Generator":
    from dashboard.pages.report_page import render
    render(db)
elif page == "🤖 AI Summarizer":
    from dashboard.pages.summarizer_page import render
    render(db)
