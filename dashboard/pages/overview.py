"""
Overview Page — high-level summary metrics and charts.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from analysis.trend_analyzer import TrendAnalyzer
from analysis.visualizer import Visualizer


def render(db: Any) -> None:
    st.title("📊 Threat Intelligence Overview")
    st.markdown("Real-time summary of collected threat data.")

    analyzer = TrendAnalyzer(db)
    stats = analyzer.get_summary_stats()

    # ── Metric cards ──────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Posts", f"{stats['total_posts']:,}")
    with col2:
        st.metric("IOCs Extracted", f"{stats['total_entities']:,}")
    with col3:
        cat_count = len(stats.get("classification_distribution", {}))
        st.metric("Threat Categories", cat_count)
    with col4:
        st.metric("CVEs Enriched", stats.get("cve_enrichments_count", 0))

    st.markdown("---")

    # ── Category distribution charts ──────────────────────────────────
    cat_dist = stats.get("classification_distribution", {})
    if cat_dist:
        col_bar, col_pie = st.columns(2)
        viz = Visualizer()

        with col_bar:
            st.subheader("Threat Category Distribution")
            fig_bar = viz.category_bar_chart(cat_dist)
            st.plotly_chart(fig_bar, width="stretch")

        with col_pie:
            st.subheader("Category Breakdown")
            fig_pie = viz.category_pie_chart(cat_dist)
            st.plotly_chart(fig_pie, width="stretch")
    else:
        st.info(
            "No classified posts yet. Run the pipeline and classifier first:\n\n"
            "```\npython cli.py full-pipeline\n```"
        )

    # ── IOC type distribution ─────────────────────────────────────────
    ioc_dist = stats.get("entity_distribution", {})
    if ioc_dist:
        st.subheader("IOC Type Distribution")
        viz = Visualizer()
        fig_ioc = viz.ioc_distribution_chart(ioc_dist)
        st.plotly_chart(fig_ioc, width="stretch")

    # ── Top CVEs ──────────────────────────────────────────────────────
    top_cves = analyzer.get_top_cves(top_n=10)
    if top_cves:
        st.subheader("Top Mentioned CVEs")
        import pandas as pd
        df = pd.DataFrame(top_cves)
        df = df[["cve_id", "mention_count", "cvss_score", "severity", "description"]]
        df.columns = ["CVE ID", "Mentions", "CVSS", "Severity", "Description"]

        # Color-code severity
        def color_severity(val):
            colors = {
                "CRITICAL": "background-color: rgba(231,76,60,0.3)",
                "HIGH": "background-color: rgba(230,126,34,0.3)",
                "MEDIUM": "background-color: rgba(243,156,18,0.3)",
                "LOW": "background-color: rgba(39,174,96,0.3)",
            }
            return colors.get(val, "")

        st.dataframe(
            df.style.map(color_severity, subset=["Severity"]),
            width="stretch",
            hide_index=True,
        )
