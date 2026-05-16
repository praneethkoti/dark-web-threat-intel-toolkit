"""
Trends Page — interactive Plotly charts and anomaly detection results.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from analysis.trend_analyzer import TrendAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from analysis.visualizer import Visualizer


def render(db: Any) -> None:
    st.title("📈 Trends & Anomaly Detection")

    analyzer = TrendAnalyzer(db)
    viz = Visualizer()

    # ── Time window selector ──────────────────────────────────────────
    window = st.selectbox("Time Window", ["7d", "30d", "90d", "365d"], index=1)

    # ── Category timeline ─────────────────────────────────────────────
    st.subheader("Threat Activity Over Time")
    cat_dist = analyzer.get_category_distribution(window)

    if cat_dist["timeline"]:
        fig = viz.timeline_chart(cat_dist["timeline"])
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("Not enough data for a timeline chart.")

    # ── Category distribution ─────────────────────────────────────────
    if cat_dist["categories"]:
        st.subheader("Category Distribution")
        col1, col2 = st.columns(2)
        with col1:
            fig_bar = viz.category_bar_chart(
                cat_dist["categories"],
                title=f"Category Counts ({window})",
            )
            st.plotly_chart(fig_bar, width="stretch")
        with col2:
            fig_pie = viz.category_pie_chart(
                cat_dist["categories"],
                title=f"Category Proportions ({window})",
            )
            st.plotly_chart(fig_pie, width="stretch")

    # ── Top CVEs with severity ────────────────────────────────────────
    st.subheader("Top CVEs by Severity")
    top_cves = analyzer.get_top_cves(top_n=15)
    if top_cves:
        fig_cve = viz.cve_severity_chart(top_cves)
        st.plotly_chart(fig_cve, width="stretch")
    else:
        st.info("No CVE data available.")

    # ── Trending keywords ─────────────────────────────────────────────
    st.subheader("Trending Keywords")
    keywords = analyzer.get_trending_keywords(window, top_n=30)
    if keywords:
        # Display as tag cloud using columns
        cols = st.columns(6)
        for i, kw in enumerate(keywords[:30]):
            with cols[i % 6]:
                size = min(1.5, 0.8 + kw["count"] / (keywords[0]["count"] or 1))
                st.markdown(
                    f"<span style='font-size:{size}em'>{kw['keyword']}</span> "
                    f"<small>({kw['count']})</small>",
                    unsafe_allow_html=True,
                )
    else:
        st.info("No keyword data available.")

    # ── Anomaly detection ─────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🚨 Anomaly Detection")

    detector = AnomalyDetector(db)
    anomalies = detector.detect(window_days=int(window.replace("d", "")))

    if anomalies:
        st.warning(f"**{len(anomalies)} anomalous spikes detected!**")
        import pandas as pd
        anom_rows = []
        for a in anomalies:
            score_key = "zscore" if "zscore" in a else "deviation"
            anom_rows.append({
                "Date": a["date"],
                "Category": a["category"].replace("_", " ").title(),
                "Count": a["count"],
                "Score": round(a.get(score_key, 0), 2),
                "Method": a.get("method", ""),
            })
        df = pd.DataFrame(anom_rows)
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.success("No anomalous activity spikes detected.")

    # ── Threat actor patterns ─────────────────────────────────────────
    st.markdown("---")
    st.subheader("Threat Actor Patterns")
    patterns = analyzer.get_threat_actor_patterns()
    if patterns:
        import pandas as pd
        actor_rows = [{
            "Username": p["username"],
            "Posts": p["post_count"],
            "Sources": p["unique_sources"],
        } for p in patterns[:20]]
        st.dataframe(pd.DataFrame(actor_rows), width="stretch", hide_index=True)
    else:
        st.info("No repeat threat actors detected across sources.")
