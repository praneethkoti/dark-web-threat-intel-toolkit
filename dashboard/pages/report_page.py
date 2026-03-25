"""
Report Generator Page — trigger report generation and download.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from analysis.trend_analyzer import TrendAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from analysis.report_generator import ReportGenerator


def render(db: Any) -> None:
    st.title("📄 Report Generator")
    st.markdown("Generate and download threat intelligence reports.")

    # ── Options ───────────────────────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        report_format = st.selectbox("Format", ["Markdown", "HTML", "Both"])
    with col2:
        window = st.selectbox("Time Period", ["7d", "30d", "90d"], index=1)

    # ── Generate button ───────────────────────────────────────────────
    if st.button("🚀 Generate Report", type="primary"):
        with st.spinner("Analyzing data and generating report..."):
            analyzer = TrendAnalyzer(db)
            detector = AnomalyDetector(db)
            gen = ReportGenerator()

            stats = analyzer.get_summary_stats()
            cat_dist = analyzer.get_category_distribution(window)
            top_cves = analyzer.get_top_cves()
            keywords = analyzer.get_trending_keywords(window)
            ioc_dist = analyzer.get_ioc_distribution()
            anomalies = detector.detect(
                window_days=int(window.replace("d", ""))
            )
            actors = analyzer.get_threat_actor_patterns()

            report_args = dict(
                summary_stats=stats,
                category_dist=cat_dist,
                top_cves=top_cves,
                trending_keywords=keywords,
                ioc_dist=ioc_dist,
                anomalies=anomalies,
                actor_patterns=actors,
            )

            paths = []
            if report_format in ("Markdown", "Both"):
                md_path = gen.generate_markdown(**report_args)
                paths.append(("Markdown", md_path))

            if report_format in ("HTML", "Both"):
                html_path = gen.generate_html(**report_args)
                paths.append(("HTML", html_path))

        st.success(f"Report generated! ({len(paths)} file(s))")

        # ── Download buttons ──────────────────────────────────────
        for label, path in paths:
            content = path.read_text(encoding="utf-8")
            mime = "text/markdown" if label == "Markdown" else "text/html"
            suffix = ".md" if label == "Markdown" else ".html"

            st.download_button(
                label=f"📥 Download {label} Report",
                data=content,
                file_name=f"threat_report{suffix}",
                mime=mime,
            )

            # Preview
            with st.expander(f"Preview {label} Report"):
                if label == "HTML":
                    st.components.v1.html(content, height=600, scrolling=True)
                else:
                    st.markdown(content)
