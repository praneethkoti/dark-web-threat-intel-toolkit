"""
AI Summarizer Page — on-demand threat summarization of selected posts.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from analysis.trend_analyzer import TrendAnalyzer


def render(db: Any) -> None:
    st.title("🤖 AI Threat Summarizer")
    st.markdown("Generate AI-powered threat intelligence summaries.")

    # ── Backend selector ──────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        backend = st.selectbox(
            "LLM Backend",
            options=["openai", "anthropic", "local"],
            index=0,
        )
    with col2:
        mode = st.selectbox(
            "Summary Mode",
            options=["executive", "technical", "ioc_bulletin"],
            index=0,
            help="executive = leadership briefing, technical = SOC analyst, ioc_bulletin = actionable IOCs",
        )
    with col3:
        period = st.selectbox("Time Period", ["24h", "7d", "30d"], index=0)

    st.markdown("---")

    # ── Gather context from DB ────────────────────────────────────────
    analyzer = TrendAnalyzer(db)
    stats = analyzer.get_summary_stats()
    cat_dist = stats.get("classification_distribution", {})
    top_cves = analyzer.get_top_cves(top_n=5)
    ioc_dist = stats.get("entity_distribution", {})

    # Display current data context
    with st.expander("📊 Data Context (auto-populated)"):
        st.json({
            "total_posts": stats["total_posts"],
            "total_entities": stats["total_entities"],
            "category_breakdown": cat_dist,
            "top_cves": [
                f"{c['cve_id']} (CVSS: {c.get('cvss_score', 'N/A')}, {c.get('severity', 'N/A')})"
                for c in top_cves
            ],
            "ioc_distribution": ioc_dist,
        })

    # ── Custom context (optional) ─────────────────────────────────────
    custom_context = st.text_area(
        "Additional Context (optional)",
        placeholder="Add any extra context for the summarizer, e.g. specific incidents or priorities...",
        height=100,
    )

    # ── Generate button ───────────────────────────────────────────────
    if st.button("🚀 Generate Summary", type="primary"):
        if stats["total_posts"] == 0:
            st.warning("No data in the database. Run the pipeline first.")
            return

        with st.spinner(f"Generating {mode} summary via {backend}..."):
            try:
                from ai_summarizer import ThreatSummarizer
                summarizer = ThreatSummarizer(backend)

                cat_str = ", ".join(
                    f"{k}: {v}" for k, v in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True)
                )
                cve_str = "; ".join(
                    f"{c['cve_id']} (CVSS {c.get('cvss_score', 'N/A')}, {c.get('severity', '')})"
                    for c in top_cves
                ) or "None identified"
                ioc_str = ", ".join(f"{v} {k}" for k, v in ioc_dist.items()) or "N/A"

                additional = f"\nAdditional context: {custom_context}" if custom_context else ""

                result = summarizer.summarize(
                    mode=mode,
                    time_period=period,
                    total_posts=str(stats["total_posts"]),
                    category_breakdown=cat_str + additional,
                    critical_cves=cve_str,
                    ioc_summary=ioc_str,
                    trends="See trend analysis",
                    cve_details=cve_str,
                    mitre_techniques="See classification results",
                    ioc_details=ioc_str,
                    ioc_data=ioc_str,
                    anomalies="See anomaly detection output",
                    categories=cat_str,
                )

                st.success(f"Summary generated ({len(result)} chars) via {summarizer.backend_name}")
                st.markdown("---")
                st.markdown(result)

                # Download button
                st.download_button(
                    label="📥 Download Summary",
                    data=result,
                    file_name=f"threat_summary_{mode}_{period}.md",
                    mime="text/markdown",
                )

            except ImportError as e:
                st.error(f"Missing dependency: {e}\n\nInstall with: `pip install openai anthropic`")
            except ValueError as e:
                st.error(f"Configuration error: {e}")
            except Exception as e:
                st.error(f"Summary generation failed: {e}")

    # ── Summarize specific posts ──────────────────────────────────────
    st.markdown("---")
    st.subheader("Summarize Specific Posts")

    classifications = db.get_classifications(limit=500)
    if classifications:
        post_ids = [c["post_id"] for c in classifications]
        selected_ids = st.multiselect(
            "Select Post IDs to Summarize",
            options=sorted(set(post_ids)),
        )

        if selected_ids and st.button("Summarize Selected Posts"):
            selected_posts = [
                c for c in classifications if c["post_id"] in selected_ids
            ]
            with st.spinner("Summarizing selected posts..."):
                try:
                    from ai_summarizer import ThreatSummarizer
                    summarizer = ThreatSummarizer(backend)
                    result = summarizer.summarize_posts(
                        selected_posts, mode=mode, time_period=period,
                    )
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Failed: {e}")
    else:
        st.info("No classified posts available for selection.")
