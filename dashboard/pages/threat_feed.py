"""
Threat Feed Page — scrollable/filterable table of classified posts.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st
import pandas as pd


def render(db: Any) -> None:
    st.title("📋 Threat Feed")
    st.markdown("Browse and filter classified threat posts.")

    # ── Filters ───────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)

    classifications = db.get_classifications(limit=2000)
    if not classifications:
        st.info("No classified posts yet. Run the classifier first.")
        return

    # Get unique categories and models for filter dropdowns
    all_categories = sorted({c["category"] for c in classifications})
    all_models = sorted({c["model_used"] for c in classifications})

    with col1:
        selected_cats = st.multiselect(
            "Filter by Category",
            options=all_categories,
            default=all_categories,
        )
    with col2:
        selected_models = st.multiselect(
            "Filter by Model",
            options=all_models,
            default=all_models,
        )
    with col3:
        min_confidence = st.slider(
            "Min Confidence", 0.0, 1.0, 0.0, 0.05,
        )

    # ── Apply filters ─────────────────────────────────────────────────
    filtered = [
        c for c in classifications
        if c["category"] in selected_cats
        and c["model_used"] in selected_models
        and c["confidence"] >= min_confidence
    ]

    st.markdown(f"**Showing {len(filtered)} of {len(classifications)} posts**")

    if not filtered:
        st.warning("No posts match the current filters.")
        return

    # ── Build DataFrame ───────────────────────────────────────────────
    rows = []
    for c in filtered:
        mitre = c.get("mitre_techniques", "[]")
        if isinstance(mitre, str):
            try:
                mitre = json.loads(mitre)
            except (json.JSONDecodeError, TypeError):
                mitre = []
        mitre_str = ", ".join(mitre) if isinstance(mitre, list) else str(mitre)

        content = c.get("content", "")
        rows.append({
            "ID": c.get("post_id", ""),
            "Category": c["category"].replace("_", " ").title(),
            "Confidence": round(c["confidence"], 3),
            "Model": c["model_used"],
            "MITRE Techniques": mitre_str,
            "Classified At": c.get("classified_at", ""),
            "Content Preview": content[:150] + "..." if len(content) > 150 else content,
        })

    df = pd.DataFrame(rows)

    # ── Display table ─────────────────────────────────────────────────
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0, max_value=1, format="%.3f",
            ),
            "Content Preview": st.column_config.TextColumn(
                "Content Preview", width="large",
            ),
        },
    )

    # ── Detail expander ───────────────────────────────────────────────
    st.markdown("---")
    st.subheader("Post Detail View")
    post_ids = [r["ID"] for r in rows if r["ID"]]
    if post_ids:
        selected_id = st.selectbox("Select Post ID", options=post_ids)
        if selected_id:
            post_data = next((c for c in filtered if c.get("post_id") == selected_id), None)
            if post_data:
                col_l, col_r = st.columns([2, 1])
                with col_l:
                    st.markdown("**Full Content:**")
                    st.text_area(
                        "Content", post_data.get("content", ""),
                        height=300, disabled=True, label_visibility="collapsed",
                    )
                with col_r:
                    st.markdown("**Classification:**")
                    st.json({
                        "category": post_data["category"],
                        "confidence": post_data["confidence"],
                        "model": post_data["model_used"],
                        "mitre_techniques": post_data.get("mitre_techniques", "[]"),
                        "classified_at": post_data.get("classified_at", ""),
                    })
