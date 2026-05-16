"""
IOC Explorer Page — search/filter extracted IOCs by type, source, date.
"""

from __future__ import annotations

from typing import Any

import streamlit as st
import pandas as pd


def render(db: Any) -> None:
    st.title("🔍 IOC Explorer")
    st.markdown("Search and filter extracted Indicators of Compromise.")

    # ── Get IOC type counts for summary ───────────────────────────────
    type_counts = db.get_entity_counts_by_type()
    if not type_counts:
        st.info("No IOCs extracted yet. Run the pipeline first.")
        return

    # ── Summary metrics ───────────────────────────────────────────────
    total = sum(type_counts.values())
    cols = st.columns(min(len(type_counts), 6))
    for i, (ioc_type, count) in enumerate(
        sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:6]
    ):
        with cols[i]:
            st.metric(ioc_type.replace("_", " ").upper(), count)

    st.markdown(f"**Total IOCs: {total:,}**")
    st.markdown("---")

    # ── Filters ───────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)

    with col1:
        available_types = sorted(type_counts.keys())
        selected_type = st.selectbox(
            "IOC Type",
            options=["All"] + available_types,
            index=0,
        )

    with col2:
        confidence_filter = st.selectbox(
            "Min Confidence",
            options=["All", "high", "medium", "low"],
            index=0,
        )

    with col3:
        search_query = st.text_input("Search Value", placeholder="e.g. 192.168 or CVE-2024")

    # ── Fetch and filter ──────────────────────────────────────────────
    entity_type = selected_type if selected_type != "All" else None
    entities = db.get_entities(entity_type=entity_type, limit=5000)

    if confidence_filter != "All":
        confidence_order = {"low": 0, "medium": 1, "high": 2}
        min_level = confidence_order.get(confidence_filter, 0)
        entities = [
            e for e in entities
            if confidence_order.get(e.get("confidence", "low"), 0) >= min_level
        ]

    if search_query:
        query_lower = search_query.lower()
        entities = [e for e in entities if query_lower in e.get("value", "").lower()]

    st.markdown(f"**Showing {len(entities)} IOCs**")

    if not entities:
        st.warning("No IOCs match the current filters.")
        return

    # ── Display table ─────────────────────────────────────────────────
    rows = []
    for e in entities:
        rows.append({
            "Type": e.get("entity_type", "").replace("_", " ").upper(),
            "Value": e.get("value", ""),
            "Confidence": e.get("confidence", ""),
            "Method": e.get("extraction_method", ""),
            "Post ID": e.get("post_id", ""),
            "Extracted At": e.get("created_at", ""),
        })

    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Value": st.column_config.TextColumn("Value", width="large"),
        },
    )

    # ── Export button ─────────────────────────────────────────────────
    st.markdown("---")
    csv_data = df.to_csv(index=False)
    st.download_button(
        label="📥 Download as CSV",
        data=csv_data,
        file_name=f"iocs_{selected_type.lower()}.csv",
        mime="text/csv",
    )

    # ── Click to see post context ─────────────────────────────────────
    st.subheader("View Post Context")
    post_ids = sorted({e.get("post_id") for e in entities if e.get("post_id")})
    if post_ids:
        selected_post = st.selectbox("Select Post ID", post_ids)
        if selected_post:
            posts = db.get_all_posts(limit=5000)
            post = next((p for p in posts if p["id"] == selected_post), None)
            if post:
                st.text_area(
                    "Post Content",
                    post.get("content", ""),
                    height=250,
                    disabled=True,
                )
                # Show all IOCs from this post
                post_entities = [e for e in entities if e.get("post_id") == selected_post]
                if post_entities:
                    st.markdown(f"**IOCs from this post ({len(post_entities)}):**")
                    for pe in post_entities:
                        st.markdown(
                            f"- `{pe.get('entity_type', '')}`: **{pe.get('value', '')}** "
                            f"({pe.get('confidence', '')})"
                        )
