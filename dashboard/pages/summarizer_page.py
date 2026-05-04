"""
AI Summarizer Page — on-demand threat summarization.

Backend availability is probed at render time (not at import time) so that
missing optional packages (torch, openai, anthropic) never prevent the page
from loading. Only the backends that are actually importable and have a
configured API key are offered to the user.
"""

from __future__ import annotations

import os
from typing import Any

import streamlit as st

from analysis.trend_analyzer import TrendAnalyzer


# ── Backend availability probe ────────────────────────────────────────────────

def _probe_backends() -> dict[str, str | None]:
    """
    Return a dict mapping backend name → None if available, or an error
    string describing why it is not. Probed in preferred priority order:
    openai → anthropic → local (matches settings.yaml default_backend logic).

    Probing is intentionally lightweight: we only check that the package can
    be imported and that an API key is present. We do NOT make a live API call.
    """
    def _get_key(env_var: str, secrets_key: str) -> str:
        """Read an API key from st.secrets first, then os.environ."""
        try:
            return st.secrets.get(secrets_key, "") or ""
        except Exception:
            pass
        return os.environ.get(env_var, "")

    results: dict[str, str | None] = {}

    # openai
    try:
        import openai as _openai  # noqa: F401
        key = _get_key("OPENAI_API_KEY", "OPENAI_API_KEY")
        if key:
            results["openai"] = None          # available
        else:
            results["openai"] = "OPENAI_API_KEY not set — add it to Streamlit secrets or .env"
    except ImportError:
        results["openai"] = "openai package not installed (`pip install openai`)"

    # anthropic
    try:
        import anthropic as _anthropic  # noqa: F401
        key = _get_key("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
        if key:
            results["anthropic"] = None       # available
        else:
            results["anthropic"] = "ANTHROPIC_API_KEY not set — add it to Streamlit secrets or .env"
    except ImportError:
        results["anthropic"] = "anthropic package not installed (`pip install anthropic`)"

    # local (HuggingFace — no API key needed, but torch + transformers required)
    try:
        import transformers as _tr  # noqa: F401
        import torch as _torch      # noqa: F401
        results["local"] = None               # available
    except ImportError as exc:
        missing = "transformers + torch" if "torch" in str(exc) else "transformers"
        results["local"] = (
            f"{missing} not installed (`pip install transformers torch`) — "
            "required for local inference"
        )

    return results


# ── Page render ───────────────────────────────────────────────────────────────

def render(db: Any) -> None:
    st.title("🤖 AI Threat Summarizer")
    st.markdown("Generate AI-powered threat intelligence summaries.")

    # ── Probe which backends are usable right now ─────────────────────
    availability = _probe_backends()
    available    = [name for name, err in availability.items() if err is None]
    unavailable  = {name: err for name, err in availability.items() if err is not None}

    # ── No backends at all → friendly placeholder card ────────────────
    if not available:
        st.info(
            "**No AI backends are currently available.**\n\n"
            "Install and configure at least one to use this page:\n\n"
            "| Backend | Install command | Key required |\n"
            "|---|---|---|\n"
            "| OpenAI | `pip install openai` | `OPENAI_API_KEY` |\n"
            "| Anthropic | `pip install anthropic` | `ANTHROPIC_API_KEY` |\n"
            "| Local (HF) | `pip install transformers torch` | None |\n\n"
            "Add API keys to `.env` or to **Streamlit Cloud → Secrets**."
        )

        with st.expander("ℹ️ Backend status"):
            for name, err in unavailable.items():
                st.warning(f"**{name}**: {err}")
        return

    # ── Show availability badges in sidebar / expander ────────────────
    with st.expander("🔌 Backend status", expanded=False):
        for name, err in availability.items():
            if err is None:
                st.success(f"**{name}** — available")
            else:
                st.warning(f"**{name}** — {err}")

    # ── Controls — only show available backends ───────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        backend = st.selectbox(
            "LLM Backend",
            options=available,          # filtered to importable + keyed backends
            index=0,                    # first available = openai → anthropic → local
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
    stats    = analyzer.get_summary_stats()
    cat_dist = stats.get("classification_distribution", {})
    top_cves = analyzer.get_top_cves(top_n=5)
    ioc_dist = stats.get("entity_distribution", {})

    with st.expander("📊 Data Context (auto-populated)"):
        st.json({
            "total_posts":       stats["total_posts"],
            "total_entities":    stats["total_entities"],
            "category_breakdown": cat_dist,
            "top_cves": [
                f"{c['cve_id']} (CVSS: {c.get('cvss_score', 'N/A')}, {c.get('severity', 'N/A')})"
                for c in top_cves
            ],
            "ioc_distribution": ioc_dist,
        })

    custom_context = st.text_area(
        "Additional Context (optional)",
        placeholder="Add any extra context, e.g. specific incidents or priorities...",
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
                    f"{k}: {v}"
                    for k, v in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True)
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

                st.download_button(
                    label="📥 Download Summary",
                    data=result,
                    file_name=f"threat_summary_{mode}_{period}.md",
                    mime="text/markdown",
                )

            except ImportError as exc:
                # Shouldn't happen for an 'available' backend, but guard anyway
                st.warning(
                    f"⚠️ Could not load the **{backend}** backend: `{exc}`\n\n"
                    "This usually means a dependency was uninstalled after the page loaded. "
                    "Reload the page to refresh backend availability."
                )
            except ValueError as exc:
                # Missing API key raised by backend __init__
                st.info(
                    f"ℹ️ **{backend}** backend needs an API key.\n\n"
                    f"`{exc}`\n\n"
                    "Add it to `.env` or to **Streamlit Cloud → App settings → Secrets**."
                )
            except Exception as exc:
                st.error(f"Summary generation failed: {exc}")

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
            selected_posts = [c for c in classifications if c["post_id"] in selected_ids]
            with st.spinner("Summarizing selected posts..."):
                try:
                    from ai_summarizer import ThreatSummarizer
                    summarizer = ThreatSummarizer(backend)
                    result = summarizer.summarize_posts(
                        selected_posts, mode=mode, time_period=period,
                    )
                    st.markdown(result)
                except ValueError as exc:
                    st.info(
                        f"ℹ️ **{backend}** backend needs an API key.\n\n`{exc}`"
                    )
                except Exception as exc:
                    st.error(f"Failed: {exc}")
    else:
        st.info("No classified posts available for selection.")
