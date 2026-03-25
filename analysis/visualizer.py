"""
Visualization Engine.

Generates interactive charts (Plotly) with static fallback (matplotlib)
for embedding in reports and the Streamlit dashboard.

Charts:
    - Threat category distribution (bar + pie)
    - Timeline of threat activity by category (stacked area)
    - CVE severity heatmap
    - Word clouds of trending terms
    - IOC type distribution
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


def _get_chart_dir() -> Path:
    chart_dir = PROJECT_ROOT / settings.get(
        "analysis.chart_output_dir", "data/reports/charts"
    )
    chart_dir.mkdir(parents=True, exist_ok=True)
    return chart_dir


class Visualizer:
    """
    Generate charts from trend analysis data.

    Usage::

        viz = Visualizer()
        fig = viz.category_bar_chart(distribution_data)
        viz.save_chart(fig, "category_bar.html")
    """

    def __init__(self) -> None:
        self._chart_dir = _get_chart_dir()

    # ── Category Distribution (Bar) ───────────────────────────────────────

    def category_bar_chart(
        self, category_data: dict[str, int], title: str = "Threat Category Distribution"
    ) -> Any:
        """
        Create a bar chart of threat category counts.

        Args:
            category_data: {"data_breach": 15, "ransomware_malware": 10, ...}

        Returns:
            Plotly Figure object.
        """
        import plotly.graph_objects as go

        categories = list(category_data.keys())
        counts = list(category_data.values())

        # Pretty labels
        labels = [c.replace("_", " ").title() for c in categories]

        colors = [
            "#e74c3c", "#e67e22", "#f39c12", "#27ae60", "#3498db", "#9b59b6",
            "#1abc9c", "#34495e",
        ]

        fig = go.Figure(data=[
            go.Bar(
                x=labels,
                y=counts,
                marker_color=colors[:len(categories)],
                text=counts,
                textposition="auto",
            )
        ])
        fig.update_layout(
            title=title,
            xaxis_title="Category",
            yaxis_title="Count",
            template="plotly_dark",
            height=450,
        )
        return fig

    # ── Category Distribution (Pie) ───────────────────────────────────────

    def category_pie_chart(
        self, category_data: dict[str, int], title: str = "Threat Category Breakdown"
    ) -> Any:
        """Create a pie chart of threat category proportions."""
        import plotly.graph_objects as go

        categories = list(category_data.keys())
        counts = list(category_data.values())
        labels = [c.replace("_", " ").title() for c in categories]

        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=counts,
                hole=0.35,
                textinfo="label+percent",
            )
        ])
        fig.update_layout(
            title=title,
            template="plotly_dark",
            height=450,
        )
        return fig

    # ── Timeline (Stacked Area) ───────────────────────────────────────────

    def timeline_chart(
        self, timeline: list[dict[str, Any]], title: str = "Threat Activity Over Time"
    ) -> Any:
        """
        Create a stacked area chart of threat activity by category over time.

        Args:
            timeline: List of {"date": "2024-11-10", "data_breach": 3, ...}
        """
        import plotly.graph_objects as go

        if not timeline:
            return self._empty_figure("No timeline data available")

        dates = [entry["date"] for entry in timeline]
        # Collect all categories present
        all_cats: set[str] = set()
        for entry in timeline:
            all_cats.update(k for k in entry.keys() if k != "date")

        colors = [
            "#e74c3c", "#e67e22", "#f39c12", "#27ae60", "#3498db", "#9b59b6",
            "#1abc9c", "#34495e",
        ]

        fig = go.Figure()
        for i, cat in enumerate(sorted(all_cats)):
            values = [entry.get(cat, 0) for entry in timeline]
            fig.add_trace(go.Scatter(
                x=dates,
                y=values,
                name=cat.replace("_", " ").title(),
                mode="lines",
                stackgroup="one",
                line=dict(color=colors[i % len(colors)]),
            ))

        fig.update_layout(
            title=title,
            xaxis_title="Date",
            yaxis_title="Post Count",
            template="plotly_dark",
            height=450,
            legend=dict(orientation="h", y=-0.2),
        )
        return fig

    # ── CVE Severity Heatmap ──────────────────────────────────────────────

    def cve_severity_chart(
        self, cve_data: list[dict[str, Any]], title: str = "Top CVEs by Severity"
    ) -> Any:
        """
        Create a horizontal bar chart of top CVEs colored by severity.

        Args:
            cve_data: List of {"cve_id": str, "mention_count": int,
                      "cvss_score": float, "severity": str}
        """
        import plotly.graph_objects as go

        if not cve_data:
            return self._empty_figure("No CVE data available")

        severity_colors = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#e67e22",
            "MEDIUM": "#f39c12",
            "LOW": "#27ae60",
            "NONE": "#95a5a6",
            "UNKNOWN": "#bdc3c7",
        }

        cves = [d["cve_id"] for d in cve_data]
        counts = [d["mention_count"] for d in cve_data]
        colors = [severity_colors.get(d.get("severity", "UNKNOWN"), "#bdc3c7") for d in cve_data]
        hover_text = [
            f"{d['cve_id']}<br>CVSS: {d.get('cvss_score', 'N/A')}<br>"
            f"Severity: {d.get('severity', 'N/A')}<br>Mentions: {d['mention_count']}"
            for d in cve_data
        ]

        fig = go.Figure(data=[
            go.Bar(
                y=cves,
                x=counts,
                orientation="h",
                marker_color=colors,
                text=counts,
                textposition="auto",
                hovertext=hover_text,
                hoverinfo="text",
            )
        ])
        fig.update_layout(
            title=title,
            xaxis_title="Mentions",
            yaxis_title="CVE ID",
            template="plotly_dark",
            height=max(350, len(cves) * 35),
            yaxis=dict(autorange="reversed"),
        )
        return fig

    # ── IOC Type Distribution ─────────────────────────────────────────────

    def ioc_distribution_chart(
        self, ioc_counts: dict[str, int], title: str = "IOC Type Distribution"
    ) -> Any:
        """Create a bar chart showing how many of each IOC type were extracted."""
        import plotly.graph_objects as go

        types = list(ioc_counts.keys())
        counts = list(ioc_counts.values())
        labels = [t.replace("_", " ").upper() for t in types]

        fig = go.Figure(data=[
            go.Bar(
                x=labels,
                y=counts,
                marker_color="#3498db",
                text=counts,
                textposition="auto",
            )
        ])
        fig.update_layout(
            title=title,
            xaxis_title="IOC Type",
            yaxis_title="Count",
            template="plotly_dark",
            height=400,
        )
        return fig

    # ── Word Cloud ────────────────────────────────────────────────────────

    def word_cloud(
        self,
        keywords: list[dict[str, Any]],
        title: str = "Trending Keywords",
        max_words: int = 100,
    ) -> Path:
        """
        Generate a word cloud image from trending keywords.

        Args:
            keywords: List of {"keyword": str, "count": int}

        Returns:
            Path to the saved PNG image.
        """
        from wordcloud import WordCloud
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        if not keywords:
            logger.warning("No keywords for word cloud")
            # Create an empty placeholder
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.text(0.5, 0.5, "No Data Available", ha="center", va="center", fontsize=20)
            ax.set_axis_off()
            out = self._chart_dir / f"{title.lower().replace(' ', '_')}.png"
            fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
            plt.close(fig)
            return out

        word_freq = {kw["keyword"]: kw["count"] for kw in keywords}

        wc = WordCloud(
            width=1200,
            height=600,
            background_color="#1a1a2e",
            colormap="plasma",
            max_words=max_words,
            prefer_horizontal=0.7,
        ).generate_from_frequencies(word_freq)

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.imshow(wc, interpolation="bilinear")
        ax.set_axis_off()
        ax.set_title(title, color="white", fontsize=16, pad=10)
        fig.patch.set_facecolor("#1a1a2e")

        out = self._chart_dir / f"{title.lower().replace(' ', '_')}.png"
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
        plt.close(fig)

        logger.info("Word cloud saved: %s", out)
        return out

    # ── Save helpers ──────────────────────────────────────────────────────

    def save_chart(self, fig: Any, filename: str, as_html: bool = True) -> Path:
        """
        Save a Plotly figure to disk.

        Args:
            fig:      Plotly Figure.
            filename: Output filename (with extension).
            as_html:  If True, save as interactive HTML. If False, save as PNG.

        Returns:
            Path to the saved file.
        """
        out_path = self._chart_dir / filename

        if as_html:
            fig.write_html(str(out_path), include_plotlyjs="cdn")
        else:
            try:
                fig.write_image(str(out_path), engine="kaleido")
            except Exception as exc:
                logger.warning("Kaleido export failed, falling back to HTML: %s", exc)
                out_path = out_path.with_suffix(".html")
                fig.write_html(str(out_path), include_plotlyjs="cdn")

        logger.info("Chart saved: %s", out_path)
        return out_path

    def _empty_figure(self, message: str = "No data") -> Any:
        """Create a placeholder figure for empty data."""
        import plotly.graph_objects as go
        fig = go.Figure()
        fig.add_annotation(text=message, x=0.5, y=0.5, showarrow=False, font_size=18)
        fig.update_layout(template="plotly_dark", height=300)
        return fig
