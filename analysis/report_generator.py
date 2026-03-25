"""
Auto-Report Generator.

Produces structured threat intelligence reports in two formats:
    - **Markdown** — GitHub-renderable, clean text.
    - **HTML** — styled, self-contained, shareable.

Reports include: executive summary, key findings, embedded charts,
top IOCs table, MITRE ATT&CK technique summary, and recommendations.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate threat intelligence reports from analysis data.

    Usage::

        gen = ReportGenerator()
        md_path = gen.generate_markdown(data)
        html_path = gen.generate_html(data)
    """

    def __init__(self) -> None:
        self._output_dir = PROJECT_ROOT / settings.get(
            "analysis.report_output_dir", "data/reports"
        )
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ── Markdown Report ───────────────────────────────────────────────────

    def generate_markdown(
        self,
        summary_stats: dict[str, Any],
        category_dist: dict[str, Any] | None = None,
        top_cves: list[dict[str, Any]] | None = None,
        trending_keywords: list[dict[str, Any]] | None = None,
        ioc_dist: dict[str, int] | None = None,
        anomalies: list[dict[str, Any]] | None = None,
        actor_patterns: list[dict[str, Any]] | None = None,
        filename: str | None = None,
    ) -> Path:
        """
        Generate a full Markdown threat intelligence report.

        Returns:
            Path to the saved .md file.
        """
        ts = datetime.now(timezone.utc)
        ts_str = ts.strftime("%Y-%m-%d %H:%M UTC")
        ts_file = ts.strftime("%Y%m%d_%H%M%S")

        if filename is None:
            filename = f"threat_report_{ts_file}.md"

        lines: list[str] = []

        # ── Header ────────────────────────────────────────────────────
        lines.append("# Dark Web Threat Intelligence Report")
        lines.append(f"\n**Generated:** {ts_str}")
        lines.append(f"**Report Period:** {category_dist.get('window', 'N/A') if category_dist else 'N/A'}")
        lines.append("")

        # ── Executive Summary ─────────────────────────────────────────
        lines.append("## Executive Summary")
        lines.append("")
        total_posts = summary_stats.get("total_posts", 0)
        total_entities = summary_stats.get("total_entities", 0)
        cat_dist = summary_stats.get("classification_distribution", {})
        top_cat = max(cat_dist, key=cat_dist.get) if cat_dist else "N/A"
        anomaly_count = len(anomalies) if anomalies else 0

        lines.append(
            f"This report summarizes threat intelligence collected from dark web sources. "
            f"A total of **{total_posts} posts** were analyzed, yielding "
            f"**{total_entities} indicators of compromise (IOCs)**. "
            f"The most prevalent threat category is **{top_cat.replace('_', ' ').title()}**"
            f"{f', and **{anomaly_count} anomalous spikes** were detected in threat activity.' if anomaly_count else '.'}"
        )
        lines.append("")

        # ── Key Findings ──────────────────────────────────────────────
        lines.append("## Key Findings")
        lines.append("")

        if cat_dist:
            lines.append("### Threat Category Distribution")
            lines.append("")
            lines.append("| Category | Count |")
            lines.append("|----------|-------|")
            for cat, count in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {cat.replace('_', ' ').title()} | {count} |")
            lines.append("")

        # ── Top CVEs ──────────────────────────────────────────────────
        if top_cves:
            lines.append("### Most Mentioned CVEs")
            lines.append("")
            lines.append("| CVE ID | Mentions | CVSS | Severity | Description |")
            lines.append("|--------|----------|------|----------|-------------|")
            for cve in top_cves[:15]:
                cvss = cve.get("cvss_score", "N/A")
                sev = cve.get("severity", "N/A")
                desc = cve.get("description", "")[:80]
                lines.append(
                    f"| {cve['cve_id']} | {cve['mention_count']} | {cvss} | {sev} | {desc} |"
                )
            lines.append("")

        # ── IOC Summary ───────────────────────────────────────────────
        if ioc_dist:
            lines.append("### IOC Type Distribution")
            lines.append("")
            lines.append("| IOC Type | Count |")
            lines.append("|----------|-------|")
            for ioc_type, count in sorted(ioc_dist.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {ioc_type.replace('_', ' ').upper()} | {count} |")
            lines.append("")

        # ── Trending Keywords ─────────────────────────────────────────
        if trending_keywords:
            lines.append("### Trending Keywords")
            lines.append("")
            top_kw = trending_keywords[:20]
            kw_str = ", ".join(f"**{kw['keyword']}** ({kw['count']})" for kw in top_kw)
            lines.append(kw_str)
            lines.append("")

        # ── Anomalies ─────────────────────────────────────────────────
        if anomalies:
            lines.append("### Anomalous Activity Spikes")
            lines.append("")
            lines.append("| Date | Category | Count | Z-Score / Deviation |")
            lines.append("|------|----------|-------|---------------------|")
            for a in anomalies[:10]:
                score = a.get("zscore", a.get("deviation", "N/A"))
                lines.append(
                    f"| {a['date']} | {a['category'].replace('_', ' ').title()} "
                    f"| {a['count']} | {score} |"
                )
            lines.append("")

        # ── Threat Actor Patterns ─────────────────────────────────────
        if actor_patterns:
            lines.append("### Threat Actor Patterns")
            lines.append("")
            lines.append("| Username | Posts | Unique Sources |")
            lines.append("|----------|-------|----------------|")
            for actor in actor_patterns[:10]:
                lines.append(
                    f"| {actor['username']} | {actor['post_count']} "
                    f"| {actor['unique_sources']} |"
                )
            lines.append("")

        # ── Recommendations ───────────────────────────────────────────
        lines.append("## Recommendations")
        lines.append("")
        lines.append("1. **Patch critical CVEs immediately** — prioritize any CVEs listed above with CRITICAL/HIGH severity.")
        lines.append("2. **Block extracted IOCs** — ingest IP addresses, domains, and file hashes into firewall/EDR/SIEM rules.")
        lines.append("3. **Monitor for anomalous activity** — investigate any flagged spikes in threat categories.")
        lines.append("4. **Track repeat threat actors** — usernames appearing across multiple sources may indicate organized operations.")
        lines.append("5. **Review MITRE ATT&CK mappings** — align detection rules with the techniques observed in classified threats.")
        lines.append("")

        # ── Footer ────────────────────────────────────────────────────
        lines.append("---")
        lines.append(f"*Report generated by Dark Web Threat Intelligence Toolkit — {ts_str}*")

        # Write to disk
        content = "\n".join(lines)
        out_path = self._output_dir / filename
        out_path.write_text(content, encoding="utf-8")
        logger.info("Markdown report saved: %s", out_path)
        return out_path

    # ── HTML Report ───────────────────────────────────────────────────────

    def generate_html(
        self,
        summary_stats: dict[str, Any],
        category_dist: dict[str, Any] | None = None,
        top_cves: list[dict[str, Any]] | None = None,
        trending_keywords: list[dict[str, Any]] | None = None,
        ioc_dist: dict[str, int] | None = None,
        anomalies: list[dict[str, Any]] | None = None,
        actor_patterns: list[dict[str, Any]] | None = None,
        chart_paths: dict[str, str] | None = None,
        filename: str | None = None,
    ) -> Path:
        """
        Generate a styled, self-contained HTML report.

        Args:
            chart_paths: Optional dict of {"chart_name": "relative/path.html"}
                         for embedding interactive charts.

        Returns:
            Path to the saved .html file.
        """
        ts = datetime.now(timezone.utc)
        ts_str = ts.strftime("%Y-%m-%d %H:%M UTC")
        ts_file = ts.strftime("%Y%m%d_%H%M%S")

        if filename is None:
            filename = f"threat_report_{ts_file}.html"

        cat_dist_data = summary_stats.get("classification_distribution", {})
        total_posts = summary_stats.get("total_posts", 0)
        total_entities = summary_stats.get("total_entities", 0)
        top_cat = max(cat_dist_data, key=cat_dist_data.get) if cat_dist_data else "N/A"

        # ── Build HTML ────────────────────────────────────────────────
        html_parts: list[str] = []
        html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Intelligence Report — {ts_str}</title>
<style>
  :root {{ --bg: #0f0f23; --card: #1a1a2e; --text: #e0e0e0; --accent: #3498db;
           --red: #e74c3c; --orange: #e67e22; --green: #27ae60; --border: #2d2d44; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
          color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1100px; margin: auto; }}
  h1 {{ color: #fff; border-bottom: 2px solid var(--accent); padding-bottom: .5rem; margin-bottom: 1rem; }}
  h2 {{ color: var(--accent); margin-top: 2rem; margin-bottom: .8rem; }}
  h3 {{ color: #bbb; margin-top: 1.5rem; margin-bottom: .5rem; }}
  .meta {{ color: #888; margin-bottom: 1.5rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                padding: 1.2rem; text-align: center; }}
  .stat-card .value {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat-card .label {{ color: #888; font-size: .85rem; margin-top: .3rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: var(--card); color: var(--accent); padding: .6rem .8rem; text-align: left;
        border-bottom: 2px solid var(--border); }}
  td {{ padding: .5rem .8rem; border-bottom: 1px solid var(--border); }}
  tr:hover {{ background: rgba(52, 152, 219, 0.05); }}
  .severity-critical {{ color: var(--red); font-weight: bold; }}
  .severity-high {{ color: var(--orange); font-weight: bold; }}
  .severity-medium {{ color: #f39c12; }}
  .severity-low {{ color: var(--green); }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .8rem; }}
  .badge-red {{ background: rgba(231,76,60,.2); color: var(--red); }}
  .badge-blue {{ background: rgba(52,152,219,.2); color: var(--accent); }}
  .keywords {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: .5rem 0; }}
  .kw {{ background: var(--card); border: 1px solid var(--border); padding: .3rem .6rem;
         border-radius: 4px; font-size: .85rem; }}
  .recommendations li {{ margin: .5rem 0; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #666; font-size: .85rem; }}
</style>
</head>
<body>
<h1>Dark Web Threat Intelligence Report</h1>
<div class="meta">Generated: {ts_str} | Period: {category_dist.get('window', 'N/A') if category_dist else 'N/A'}</div>
""")

        # Summary cards
        html_parts.append('<div class="summary-grid">')
        html_parts.append(f'<div class="stat-card"><div class="value">{total_posts}</div><div class="label">Posts Analyzed</div></div>')
        html_parts.append(f'<div class="stat-card"><div class="value">{total_entities}</div><div class="label">IOCs Extracted</div></div>')
        cat_count = len(cat_dist_data)
        html_parts.append(f'<div class="stat-card"><div class="value">{cat_count}</div><div class="label">Threat Categories</div></div>')
        cve_count = summary_stats.get("cve_enrichments_count", 0)
        html_parts.append(f'<div class="stat-card"><div class="value">{cve_count}</div><div class="label">CVEs Enriched</div></div>')
        html_parts.append('</div>')

        # Executive summary
        anomaly_count = len(anomalies) if anomalies else 0
        html_parts.append('<h2>Executive Summary</h2>')
        html_parts.append(
            f'<p>Analysis of <strong>{total_posts} posts</strong> yielded '
            f'<strong>{total_entities} IOCs</strong>. '
            f'The dominant threat category is <strong>{top_cat.replace("_", " ").title()}</strong>.'
            f'{f" <strong>{anomaly_count} anomalous spikes</strong> were detected." if anomaly_count else ""}</p>'
        )

        # Category distribution table
        if cat_dist_data:
            html_parts.append('<h2>Threat Category Distribution</h2>')
            html_parts.append('<table><tr><th>Category</th><th>Count</th></tr>')
            for cat, count in sorted(cat_dist_data.items(), key=lambda x: x[1], reverse=True):
                html_parts.append(f'<tr><td>{cat.replace("_", " ").title()}</td><td>{count}</td></tr>')
            html_parts.append('</table>')

        # Top CVEs
        if top_cves:
            html_parts.append('<h2>Top CVEs</h2>')
            html_parts.append('<table><tr><th>CVE ID</th><th>Mentions</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>')
            for cve in top_cves[:15]:
                sev = cve.get("severity", "N/A")
                sev_class = f"severity-{sev.lower()}" if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""
                desc = cve.get("description", "")[:100]
                html_parts.append(
                    f'<tr><td><strong>{cve["cve_id"]}</strong></td>'
                    f'<td>{cve["mention_count"]}</td>'
                    f'<td>{cve.get("cvss_score", "N/A")}</td>'
                    f'<td class="{sev_class}">{sev}</td>'
                    f'<td>{desc}</td></tr>'
                )
            html_parts.append('</table>')

        # IOC Distribution
        if ioc_dist:
            html_parts.append('<h2>IOC Type Distribution</h2>')
            html_parts.append('<table><tr><th>IOC Type</th><th>Count</th></tr>')
            for t, c in sorted(ioc_dist.items(), key=lambda x: x[1], reverse=True):
                html_parts.append(f'<tr><td>{t.replace("_", " ").upper()}</td><td>{c}</td></tr>')
            html_parts.append('</table>')

        # Trending keywords
        if trending_keywords:
            html_parts.append('<h2>Trending Keywords</h2>')
            html_parts.append('<div class="keywords">')
            for kw in trending_keywords[:25]:
                html_parts.append(f'<span class="kw">{kw["keyword"]} ({kw["count"]})</span>')
            html_parts.append('</div>')

        # Anomalies
        if anomalies:
            html_parts.append('<h2>Anomalous Activity Spikes</h2>')
            html_parts.append('<table><tr><th>Date</th><th>Category</th><th>Count</th><th>Score</th></tr>')
            for a in anomalies[:10]:
                score = a.get("zscore", a.get("deviation", "N/A"))
                html_parts.append(
                    f'<tr><td>{a["date"]}</td>'
                    f'<td>{a["category"].replace("_", " ").title()}</td>'
                    f'<td>{a["count"]}</td>'
                    f'<td><span class="badge badge-red">{score}</span></td></tr>'
                )
            html_parts.append('</table>')

        # Recommendations
        html_parts.append('<h2>Recommendations</h2>')
        html_parts.append('<ol class="recommendations">')
        html_parts.append('<li><strong>Patch critical CVEs immediately</strong> — prioritize CRITICAL/HIGH severity CVEs listed above.</li>')
        html_parts.append('<li><strong>Block extracted IOCs</strong> — ingest IPs, domains, and hashes into firewall/EDR/SIEM.</li>')
        html_parts.append('<li><strong>Monitor for anomalous spikes</strong> — investigate flagged activity increases.</li>')
        html_parts.append('<li><strong>Track repeat threat actors</strong> — cross-source username patterns may indicate organized groups.</li>')
        html_parts.append('<li><strong>Align detection with MITRE ATT&CK</strong> — map observed techniques to detection rules.</li>')
        html_parts.append('</ol>')

        html_parts.append(f'<footer>Report generated by Dark Web Threat Intelligence Toolkit — {ts_str}</footer>')
        html_parts.append('</body></html>')

        content = "\n".join(html_parts)
        out_path = self._output_dir / filename
        out_path.write_text(content, encoding="utf-8")
        logger.info("HTML report saved: %s", out_path)
        return out_path
