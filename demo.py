"""
Dark Web Threat Intelligence Toolkit — End-to-End Demo

Runs the entire pipeline in one command and prints rich output.
Completes in under 30 seconds on a modern laptop.

Usage::

    python demo.py              # full run
    python demo.py --dry-run    # print steps without executing
    python demo.py --no-dashboard  # skip the "launch dashboard?" prompt

Steps:
    1. Banner
    2. Generate synthetic data
    3. Scrape all fixtures (Paste + SimulatedMarket + Selenium)
    4. Full pipeline  (clean → extract → enrich → store)
    5. Classify       (keyword + MITRE mapping)
    6. Trend analysis + anomaly detection
    7. Generate Markdown + HTML report
    8. Export IOCs as STIX + CSV + MISP
    9. Final summary panel
   10. Offer to launch Streamlit dashboard
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is on the path regardless of CWD
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich import box
import io

# Force UTF-8 so emoji/Unicode in Rich output don't crash on Windows cp1252 terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console()

AUTHOR = "Sai Praneeth Koti"
EMAIL  = "praneeth01koti@gmail.com"
ROLE   = "Cybersecurity Researcher · Python Developer"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _step(n: int, label: str) -> None:
    console.print(f"\n[bold cyan]Step {n}[/] [white]{label}[/]")


def _ok(msg: str) -> None:
    console.print(f"  [green]✓[/] {msg}")


def _skip(msg: str) -> None:
    console.print(f"  [yellow]↷[/] [dim]{msg}[/]")


# ── Step implementations ──────────────────────────────────────────────────────

def step_banner() -> None:
    console.print(
        Panel(
            f"[bold white]Dark Web Threat Intelligence Toolkit[/]\n"
            f"[dim]{AUTHOR} · {EMAIL}[/]\n"
            f"[dim]{ROLE}[/]",
            title="[bold cyan]🛡️  Demo",
            subtitle="[dim]github.com/praneethkoti/dark-web-threat-intel-toolkit[/]",
            border_style="cyan",
            padding=(1, 4),
        )
    )


def step_synthetic(dry_run: bool) -> list[dict]:
    _step(2, "Generating synthetic training data  (50 samples)")
    if dry_run:
        _skip("dry-run — skipped")
        return []
    from classifier.synthetic_data_generator import generate_synthetic_data
    data = generate_synthetic_data(
        num_samples=50, balanced=True, seed=42,
        output_path=PROJECT_ROOT / "data" / "demo_synthetic.json",
    )
    _ok(f"{len(data)} synthetic threat posts generated")
    return data


def step_scrape(dry_run: bool) -> list[dict]:
    _step(3, "Scraping fixtures  (Paste + SimulatedMarket + Selenium)")
    if dry_run:
        _skip("dry-run — skipped")
        return []

    from scraper.paste_scraper import PasteScraper
    from scraper.simulated_market_scraper import SimulatedMarketScraper
    from scraper.selenium_scraper import SeleniumScraper

    items: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        t = progress.add_task("Scraping paste fixtures…", total=None)
        paste_items = PasteScraper().scrape(source="fixture")
        items.extend([i.__dict__ if hasattr(i, "__dict__") else i for i in paste_items])
        _ok(f"PasteScraper: {len(paste_items)} items")

        progress.update(t, description="Scraping simulated market fixtures…")
        market_items = SimulatedMarketScraper().scrape(source="all")
        items.extend([i.__dict__ if hasattr(i, "__dict__") else i for i in market_items])
        _ok(f"SimulatedMarketScraper: {len(market_items)} items")

        progress.update(t, description="Scraping via Selenium (headless Chrome)…")
        try:
            sel_items = SeleniumScraper().scrape(source="fixture")
            items.extend([i.__dict__ if hasattr(i, "__dict__") else i for i in sel_items])
            _ok(f"SeleniumScraper: {len(sel_items)} items")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/]  SeleniumScraper skipped ({exc})")

    _ok(f"Total scraped: [bold]{len(items)}[/] items")
    return items


def step_pipeline(items: list[dict], dry_run: bool) -> tuple:
    _step(4, "Running full pipeline  (clean → extract → enrich → store)")
    if dry_run:
        _skip("dry-run — skipped")
        return None, None

    from pipeline import Pipeline
    from pipeline.db_loader import DatabaseLoader

    db = DatabaseLoader()
    db.init_schema()

    # skip_enrichment=True avoids live NVD API calls in the demo for speed
    pipeline = Pipeline(db=db, skip_enrichment=True, use_ner=False)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Processing…", total=None)
        stats = pipeline.run(items, source_type="demo")

    _ok(f"Input: {stats.items_input}  |  Stored: {stats.items_stored}  "
        f"|  Entities: {stats.entities_extracted}  "
        f"|  Dupes skipped: {stats.duplicates_skipped}")
    return db, stats


def step_classify(db, dry_run: bool) -> int:
    _step(5, "Classifying posts  (keyword scorer + MITRE ATT&CK mapper)")
    if dry_run or db is None:
        _skip("dry-run — skipped")
        return 0

    from classifier.keyword_classifier import KeywordClassifier
    from classifier.mitre_mapper import MitreMapper

    posts = db.get_unclassified_posts(limit=1000)
    if not posts:
        _ok("No unclassified posts — already classified")
        return 0

    clf = KeywordClassifier()
    mapper = MitreMapper()
    classified = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Classifying {len(posts)} posts…", total=None)
        for post in posts:
            result = clf.classify(post["content"])
            result = mapper.enrich_classification(result)
            db.insert_classification(
                post_id=post["id"],
                category=result["category"],
                model_used="keyword",
                confidence=result["confidence"],
                mitre_techniques=result.get("mitre_technique_ids"),
            )
            classified += 1

    _ok(f"Classified [bold]{classified}[/] posts with MITRE ATT&CK enrichment")
    return classified


def step_analyze(db, dry_run: bool) -> tuple:
    _step(6, "Running trend analysis + anomaly detection")
    if dry_run or db is None:
        _skip("dry-run — skipped")
        return None, None, None, None, None

    from analysis.trend_analyzer import TrendAnalyzer
    from analysis.anomaly_detector import AnomalyDetector

    analyzer = TrendAnalyzer(db)
    detector = AnomalyDetector(db)

    summary       = analyzer.get_summary_stats()
    category_dist = analyzer.get_category_distribution(window="30d")
    top_cves      = analyzer.get_top_cves()
    keywords      = analyzer.get_trending_keywords(window="30d")
    anomalies     = detector.detect(window_days=90)

    _ok(f"Summary: {summary.get('total_posts', 0)} posts | "
        f"{summary.get('total_entities', 0)} IOCs | "
        f"{summary.get('total_cves', 0)} CVEs | "
        f"{len(anomalies)} anomalies detected")
    return summary, category_dist, top_cves, keywords, anomalies


def step_report(summary, category_dist, top_cves, keywords, anomalies, dry_run: bool) -> tuple:
    _step(7, "Generating reports  (Markdown + HTML)")
    if dry_run or summary is None:
        _skip("dry-run — skipped")
        return None, None

    from analysis.report_generator import ReportGenerator

    gen = ReportGenerator()
    md_path   = gen.generate_markdown(
        summary_stats=summary,
        category_dist=category_dist,
        top_cves=top_cves,
        trending_keywords=keywords,
        anomalies=anomalies,
        filename="demo_threat_report",
    )
    html_path = gen.generate_html(
        summary_stats=summary,
        category_dist=category_dist,
        top_cves=top_cves,
        trending_keywords=keywords,
        anomalies=anomalies,
        filename="demo_threat_report",
    )
    _ok(f"Markdown → {md_path.relative_to(PROJECT_ROOT)}")
    _ok(f"HTML     → {html_path.relative_to(PROJECT_ROOT)}")
    return md_path, html_path


def step_export(db, dry_run: bool) -> tuple:
    _step(8, "Exporting IOCs  (STIX 2.1 + CSV + MISP)")
    if dry_run or db is None:
        _skip("dry-run — skipped")
        return None, None, None

    from export.stix_exporter import StixExporter
    from export.csv_exporter import CsvExporter
    from export.misp_exporter import MispExporter

    entities        = db.get_entities(limit=500)
    classifications = db.get_classifications(limit=500)
    cve_enrichments = db.get_cve_enrichments()

    stix_path  = None
    csv_path   = None
    misp_path  = None

    # STIX
    try:
        stix_exp   = StixExporter()
        bundle     = stix_exp.create_bundle(
            entities=entities,
            cve_enrichments=cve_enrichments,
            classifications=classifications,
        )
        stix_path  = stix_exp.save(bundle, filename="demo_stix_bundle.json")
        _ok(f"STIX bundle → {stix_path.relative_to(PROJECT_ROOT)}  "
            f"({len(bundle.objects)} objects)")
    except Exception as exc:
        console.print(f"  [yellow]⚠[/]  STIX export skipped: {exc}")

    # CSV
    try:
        csv_exp  = CsvExporter()
        csv_path = csv_exp.export_entities(entities, filename="demo_iocs.csv")
        _ok(f"CSV IOCs    → {csv_path.relative_to(PROJECT_ROOT)}  "
            f"({len(entities)} rows)")
    except Exception as exc:
        console.print(f"  [yellow]⚠[/]  CSV export skipped: {exc}")

    # MISP
    try:
        misp_exp  = MispExporter()
        event     = misp_exp.create_event(
            entities=entities,
            classifications=classifications,
            event_info="Dark Web Threat Intelligence Demo",
        )
        misp_path = misp_exp.save(event, filename="demo_misp_event.json")
        _ok(f"MISP event  → {misp_path.relative_to(PROJECT_ROOT)}")
    except Exception as exc:
        console.print(f"  [yellow]⚠[/]  MISP export skipped: {exc}")

    return stix_path, csv_path, misp_path


def step_summary(
    t0: float,
    pipeline_stats,
    classified: int,
    summary: dict | None,
    stix_path,
    csv_path,
    misp_path,
    md_path,
    html_path,
    dry_run: bool,
) -> None:
    elapsed = time.perf_counter() - t0
    console.print()
    console.print(Rule("[bold cyan]Demo Complete", style="cyan"))

    if dry_run:
        console.print(
            Panel(
                "[yellow]Dry-run mode — no data was written.[/]\n"
                "Remove [bold]--dry-run[/] to execute the full pipeline.",
                border_style="yellow",
            )
        )
        return

    # Numbers
    posts       = (summary or {}).get("total_posts", 0)
    iocs        = (summary or {}).get("total_entities", 0)
    cves        = (summary or {}).get("total_cves", 0)
    stored      = getattr(pipeline_stats, "items_stored", 0) if pipeline_stats else 0
    entities_ex = getattr(pipeline_stats, "entities_extracted", 0) if pipeline_stats else 0

    tbl = Table(box=box.ROUNDED, show_header=False, border_style="cyan", padding=(0, 2))
    tbl.add_column("Metric", style="bold white")
    tbl.add_column("Value",  style="bold green", justify="right")

    tbl.add_row("Posts stored",         str(stored))
    tbl.add_row("Posts in DB",          str(posts))
    tbl.add_row("Posts classified",     str(classified))
    tbl.add_row("Entities extracted",   str(entities_ex))
    tbl.add_row("IOCs in DB",           str(iocs))
    tbl.add_row("CVEs enriched",        str(cves))
    tbl.add_row("", "")
    tbl.add_row("Report (Markdown)",    str(md_path.relative_to(PROJECT_ROOT)) if md_path else "—")
    tbl.add_row("Report (HTML)",        str(html_path.relative_to(PROJECT_ROOT)) if html_path else "—")
    tbl.add_row("STIX bundle",          str(stix_path.relative_to(PROJECT_ROOT)) if stix_path else "—")
    tbl.add_row("IOC CSV",              str(csv_path.relative_to(PROJECT_ROOT)) if csv_path else "—")
    tbl.add_row("MISP event",           str(misp_path.relative_to(PROJECT_ROOT)) if misp_path else "—")
    tbl.add_row("", "")
    tbl.add_row("Total time",           f"[bold]{elapsed:.1f}s[/]")

    console.print(
        Panel(tbl, title="[bold cyan]Pipeline Summary", border_style="cyan", padding=(1, 2))
    )


def offer_dashboard(no_dashboard: bool) -> None:
    if no_dashboard:
        return
    console.print()
    try:
        answer = console.input("[bold cyan]Launch dashboard?[/] [dim]\\[Y/n][/] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if answer in ("", "y", "yes"):
        console.print("[cyan]Starting Streamlit dashboard...[/]  [dim](Ctrl+C to stop)[/]")
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "dashboard/app.py"],
            cwd=str(PROJECT_ROOT),
        )


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dark Web Threat Intelligence Toolkit — end-to-end demo"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print steps without executing")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="Skip the 'launch dashboard?' prompt at the end")
    args = parser.parse_args()

    t0 = time.perf_counter()

    step_banner()

    synthetic     = step_synthetic(args.dry_run)
    items         = step_scrape(args.dry_run)

    # Merge synthetic data as if it were scraped items so it flows through pipeline
    all_items = items + [
        {
            "source_name": "synthetic_demo",
            "content": d["content"],
            "url": "",
            "raw_html": "",
            "metadata": {"category": d["category"]},
            "scraped_at": d.get("timestamp", ""),
        }
        for d in synthetic
    ]

    db, pipeline_stats = step_pipeline(all_items, args.dry_run)
    classified         = step_classify(db, args.dry_run)
    summary, cat_dist, top_cves, keywords, anomalies = step_analyze(db, args.dry_run)
    md_path, html_path = step_report(summary, cat_dist, top_cves, keywords, anomalies, args.dry_run)
    stix_path, csv_path, misp_path = step_export(db, args.dry_run)

    if db is not None:
        db.close()

    step_summary(
        t0=t0,
        pipeline_stats=pipeline_stats,
        classified=classified,
        summary=summary,
        stix_path=stix_path,
        csv_path=csv_path,
        misp_path=misp_path,
        md_path=md_path,
        html_path=html_path,
        dry_run=args.dry_run,
    )

    offer_dashboard(args.no_dashboard)


if __name__ == "__main__":
    main()
