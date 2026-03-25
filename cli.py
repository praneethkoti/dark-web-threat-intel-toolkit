# -*- coding: utf-8 -*-
"""
CLI & Orchestration — unified command-line interface.

Exposes every module through Click commands with colorized output
via Rich.

Usage::

    python cli.py scrape --source fixtures --limit 50
    python cli.py process --input data/raw
    python cli.py classify --model keyword --export-mitre
    python cli.py analyze --period 30d --output report
    python cli.py export --format stix --output data/exports/
    python cli.py summarize --mode executive --period 24h
    python cli.py dashboard
    python cli.py full-pipeline
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows terminals that default to cp1252,
# so emoji in help text don't raise UnicodeEncodeError.
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import settings, setup_logging

console = Console()

# ── Shared options ────────────────────────────────────────────────────────────

@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.option("--dry-run", is_flag=True, help="Show what would be done without executing.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, dry_run: bool) -> None:
    """🛡️  Dark Web Threat Intelligence Toolkit — CLI"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run
    level = "DEBUG" if verbose else "INFO"
    setup_logging("toolkit")
    if verbose:
        import logging
        logging.getLogger("toolkit").setLevel(logging.DEBUG)


# ── Scrape command ────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--source", "-s",
    type=click.Choice(["fixtures", "pastes", "feeds", "nvd", "otx", "urlhaus", "bazaar", "all"]),
    default="fixtures",
    help="Data source to scrape.",
)
@click.option("--limit", "-l", type=int, default=50, help="Max items to collect.")
@click.option("--cve-year", type=int, default=None, help="CVE year filter (NVD only).")
@click.option("--cve-id", type=str, default=None, help="Specific CVE ID to fetch.")
@click.option("--save/--no-save", default=True, help="Save raw data to data/raw/.")
@click.pass_context
def scrape(ctx: click.Context, source: str, limit: int, cve_year: int | None,
           cve_id: str | None, save: bool) -> None:
    """🕷️  Scrape threat data from configured sources."""
    from scraper import PasteScraper, FeedScraper, SimulatedMarketScraper

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would scrape source={source}, limit={limit}")
        return

    all_items = []

    with console.status(f"[bold cyan]Scraping {source}..."):
        if source in ("fixtures", "all"):
            ps = PasteScraper()
            ms = SimulatedMarketScraper()
            items = ps.scrape(source="fixture") + ms.scrape(fixture="all")
            all_items.extend(items)
            if save and items:
                ps.save_raw(items, "fixtures_pastes")
                ms.save_raw(
                    [i for i in items if i.source_name.startswith("simulated")],
                    "fixtures_market",
                )

        if source in ("pastes", "all"):
            ps = PasteScraper()
            items = ps.scrape(source="live", limit=limit)
            all_items.extend(items)
            if save and items:
                ps.save_raw(items, "live_pastes")

        if source in ("feeds", "nvd", "otx", "urlhaus", "bazaar", "all"):
            fs = FeedScraper()
            feed_map = {
                "feeds": "all", "nvd": "nvd", "otx": "otx",
                "urlhaus": "urlhaus", "bazaar": "bazaar", "all": "all",
            }
            feed_name = feed_map.get(source, "all")
            kwargs = {"feed": feed_name, "limit": limit}
            if cve_year:
                kwargs["cve_year"] = cve_year
            if cve_id:
                kwargs["cve_id"] = cve_id
            items = fs.scrape(**kwargs)
            all_items.extend(items)
            if save and items:
                fs.save_raw(items, f"feed_{feed_name}")

    # ── Summary table ─────────────────────────────────────────────────
    table = Table(title="Scrape Results", show_lines=True)
    table.add_column("Source", style="cyan")
    table.add_column("Items", style="green", justify="right")

    source_counts: dict[str, int] = {}
    for item in all_items:
        src = item.source_name
        source_counts[src] = source_counts.get(src, 0) + 1

    for src, count in sorted(source_counts.items()):
        table.add_row(src, str(count))
    table.add_row("[bold]Total", f"[bold]{len(all_items)}")

    console.print(table)


# ── Process command ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--input", "-i", "input_dir", type=str, default="data/raw",
              help="Directory containing raw JSON files.")
@click.option("--skip-enrichment", is_flag=True, help="Skip NVD CVE enrichment.")
@click.option("--skip-ner", is_flag=True, help="Skip spaCy NER (regex only).")
@click.pass_context
def process(ctx: click.Context, input_dir: str, skip_enrichment: bool, skip_ner: bool) -> None:
    """⚙️  Run the data processing pipeline (clean → extract → enrich → store)."""
    from pipeline import Pipeline

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would process files in {input_dir}")
        return

    with console.status("[bold cyan]Running pipeline..."):
        pipe = Pipeline(skip_enrichment=skip_enrichment, use_ner=not skip_ner)
        stats = pipe.run_from_files(input_dir)
        pipe.close()

    table = Table(title="Pipeline Results", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")
    for key, val in stats.to_dict().items():
        table.add_row(key.replace("_", " ").title(), str(val))

    console.print(table)


# ── Classify command ──────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--model", "-m",
    type=click.Choice(["keyword", "ml", "bert", "all"]),
    default="keyword",
    help="Classification model to use.",
)
@click.option("--input-filter", type=click.Choice(["unclassified", "all"]),
              default="unclassified", help="Which posts to classify.")
@click.option("--export-mitre", is_flag=True, help="Enrich with MITRE ATT&CK techniques.")
@click.option("--train-ml", is_flag=True, help="Train ML models on synthetic data first.")
@click.option("--limit", "-l", type=int, default=500, help="Max posts to classify.")
@click.pass_context
def classify(ctx: click.Context, model: str, input_filter: str, export_mitre: bool,
             train_ml: bool, limit: int) -> None:
    """🏷️  Classify posts by threat category."""
    from pipeline.db_loader import DatabaseLoader
    from classifier.keyword_classifier import KeywordClassifier
    from classifier.mitre_mapper import MitreMapper

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would classify with model={model}")
        return

    db = DatabaseLoader()
    db.init_schema()

    # Get posts
    if input_filter == "unclassified":
        posts = db.get_unclassified_posts(limit=limit)
    else:
        posts = db.get_all_posts(limit=limit)

    if not posts:
        console.print("[yellow]No posts to classify.[/]")
        return

    mapper = MitreMapper() if export_mitre else None
    classified = 0
    category_counts: dict[str, int] = {}

    with console.status(f"[bold cyan]Classifying {len(posts)} posts with {model}..."):
        if model in ("keyword", "all"):
            clf = KeywordClassifier()
            for post in posts:
                result = clf.classify(post["content"])
                if mapper:
                    result = mapper.enrich_classification(result)
                db.insert_classification(
                    post_id=post["id"],
                    category=result["category"],
                    model_used="keyword",
                    confidence=result["confidence"],
                    mitre_techniques=result.get("mitre_technique_ids"),
                )
                cat = result["category"]
                category_counts[cat] = category_counts.get(cat, 0) + 1
                classified += 1

        if model in ("ml", "all") or train_ml:
            from classifier.ml_classifier import MLClassifier
            from classifier.synthetic_data_generator import generate_synthetic_data

            ml_clf = MLClassifier()
            if train_ml or not ml_clf.is_trained:
                console.print("[cyan]Training ML models on synthetic data...[/]")
                synth = generate_synthetic_data(num_samples=2500)
                texts = [s["content"] for s in synth]
                labels = [s["category"] for s in synth]
                results = ml_clf.train(texts, labels, tune=False)
                for name, res in results.items():
                    console.print(f"  {name}: accuracy={res['accuracy']:.4f}")

            if model in ("ml", "all"):
                for post in posts:
                    result = ml_clf.classify(post["content"])
                    if mapper:
                        result = mapper.enrich_classification(result)
                    db.insert_classification(
                        post_id=post["id"],
                        category=result["category"],
                        model_used=result.get("model", "ml"),
                        confidence=result["confidence"],
                        mitre_techniques=result.get("mitre_technique_ids"),
                    )
                    classified += 1

        if model in ("bert", "all"):
            try:
                from classifier.bert_classifier import TransformerClassifier
                t_clf = TransformerClassifier()
                for post in posts:
                    result = t_clf.classify(post["content"])
                    if mapper:
                        result = mapper.enrich_classification(result)
                    db.insert_classification(
                        post_id=post["id"],
                        category=result["category"],
                        model_used="zero_shot",
                        confidence=result["confidence"],
                        mitre_techniques=result.get("mitre_technique_ids"),
                    )
                    classified += 1
            except ImportError:
                console.print("[red]transformers not installed. Skipping BERT.[/]")

    db.close()

    # Summary
    table = Table(title="Classification Results", show_lines=True)
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green", justify="right")
    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        table.add_row(cat.replace("_", " ").title(), str(count))
    table.add_row("[bold]Total Classified", f"[bold]{classified}")
    console.print(table)


# ── Analyze command ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--period", "-p", type=str, default="30d", help="Analysis time window.")
@click.option("--output", "-o", type=click.Choice(["report", "charts", "both"]),
              default="both", help="Output type.")
@click.option("--format", "-f", "report_format", type=click.Choice(["markdown", "html", "both"]),
              default="both", help="Report format.")
@click.pass_context
def analyze(ctx: click.Context, period: str, output: str, report_format: str) -> None:
    """📈  Analyze trends, detect anomalies, generate reports."""
    from pipeline.db_loader import DatabaseLoader
    from analysis.trend_analyzer import TrendAnalyzer
    from analysis.anomaly_detector import AnomalyDetector
    from analysis.visualizer import Visualizer
    from analysis.report_generator import ReportGenerator

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would analyze period={period}")
        return

    db = DatabaseLoader()
    db.init_schema()
    analyzer = TrendAnalyzer(db)
    detector = AnomalyDetector(db)

    with console.status("[bold cyan]Analyzing threat data..."):
        stats = analyzer.get_summary_stats()
        cat_dist = analyzer.get_category_distribution(period)
        top_cves = analyzer.get_top_cves()
        keywords = analyzer.get_trending_keywords(period)
        ioc_dist = analyzer.get_ioc_distribution()
        anomalies = detector.detect(window_days=int(period.replace("d", "").replace("h", "")))
        actors = analyzer.get_threat_actor_patterns()

    # Print summary
    console.print(Panel(
        f"Posts: {stats['total_posts']} | IOCs: {stats['total_entities']} | "
        f"CVEs enriched: {stats['cve_enrichments_count']} | "
        f"Anomalies: {len(anomalies)}",
        title="Analysis Summary",
        style="cyan",
    ))

    if keywords:
        kw_str = ", ".join(f"{k['keyword']}({k['count']})" for k in keywords[:15])
        console.print(f"\n[bold]Trending Keywords:[/] {kw_str}")

    if anomalies:
        console.print(f"\n[bold red]⚠ {len(anomalies)} anomalous spikes detected![/]")

    # Generate outputs
    report_args = dict(
        summary_stats=stats,
        category_dist=cat_dist,
        top_cves=top_cves,
        trending_keywords=keywords,
        ioc_dist=ioc_dist,
        anomalies=anomalies,
        actor_patterns=actors,
    )

    if output in ("charts", "both"):
        viz = Visualizer()
        if cat_dist["categories"]:
            viz.save_chart(viz.category_bar_chart(cat_dist["categories"]), "category_bar.html")
            viz.save_chart(viz.category_pie_chart(cat_dist["categories"]), "category_pie.html")
        if top_cves:
            viz.save_chart(viz.cve_severity_chart(top_cves), "cve_severity.html")
        if ioc_dist:
            viz.save_chart(viz.ioc_distribution_chart(ioc_dist), "ioc_distribution.html")
        if keywords:
            viz.word_cloud(keywords, "trending_keywords")
        console.print("[green]Charts saved to data/reports/charts/[/]")

    if output in ("report", "both"):
        gen = ReportGenerator()
        if report_format in ("markdown", "both"):
            md = gen.generate_markdown(**report_args)
            console.print(f"[green]Markdown report: {md}[/]")
        if report_format in ("html", "both"):
            html = gen.generate_html(**report_args)
            console.print(f"[green]HTML report: {html}[/]")

    db.close()


# ── Export command ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--format", "-f", "export_format",
              type=click.Choice(["stix", "csv", "misp", "all"]),
              default="all", help="Export format.")
@click.option("--output", "-o", type=str, default="data/exports", help="Output directory.")
@click.option("--ioc-type", type=str, default=None, help="Filter CSV export by IOC type.")
@click.pass_context
def export(ctx: click.Context, export_format: str, output: str, ioc_type: str | None) -> None:
    """📦  Export IOCs in industry-standard formats (STIX, CSV, MISP)."""
    from pipeline.db_loader import DatabaseLoader
    from export.stix_exporter import StixExporter
    from export.csv_exporter import CsvExporter
    from export.misp_exporter import MispExporter

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would export format={export_format}")
        return

    db = DatabaseLoader()
    db.init_schema()
    entities = db.get_entities(entity_type=ioc_type, limit=10000)
    cves = db.get_cve_enrichments()
    classifications = db.get_classifications(limit=5000)

    if not entities:
        console.print("[yellow]No entities to export. Run the pipeline first.[/]")
        db.close()
        return

    paths: list[str] = []

    with console.status("[bold cyan]Exporting..."):
        if export_format in ("stix", "all"):
            exp = StixExporter()
            exp._output_dir = Path(output)
            p = exp.export(entities, cves, classifications)
            paths.append(str(p))

        if export_format in ("csv", "all"):
            exp = CsvExporter()
            exp._output_dir = Path(output)
            csv_paths = exp.export_all(entities, classifications, cves)
            paths.extend(str(p) for p in csv_paths)

        if export_format in ("misp", "all"):
            exp = MispExporter()
            exp._output_dir = Path(output)
            p = exp.export(entities, classifications)
            paths.append(str(p))

    db.close()

    table = Table(title="Exported Files", show_lines=True)
    table.add_column("File", style="green")
    for p in paths:
        table.add_row(p)
    table.add_row(f"[bold]Total: {len(paths)} files")
    console.print(table)


# ── Summarize command ─────────────────────────────────────────────────────────

@cli.command()
@click.option("--mode", "-m", type=click.Choice(["executive", "technical", "ioc_bulletin"]),
              default="executive", help="Summary style.")
@click.option("--period", "-p", type=str, default="24h", help="Time period to summarize.")
@click.option("--backend", "-b", type=click.Choice(["openai", "anthropic", "local"]),
              default=None, help="LLM backend (default from config).")
@click.option("--post-ids", type=str, default=None,
              help="Comma-separated post IDs to summarize specifically.")
@click.pass_context
def summarize(ctx: click.Context, mode: str, period: str, backend: str | None,
              post_ids: str | None) -> None:
    """🤖  Generate AI-powered threat intelligence summaries."""
    from pipeline.db_loader import DatabaseLoader
    from analysis.trend_analyzer import TrendAnalyzer
    from ai_summarizer import ThreatSummarizer

    if ctx.obj.get("dry_run"):
        console.print(f"[yellow]DRY RUN:[/] Would summarize mode={mode}, backend={backend}")
        return

    db = DatabaseLoader()
    db.init_schema()
    analyzer = TrendAnalyzer(db)

    try:
        summarizer = ThreatSummarizer(backend)
    except Exception as exc:
        console.print(f"[red]Failed to initialize summarizer: {exc}[/]")
        db.close()
        return

    with console.status(f"[bold cyan]Generating {mode} summary via {summarizer.backend_name}..."):
        if post_ids:
            ids = [int(x.strip()) for x in post_ids.split(",")]
            classifications = db.get_classifications(limit=5000)
            selected = [c for c in classifications if c.get("post_id") in ids]
            result = summarizer.summarize_posts(selected, mode=mode, time_period=period)
        else:
            stats = analyzer.get_summary_stats()
            cat_dist = stats.get("classification_distribution", {})
            top_cves = analyzer.get_top_cves(top_n=5)

            cat_str = ", ".join(f"{k}: {v}" for k, v in cat_dist.items()) or "N/A"
            cve_str = "; ".join(
                f"{c['cve_id']} (CVSS {c.get('cvss_score', 'N/A')})" for c in top_cves
            ) or "None"
            ioc_dist = stats.get("entity_distribution", {})
            ioc_str = ", ".join(f"{v} {k}" for k, v in ioc_dist.items()) or "N/A"

            result = summarizer.summarize(
                mode=mode, time_period=period,
                total_posts=str(stats["total_posts"]),
                category_breakdown=cat_str,
                critical_cves=cve_str,
                ioc_summary=ioc_str,
                trends="See analysis output",
                cve_details=cve_str,
                mitre_techniques="See classification output",
                ioc_details=ioc_str,
                ioc_data=ioc_str,
                anomalies="See anomaly detection",
                categories=cat_str,
            )

    db.close()

    console.print(Panel(result, title=f"{mode.title()} Summary", style="green"))
    console.print(f"\n[dim]Generated by {summarizer.backend_name} | {len(result)} chars[/]")


# ── Dashboard command ─────────────────────────────────────────────────────────

@cli.command()
@click.option("--port", type=int, default=None, help="Port number (default from config).")
@click.pass_context
def dashboard(ctx: click.Context, port: int | None) -> None:
    """🖥️  Launch the Streamlit threat intelligence dashboard."""
    import subprocess

    port = port or settings.get("dashboard.port", 8501)
    app_path = PROJECT_ROOT / "dashboard" / "app.py"

    console.print(f"[bold cyan]Launching dashboard on port {port}...[/]")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", str(app_path),
        "--server.port", str(port),
        "--server.headless", "true",
    ])


# ── Full Pipeline command ─────────────────────────────────────────────────────

@cli.command("full-pipeline")
@click.option("--source", "-s", type=str, default="fixtures", help="Scrape source.")
@click.option("--skip-enrichment", is_flag=True, help="Skip NVD enrichment.")
@click.option("--skip-export", is_flag=True, help="Skip IOC export.")
@click.option("--skip-report", is_flag=True, help="Skip report generation.")
@click.pass_context
def full_pipeline(ctx: click.Context, source: str, skip_enrichment: bool,
                  skip_export: bool, skip_report: bool) -> None:
    """🚀  Run the complete pipeline: scrape → process → classify → analyze → export."""
    console.print(Panel("[bold]Full Pipeline Execution[/]", style="cyan"))

    # Step 1: Scrape
    console.print("\n[bold cyan]Step 1/5:[/] Scraping...")
    ctx.invoke(scrape, source=source, limit=100, save=True)

    # Step 2: Process
    console.print("\n[bold cyan]Step 2/5:[/] Processing pipeline...")
    ctx.invoke(process, input_dir="data/raw", skip_enrichment=skip_enrichment, skip_ner=True)

    # Step 3: Classify
    console.print("\n[bold cyan]Step 3/5:[/] Classifying...")
    ctx.invoke(classify, model="keyword", input_filter="unclassified", export_mitre=True)

    # Step 4: Analyze + Report
    if not skip_report:
        console.print("\n[bold cyan]Step 4/5:[/] Analyzing and generating report...")
        ctx.invoke(analyze, period="30d", output="both", report_format="both")
    else:
        console.print("\n[bold cyan]Step 4/5:[/] Skipping report generation.")

    # Step 5: Export
    if not skip_export:
        console.print("\n[bold cyan]Step 5/5:[/] Exporting IOCs...")
        ctx.invoke(export, export_format="all")
    else:
        console.print("\n[bold cyan]Step 5/5:[/] Skipping export.")

    console.print(Panel("[bold green]✅ Full pipeline complete![/]", style="green"))


# ── Generate synthetic data command ───────────────────────────────────────────

@cli.command("generate-data")
@click.option("--count", "-n", type=int, default=2500, help="Number of samples.")
@click.option("--balanced/--imbalanced", default=True, help="Category distribution.")
@click.option("--seed", type=int, default=42, help="Random seed.")
@click.pass_context
def generate_data(ctx: click.Context, count: int, balanced: bool, seed: int) -> None:
    """🧪  Generate synthetic training data for classifiers."""
    from classifier.synthetic_data_generator import generate_synthetic_data

    with console.status(f"[bold cyan]Generating {count} synthetic samples..."):
        data = generate_synthetic_data(num_samples=count, balanced=balanced, seed=seed)

    cats: dict[str, int] = {}
    for item in data:
        cats[item["category"]] = cats.get(item["category"], 0) + 1

    table = Table(title="Synthetic Data Generated", show_lines=True)
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green", justify="right")
    for cat, c in sorted(cats.items()):
        table.add_row(cat.replace("_", " ").title(), str(c))
    table.add_row("[bold]Total", f"[bold]{len(data)}")
    console.print(table)


# ── Scheduler commands (delegated) ────────────────────────────────────────────

@cli.group()
def scheduler() -> None:
    """⏱️  Scheduler management commands."""
    pass


@scheduler.command("start")
def scheduler_start() -> None:
    """Start the scheduler daemon."""
    from scheduler.scheduler import ToolkitScheduler
    sched = ToolkitScheduler(blocking=True)
    sched.start()


@scheduler.command("status")
def scheduler_status() -> None:
    """Show next scheduled runs."""
    from scheduler.scheduler import ToolkitScheduler
    sched = ToolkitScheduler(blocking=False)
    sched.status()


@scheduler.command("run-now")
@click.option("--task", "-t", required=True, help="Task name to run.")
def scheduler_run_now(task: str) -> None:
    """Manually trigger a scheduled task."""
    from scheduler.scheduler import ToolkitScheduler
    sched = ToolkitScheduler(blocking=False)
    sched.run_now(task)


@scheduler.command("history")
@click.option("--limit", "-l", type=int, default=20, help="Number of runs to show.")
def scheduler_history(limit: int) -> None:
    """Show recent scheduler run history."""
    from scheduler.scheduler import ToolkitScheduler
    sched = ToolkitScheduler(blocking=False)
    runs = sched.get_run_history(limit=limit)
    if runs:
        table = Table(title="Scheduler Run History", show_lines=True)
        table.add_column("Job", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Started", style="dim")
        table.add_column("Records")
        table.add_column("Error", style="red")
        for run in runs:
            status_style = "green" if run["status"] == "success" else "red"
            table.add_row(
                run["job_name"],
                f"[{status_style}]{run['status']}[/]",
                run["started_at"][:19],
                str(run.get("records_affected", 0)),
                (run.get("error_message") or "")[:50],
            )
        console.print(table)
    else:
        console.print("[yellow]No scheduler runs recorded yet.[/]")


# ── DB Info command ───────────────────────────────────────────────────────────

@cli.command("db-info")
def db_info() -> None:
    """🗄️  Show database statistics."""
    from pipeline.db_loader import DatabaseLoader

    db = DatabaseLoader()
    db.init_schema()

    table = Table(title="Database Statistics", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")

    table.add_row("Total Posts", str(db.get_post_count()))
    table.add_row("Total Entities", str(db.get_entity_count()))

    entity_counts = db.get_entity_counts_by_type()
    for etype, count in sorted(entity_counts.items(), key=lambda x: x[1], reverse=True):
        table.add_row(f"  {etype}", str(count))

    class_dist = db.get_classification_distribution()
    table.add_row("Classifications", str(sum(class_dist.values())))
    for cat, count in sorted(class_dist.items(), key=lambda x: x[1], reverse=True):
        table.add_row(f"  {cat}", str(count))

    table.add_row("CVE Enrichments", str(len(db.get_cve_enrichments())))

    db.close()
    console.print(table)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
