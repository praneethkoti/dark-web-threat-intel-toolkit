"""
Scheduler & Automation Engine.

Lightweight scheduler using APScheduler that:
    - Runs scrapers on a configurable schedule.
    - Auto-triggers the processing pipeline after each scrape.
    - Auto-triggers classification on new unclassified posts.
    - Generates a daily summary report at a configured time.
    - Logs all runs with timestamps and success/failure status.

Entry points::

    python scheduler.py start       — start the scheduler daemon
    python scheduler.py status      — show next scheduled runs
    python scheduler.py run-now --task scrape   — manually trigger a task
"""

from __future__ import annotations

import logging
import sys
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from rich.console import Console
from rich.table import Table

from config import settings, setup_logging, PROJECT_ROOT as PROJ_ROOT

logger = logging.getLogger(__name__)
console = Console()

# ── Job functions ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def job_scrape_pastes() -> dict[str, Any]:
    """
    Scrape paste sites and save raw data.

    Source is configurable via ``scheduler.jobs.scrape_pastes.source`` in
    settings.yaml. Defaults to ``"fixture"`` (local HTML, no network) so
    out-of-the-box demos stay fully offline. Flip to ``"live"`` or
    ``"all"`` for a real deployment.
    """
    from scraper import PasteScraper
    started = _now_iso()
    try:
        scraper = PasteScraper()
        source = settings.get("scheduler.jobs.scrape_pastes.source", "fixture")
        logger.debug("job_scrape_pastes: using source=%s", source)
        items = scraper.scrape(source=source)
        if items:
            scraper.save_raw(items)
        logger.info("job_scrape_pastes: collected %d items", len(items))
        _log_run("scrape_pastes", "success", started, len(items))
        return {"status": "success", "items": len(items)}
    except Exception as exc:
        logger.error("job_scrape_pastes failed: %s", exc)
        _log_run("scrape_pastes", "failure", started, 0, str(exc))
        return {"status": "failure", "error": str(exc)}


def job_scrape_feeds() -> dict[str, Any]:
    """
    Scrape threat intelligence feeds.

    Feed name and per-run limit are configurable via
    ``scheduler.jobs.scrape_feeds.feed`` and
    ``scheduler.jobs.scrape_feeds.limit`` in settings.yaml. Defaults
    preserve the original hardcoded behaviour (``feed="all"``,
    ``limit=25``).
    """
    from scraper import FeedScraper
    started = _now_iso()
    try:
        scraper = FeedScraper()
        feed = settings.get("scheduler.jobs.scrape_feeds.feed", "all")
        limit = settings.get("scheduler.jobs.scrape_feeds.limit", 25)
        logger.debug("job_scrape_feeds: using feed=%s, limit=%d", feed, limit)
        items = scraper.scrape(feed=feed, limit=limit)
        if items:
            scraper.save_raw(items)
        logger.info("job_scrape_feeds: collected %d items", len(items))
        _log_run("scrape_feeds", "success", started, len(items))
        return {"status": "success", "items": len(items)}
    except Exception as exc:
        logger.error("job_scrape_feeds failed: %s", exc)
        _log_run("scrape_feeds", "failure", started, 0, str(exc))
        return {"status": "failure", "error": str(exc)}


def job_process_pipeline() -> dict[str, Any]:
    """Run the processing pipeline on all raw JSON files."""
    from pipeline import Pipeline
    started = _now_iso()
    try:
        pipe = Pipeline(skip_enrichment=False, use_ner=False)
        stats = pipe.run_from_files("data/raw")
        pipe.close()
        logger.info("job_process_pipeline: %s", stats)
        _log_run("process_pipeline", "success", started, stats.items_stored)
        return {"status": "success", "stats": stats.to_dict()}
    except Exception as exc:
        logger.error("job_process_pipeline failed: %s", exc)
        _log_run("process_pipeline", "failure", started, 0, str(exc))
        return {"status": "failure", "error": str(exc)}


def job_classify_new() -> dict[str, Any]:
    """Classify unclassified posts using the keyword classifier + MITRE mapper."""
    from pipeline.db_loader import DatabaseLoader
    from classifier.keyword_classifier import KeywordClassifier
    from classifier.mitre_mapper import MitreMapper
    started = _now_iso()
    try:
        db = DatabaseLoader()
        db.init_schema()
        posts = db.get_unclassified_posts(limit=500)

        if not posts:
            logger.info("job_classify_new: no unclassified posts")
            _log_run("classify_new", "skipped", started, 0)
            return {"status": "skipped", "reason": "no unclassified posts"}

        clf = KeywordClassifier()
        mapper = MitreMapper()
        classified = 0

        for post in posts:
            result = clf.classify(post["content"])
            enriched = mapper.enrich_classification(result)
            db.insert_classification(
                post_id=post["id"],
                category=enriched["category"],
                model_used="keyword",
                confidence=enriched["confidence"],
                mitre_techniques=enriched.get("mitre_technique_ids"),
            )
            classified += 1

        db.close()
        logger.info("job_classify_new: classified %d posts", classified)
        _log_run("classify_new", "success", started, classified)
        return {"status": "success", "classified": classified}
    except Exception as exc:
        logger.error("job_classify_new failed: %s", exc)
        _log_run("classify_new", "failure", started, 0, str(exc))
        return {"status": "failure", "error": str(exc)}


def job_daily_report() -> dict[str, Any]:
    """Generate a daily threat intelligence report."""
    from pipeline.db_loader import DatabaseLoader
    from analysis.trend_analyzer import TrendAnalyzer
    from analysis.anomaly_detector import AnomalyDetector
    from analysis.report_generator import ReportGenerator
    started = _now_iso()
    try:
        db = DatabaseLoader()
        db.init_schema()
        analyzer = TrendAnalyzer(db)
        detector = AnomalyDetector(db)
        gen = ReportGenerator()

        stats = analyzer.get_summary_stats()
        cat_dist = analyzer.get_category_distribution("24h")
        top_cves = analyzer.get_top_cves()
        keywords = analyzer.get_trending_keywords("24h")
        ioc_dist = analyzer.get_ioc_distribution()
        anomalies = detector.detect(window_days=7)
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

        md_path = gen.generate_markdown(**report_args)
        html_path = gen.generate_html(**report_args)
        db.close()

        logger.info("job_daily_report: generated %s and %s", md_path.name, html_path.name)
        _log_run("daily_report", "success", started, 2)
        return {"status": "success", "markdown": str(md_path), "html": str(html_path)}
    except Exception as exc:
        logger.error("job_daily_report failed: %s", exc)
        _log_run("daily_report", "failure", started, 0, str(exc))
        return {"status": "failure", "error": str(exc)}


def _log_run(
    job_name: str, status: str, started: str,
    records: int = 0, error: str | None = None,
) -> None:
    """Log a scheduler run to the database (best-effort)."""
    try:
        from pipeline.db_loader import DatabaseLoader
        db = DatabaseLoader()
        db.init_schema()
        db.log_scheduler_run(
            job_name=job_name,
            status=status,
            started_at=started,
            finished_at=_now_iso(),
            records_affected=records,
            error_message=error,
        )
        db.close()
    except Exception as exc:
        logger.debug("Failed to log scheduler run: %s", exc)


# ── Job registry ──────────────────────────────────────────────────────────────

JOB_REGISTRY: dict[str, dict[str, Any]] = {
    "scrape_pastes": {
        "func": job_scrape_pastes,
        "description": "Scrape paste sites for new posts",
    },
    "scrape_feeds": {
        "func": job_scrape_feeds,
        "description": "Scrape public threat intel feeds (OTX, URLhaus, NVD)",
    },
    "process_pipeline": {
        "func": job_process_pipeline,
        "description": "Run cleaning + entity extraction + enrichment pipeline",
    },
    "classify_new": {
        "func": job_classify_new,
        "description": "Classify unclassified posts with keyword classifier + MITRE",
    },
    "daily_report": {
        "func": job_daily_report,
        "description": "Generate daily Markdown + HTML threat report",
    },
}


# ── Scheduler class ───────────────────────────────────────────────────────────

class ToolkitScheduler:
    """
    Configurable scheduler for automated threat intel collection.

    Usage::

        sched = ToolkitScheduler()
        sched.start()       # Blocking — runs until Ctrl+C
        sched.status()      # Print next scheduled runs
        sched.run_now("scrape_pastes")  # Manually trigger a task
    """

    def __init__(self, blocking: bool = True) -> None:
        tz = settings.get("scheduler.timezone", "UTC")
        if blocking:
            self._scheduler = BlockingScheduler(timezone=tz)
        else:
            self._scheduler = BackgroundScheduler(timezone=tz)
        self._blocking = blocking
        self._configure_jobs()

    def _configure_jobs(self) -> None:
        """Register all jobs from settings.yaml schedule config."""
        jobs_config = settings.get("scheduler.jobs", {})

        sp = jobs_config.get("scrape_pastes", {})
        if sp:
            self._scheduler.add_job(
                job_scrape_pastes,
                trigger=IntervalTrigger(minutes=sp.get("minutes", 30)),
                id="scrape_pastes",
                name="Scrape Paste Sites",
                replace_existing=True,
            )

        sf = jobs_config.get("scrape_feeds", {})
        if sf:
            self._scheduler.add_job(
                job_scrape_feeds,
                trigger=IntervalTrigger(hours=sf.get("hours", 6)),
                id="scrape_feeds",
                name="Scrape Threat Feeds",
                replace_existing=True,
            )

        pp = jobs_config.get("process_pipeline", {})
        if pp:
            self._scheduler.add_job(
                job_process_pipeline,
                trigger=IntervalTrigger(minutes=pp.get("minutes", 35)),
                id="process_pipeline",
                name="Process Pipeline",
                replace_existing=True,
            )

        cn = jobs_config.get("classify_new", {})
        if cn:
            self._scheduler.add_job(
                job_classify_new,
                trigger=IntervalTrigger(hours=cn.get("hours", 1)),
                id="classify_new",
                name="Classify New Posts",
                replace_existing=True,
            )

        dr = jobs_config.get("daily_report", {})
        if dr:
            self._scheduler.add_job(
                job_daily_report,
                trigger=CronTrigger(
                    hour=dr.get("hour", 6),
                    minute=dr.get("minute", 0),
                ),
                id="daily_report",
                name="Daily Report",
                replace_existing=True,
            )

        logger.info("Scheduler configured with %d jobs", len(self._scheduler.get_jobs()))

    def start(self) -> None:
        """Start the scheduler (blocking mode — runs until interrupted)."""
        logger.info("Starting scheduler daemon...")
        console.print("\n[bold cyan]Threat Intel Scheduler started.[/] Press Ctrl+C to stop.\n")
        self.status()
        console.print()

        def _shutdown(signum: int, frame: Any) -> None:
            console.print("\n[yellow]Shutting down scheduler...[/]")
            self._scheduler.shutdown(wait=False)
            sys.exit(0)

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        try:
            self._scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            pass

    def start_background(self) -> None:
        """Start in non-blocking mode (for embedding in other apps)."""
        self._scheduler.start()

    def stop(self) -> None:
        """Shut down the scheduler (safe to call even if not started)."""
        from apscheduler.schedulers.base import STATE_STOPPED
        if self._scheduler.state != STATE_STOPPED:
            self._scheduler.shutdown(wait=False)

    def status(self) -> list[dict[str, Any]]:
        """Print and return the status of all scheduled jobs."""
        jobs = self._scheduler.get_jobs()
        results = []

        table = Table(title="Scheduled Jobs", show_lines=True)
        table.add_column("ID", style="cyan", min_width=20)
        table.add_column("Name", style="white", min_width=25)
        table.add_column("Next Run", style="green", min_width=30)
        table.add_column("Trigger", style="dim")

        for job in jobs:
            next_run = str(getattr(job, "next_run_time", None) or "pending")
            trigger_str = str(job.trigger)
            table.add_row(job.id, job.name, next_run, trigger_str)
            results.append({
                "id": job.id,
                "name": job.name,
                "next_run": next_run,
                "trigger": trigger_str,
            })

        console.print(table)
        console.print(f"[dim]Total: {len(jobs)} jobs[/]")
        return results

    def run_now(self, task_name: str) -> dict[str, Any]:
        """Manually trigger a task by name."""
        if task_name not in JOB_REGISTRY:
            available = ", ".join(JOB_REGISTRY.keys())
            console.print(f"[red]Unknown task:[/] {task_name}")
            console.print(f"  Available tasks: {available}")
            return {"status": "error", "message": f"Unknown task: {task_name}"}

        job_info = JOB_REGISTRY[task_name]
        console.print(f"[bold cyan]Running:[/] {task_name} — {job_info['description']}")
        result = job_info["func"]()
        console.print(f"  [green]Result:[/] {result}")
        return result

    def get_run_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Retrieve recent scheduler run logs from the database."""
        try:
            from pipeline.db_loader import DatabaseLoader
            db = DatabaseLoader()
            db.init_schema()
            cursor = db.conn.execute(
                "SELECT * FROM scheduler_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
            runs = [dict(row) for row in cursor.fetchall()]
            db.close()
            return runs
        except Exception as exc:
            logger.error("Failed to get run history: %s", exc)
            return []


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    """
    Entry point for ``python scheduler.py <command>``.

    Commands:
        start              — Start the scheduler daemon
        status             — Show next scheduled runs
        run-now --task X   — Manually trigger a task
        history            — Show recent run history
    """
    setup_logging("scheduler")

    if len(sys.argv) < 2:
        console.print("[bold]Usage:[/] python scheduler.py <command>")
        console.print("Commands: start, status, run-now --task <n>, history")
        console.print(f"Available tasks: {', '.join(JOB_REGISTRY.keys())}")
        sys.exit(1)

    command = sys.argv[1]

    if command == "start":
        sched = ToolkitScheduler(blocking=True)
        sched.start()

    elif command == "status":
        sched = ToolkitScheduler(blocking=False)
        sched.status()

    elif command == "run-now":
        if len(sys.argv) < 4 or sys.argv[2] != "--task":
            console.print("[bold]Usage:[/] python scheduler.py run-now --task <task_name>")
            console.print(f"Available tasks: {', '.join(JOB_REGISTRY.keys())}")
            sys.exit(1)
        task = sys.argv[3]
        sched = ToolkitScheduler(blocking=False)
        sched.run_now(task)

    elif command == "history":
        sched = ToolkitScheduler(blocking=False)
        runs = sched.get_run_history()
        if runs:
            hist_table = Table(title=f"Recent Scheduler Runs (last {len(runs)})", show_lines=True)
            hist_table.add_column("Job", style="cyan", min_width=20)
            hist_table.add_column("Status", min_width=10)
            hist_table.add_column("Started", style="dim", min_width=28)
            hist_table.add_column("Records", justify="right", min_width=8)
            hist_table.add_column("Error", style="red")
            for run in runs:
                status_style = "green" if run["status"] == "success" else "red"
                hist_table.add_row(
                    run["job_name"],
                    f"[{status_style}]{run['status']}[/{status_style}]",
                    run["started_at"],
                    str(run.get("records_affected", 0)),
                    (run.get("error_message") or "")[:40],
                )
            console.print(hist_table)
        else:
            console.print("[dim]No scheduler runs recorded yet.[/]")

    else:
        console.print(f"[red]Unknown command:[/] {command}")
        console.print("Commands: start, status, run-now --task <n>, history")
        sys.exit(1)


if __name__ == "__main__":
    main()
