"""
Tests for the scheduler module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_scheduler.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scheduler.scheduler import (
    ToolkitScheduler,
    JOB_REGISTRY,
    job_scrape_pastes,
    job_classify_new,
    job_daily_report,
    job_process_pipeline,
)


# ── Job Registry Tests ────────────────────────────────────────────────────────

class TestJobRegistry:
    def test_all_jobs_registered(self):
        expected = {
            "scrape_pastes", "scrape_feeds", "process_pipeline",
            "classify_new", "daily_report",
        }
        assert expected == set(JOB_REGISTRY.keys())

    def test_all_jobs_have_func(self):
        for name, info in JOB_REGISTRY.items():
            assert "func" in info, f"{name} missing 'func'"
            assert callable(info["func"]), f"{name} func is not callable"

    def test_all_jobs_have_description(self):
        for name, info in JOB_REGISTRY.items():
            assert "description" in info, f"{name} missing 'description'"
            assert len(info["description"]) > 10, f"{name} description too short"


# ── ToolkitScheduler Tests ────────────────────────────────────────────────────

class TestToolkitScheduler:
    def test_create_background_scheduler(self):
        sched = ToolkitScheduler(blocking=False)
        jobs = sched._scheduler.get_jobs()
        assert len(jobs) == 5

    def test_job_ids(self):
        sched = ToolkitScheduler(blocking=False)
        job_ids = {j.id for j in sched._scheduler.get_jobs()}
        expected = {"scrape_pastes", "scrape_feeds", "process_pipeline",
                    "classify_new", "daily_report"}
        assert expected == job_ids

    def test_status_returns_list(self, capsys):
        sched = ToolkitScheduler(blocking=False)
        results = sched.status()
        assert isinstance(results, list)
        assert len(results) == 5
        for r in results:
            assert "id" in r
            assert "name" in r
            assert "next_run" in r
            assert "trigger" in r
        captured = capsys.readouterr()
        assert "Scheduled Jobs" in captured.out

    def test_status_shows_pending_before_start(self, capsys):
        """Before start(), next_run should show 'pending'."""
        sched = ToolkitScheduler(blocking=False)
        results = sched.status()
        # All jobs should be "pending" since scheduler isn't started
        for r in results:
            assert r["next_run"] == "pending"

    def test_run_now_unknown_task(self, capsys):
        sched = ToolkitScheduler(blocking=False)
        result = sched.run_now("nonexistent_task")
        assert result["status"] == "error"
        captured = capsys.readouterr()
        assert "Unknown task" in captured.out

    def test_run_now_scrape_pastes(self):
        sched = ToolkitScheduler(blocking=False)
        result = sched.run_now("scrape_pastes")
        assert result["status"] == "success"
        assert result["items"] > 0

    def test_safe_stop_without_start(self):
        """stop() should not crash if scheduler was never started."""
        sched = ToolkitScheduler(blocking=False)
        sched.stop()  # Should not raise

    def test_stop_after_start(self):
        """stop() should work after start_background()."""
        sched = ToolkitScheduler(blocking=False)
        sched.start_background()
        sched.stop()  # Should cleanly shut down

    def test_run_now_classify_new(self, tmp_path):
        """Trigger classify after populating DB with pipeline."""
        from scraper import PasteScraper
        from pipeline import Pipeline
        from pipeline.db_loader import DatabaseLoader

        db_path = tmp_path / "sched_test.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)

        ps = PasteScraper()
        items = ps.scrape(source="fixture")
        pipe.run([i.to_dict() for i in items], source_type="test")

        unclassified = db.get_unclassified_posts()
        assert len(unclassified) > 0

        from unittest.mock import patch
        with patch("pipeline.db_loader.settings") as mock_settings:
            mock_settings.get = lambda key, default=None: (
                str(db_path) if key == "project.database_path" else default
            )
            result = job_classify_new()

        assert result["status"] == "success"
        assert result.get("classified", 0) > 0
        pipe.close()

    def test_run_now_daily_report(self, tmp_path):
        """Trigger daily report job."""
        from pipeline.db_loader import DatabaseLoader
        from unittest.mock import patch

        db_path = tmp_path / "report_test.db"
        db = DatabaseLoader(db_path=db_path)
        db.init_schema()
        db.close()

        with patch("pipeline.db_loader.settings") as mock_settings:
            mock_settings.get = lambda key, default=None: (
                str(db_path) if key == "project.database_path" else
                str(tmp_path) if key == "analysis.report_output_dir" else
                default
            )
            result = job_daily_report()

        assert result["status"] == "success"
        assert "markdown" in result
        assert "html" in result

    def test_get_run_history(self):
        sched = ToolkitScheduler(blocking=False)
        history = sched.get_run_history(limit=5)
        assert isinstance(history, list)


# ── Individual Job Function Tests ─────────────────────────────────────────────

class TestJobFunctions:
    def test_scrape_pastes_returns_dict(self):
        result = job_scrape_pastes()
        assert isinstance(result, dict)
        assert result["status"] == "success"

    def test_process_pipeline_returns_dict(self):
        result = job_process_pipeline()
        assert isinstance(result, dict)
        assert "status" in result

    def test_classify_new_skips_when_empty(self):
        result = job_classify_new()
        assert isinstance(result, dict)
        assert result["status"] in ("success", "skipped")


# ── Job config override tests ────────────────────────────────────────────────

class TestJobConfig:
    """
    ``job_scrape_pastes`` and ``job_scrape_feeds`` read their source/feed
    config from settings.yaml so a real deployment can flip from fixtures
    to live sources without touching code. These tests lock in:

      * the default values match the original hardcoded behaviour
        (no regression for existing users),
      * a settings override actually reaches the underlying scraper call.
    """

    def test_scrape_pastes_default_is_fixture(self):
        """Out-of-the-box default must stay ``"fixture"`` — demos run offline."""
        from config import settings
        assert settings.get("scheduler.jobs.scrape_pastes.source") == "fixture"

    def test_scrape_feeds_defaults_preserve_original(self):
        """Default feed/limit must match the original hardcoded values."""
        from config import settings
        assert settings.get("scheduler.jobs.scrape_feeds.feed") == "all"
        assert settings.get("scheduler.jobs.scrape_feeds.limit") == 25

    def test_scrape_pastes_honors_source_override(self, monkeypatch):
        """
        Monkey-patch ``PasteScraper.scrape`` and verify ``job_scrape_pastes``
        passes whatever the settings say. Proves the job reads settings
        at call-time, not import-time (important for hot-reload scenarios).
        """
        from config import settings
        import scraper as _scraper_pkg

        calls: list[dict] = []

        class FakePasteScraper:
            def scrape(self, **kwargs):
                calls.append(dict(kwargs))
                return []
            def save_raw(self, items, *a, **kw):
                return None

        monkeypatch.setattr(_scraper_pkg, "PasteScraper", FakePasteScraper)

        # Override the settings value for this test only
        monkeypatch.setitem(
            settings.data["scheduler"]["jobs"]["scrape_pastes"],
            "source",
            "live",
        )

        result = job_scrape_pastes()
        assert result["status"] == "success"
        assert len(calls) == 1
        assert calls[0]["source"] == "live", (
            f"Expected source='live' from settings, got {calls[0]}"
        )

    def test_scrape_feeds_honors_feed_and_limit_override(self, monkeypatch):
        """
        Same pattern for scrape_feeds — both ``feed`` and ``limit`` settings
        should round-trip into the ``FeedScraper.scrape`` call.
        """
        from config import settings
        import scraper as _scraper_pkg
        from scheduler.scheduler import job_scrape_feeds

        calls: list[dict] = []

        class FakeFeedScraper:
            def scrape(self, **kwargs):
                calls.append(dict(kwargs))
                return []
            def save_raw(self, items, *a, **kw):
                return None

        monkeypatch.setattr(_scraper_pkg, "FeedScraper", FakeFeedScraper)
        monkeypatch.setitem(
            settings.data["scheduler"]["jobs"]["scrape_feeds"],
            "feed",
            "urlhaus",
        )
        monkeypatch.setitem(
            settings.data["scheduler"]["jobs"]["scrape_feeds"],
            "limit",
            7,
        )

        result = job_scrape_feeds()
        assert result["status"] == "success"
        assert len(calls) == 1
        assert calls[0]["feed"] == "urlhaus"
        assert calls[0]["limit"] == 7


# ── Scheduler CLI Tests ───────────────────────────────────────────────────────

class TestSchedulerCLI:
    def test_main_status(self, capsys, monkeypatch):
        from scheduler.scheduler import main
        monkeypatch.setattr(sys, "argv", ["scheduler.py", "status"])
        main()
        captured = capsys.readouterr()
        assert "Scheduled Jobs" in captured.out
        assert "scrape_pastes" in captured.out

    def test_main_run_now(self, capsys, monkeypatch):
        from scheduler.scheduler import main
        monkeypatch.setattr(
            sys, "argv",
            ["scheduler.py", "run-now", "--task", "scrape_pastes"],
        )
        main()
        captured = capsys.readouterr()
        assert "Running: scrape_pastes" in captured.out

    def test_main_history(self, capsys, monkeypatch):
        from scheduler.scheduler import main
        monkeypatch.setattr(sys, "argv", ["scheduler.py", "history"])
        main()
        captured = capsys.readouterr()
        assert "Scheduler Runs" in captured.out or "No scheduler runs" in captured.out

    def test_main_unknown_command(self, monkeypatch):
        from scheduler.scheduler import main
        monkeypatch.setattr(sys, "argv", ["scheduler.py", "badcommand"])
        with pytest.raises(SystemExit):
            main()

    def test_main_no_args(self, monkeypatch):
        from scheduler.scheduler import main
        monkeypatch.setattr(sys, "argv", ["scheduler.py"])
        with pytest.raises(SystemExit):
            main()
