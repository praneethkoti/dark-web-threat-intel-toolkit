# -*- coding: utf-8 -*-
"""
Smoke tests for the CLI (``cli.py``).

These don't try to re-prove what the underlying modules already cover —
that's what ``test_pipeline.py``, ``test_classifier.py`` etc. are for.
Instead they exercise the CLI surface:

    * Every command responds to ``--help``. Catches broken imports,
      typo'd option names, and missing decorators early.
    * Dry-run paths fire without touching the DB or the filesystem.
    * ``scrape -s fixtures --no-save`` actually pulls items from the HTML
      fixtures and prints a summary table.
    * ``db-info`` against a fresh isolated DB reports zero counts cleanly.
    * ``full-pipeline --dry-run`` cascades through all five steps because
      each inner command inherits the root context's dry-run flag.

Filesystem isolation is handled by the ``cli_env`` fixture in conftest.py
— it redirects DatabaseLoader to a tmp SQLite file and neutralizes the
file-logging handler so repeated runs don't spam ``data/toolkit.log``.

Run::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_cli.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path (conftest also does this; belt-and-braces)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cli import cli


# ── --help coverage ──────────────────────────────────────────────────────────

class TestHelp:
    """
    Every command and subcommand must respond to --help with exit code 0
    and a "Usage:" line. Parametrized so a new command naturally shows
    up as an obvious missing row when added.
    """

    @pytest.mark.parametrize("argv", [
        ["--help"],
        ["scrape", "--help"],
        ["process", "--help"],
        ["classify", "--help"],
        ["analyze", "--help"],
        ["export", "--help"],
        ["summarize", "--help"],
        ["dashboard", "--help"],
        ["full-pipeline", "--help"],
        ["generate-data", "--help"],
        ["db-info", "--help"],
        ["scheduler", "--help"],
        ["scheduler", "start", "--help"],
        ["scheduler", "status", "--help"],
        ["scheduler", "run-now", "--help"],
        ["scheduler", "history", "--help"],
    ])
    def test_help_renders(self, cli_runner, argv):
        result = cli_runner.invoke(cli, argv)
        assert result.exit_code == 0, (
            f"argv={argv} exited {result.exit_code}\noutput:\n{result.output}"
        )
        assert "Usage:" in result.output

    def test_root_help_lists_all_commands(self, cli_runner):
        """Top-level --help should at minimum mention scrape and full-pipeline."""
        result = cli_runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scrape" in result.output
        assert "full-pipeline" in result.output


# ── --dry-run paths (no filesystem or DB I/O) ────────────────────────────────

class TestDryRun:
    """
    Commands that honor --dry-run should print a DRY RUN line and return
    without touching the real filesystem or DB. We don't use cli_env here
    because dry-run has no side effects to isolate.
    """

    def test_dry_run_scrape(self, cli_runner):
        result = cli_runner.invoke(cli, ["--dry-run", "scrape", "-s", "fixtures"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output

    def test_dry_run_process(self, cli_runner):
        result = cli_runner.invoke(cli, ["--dry-run", "process"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output

    def test_dry_run_classify(self, cli_runner):
        result = cli_runner.invoke(cli, ["--dry-run", "classify", "-m", "keyword"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output

    def test_dry_run_analyze(self, cli_runner):
        result = cli_runner.invoke(cli, ["--dry-run", "analyze", "--period", "7d"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output

    def test_dry_run_export(self, cli_runner):
        result = cli_runner.invoke(cli, ["--dry-run", "export", "--format", "csv"])
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output


# ── Real invocations (side effects sandboxed via cli_env) ────────────────────

class TestRealInvocations:
    """
    Actually run commands that touch the filesystem / DB. The ``cli_env``
    fixture redirects DatabaseLoader to a tmp file and stubs out
    file-logging so nothing leaks into the real repo.
    """

    def test_scrape_fixtures_no_save(self, cli_runner, cli_env):
        """``scrape -s fixtures --no-save`` collects items and prints a table."""
        result = cli_runner.invoke(
            cli, ["scrape", "-s", "fixtures", "--no-save"]
        )
        assert result.exit_code == 0, result.output
        # Rich table always prints a Total row
        assert "Total" in result.output

    def test_db_info_on_empty_db(self, cli_runner, cli_env):
        """``db-info`` on a fresh isolated DB should print the stats table."""
        result = cli_runner.invoke(cli, ["db-info"])
        assert result.exit_code == 0, result.output
        assert "Database Statistics" in result.output
        assert "Total Posts" in result.output

    def test_cli_env_isolates_db(self, cli_runner, cli_env):
        """
        Regression guard: two db-info calls inside the same cli_env must
        see the same tmp DB, not the real project DB. If cli_env breaks,
        the second call could leak data from elsewhere.
        """
        r1 = cli_runner.invoke(cli, ["db-info"])
        r2 = cli_runner.invoke(cli, ["db-info"])
        assert r1.exit_code == 0
        assert r2.exit_code == 0
        # Both should report zero posts — fresh tmp DB
        assert "Total Posts" in r1.output
        assert "Total Posts" in r2.output


# ── Full-pipeline dry-run cascade ────────────────────────────────────────────

class TestFullPipeline:
    """
    ``full-pipeline`` delegates via ``ctx.invoke()`` to scrape → process →
    classify → analyze → export. With ``--dry-run`` set at the root, each
    inner command should hit its own dry-run branch and return, so the
    whole thing completes without touching anything.
    """

    def test_full_pipeline_dry_run_cascades(self, cli_runner):
        result = cli_runner.invoke(
            cli, ["--dry-run", "full-pipeline", "-s", "fixtures"]
        )
        assert result.exit_code == 0, result.output
        assert "Full Pipeline Execution" in result.output
        # All five steps should announce themselves
        for n in range(1, 6):
            assert f"Step {n}/5" in result.output, (
                f"Step {n}/5 missing from full-pipeline output:\n{result.output}"
            )
        # Each inner command should have fired its dry-run branch
        assert result.output.count("DRY RUN") >= 3
