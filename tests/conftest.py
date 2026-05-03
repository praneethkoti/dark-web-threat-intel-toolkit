"""
Shared pytest fixtures for the Dark Web Threat Intelligence Toolkit test suite.

These fixtures exist in one place so individual test modules don't rebuild
the same scaffolding. Pytest's resolution order is local-then-conftest, so
a test module that defines its own fixture with the same name will continue
to win — nothing here breaks existing tests.

Fixtures:

  * ``project_root``         — absolute ``Path`` to the repo root.
  * ``tmp_db_path``          — fresh temp path for a SQLite DB (no loader).
  * ``tmp_db``               — freshly initialized ``DatabaseLoader`` bound
                                to a temp path; closed automatically.
  * ``sample_scraped_items`` — two IOC-rich scraped-item dicts suitable for
                                pipeline / entity / classifier tests.
  * ``populated_db``         — module-scoped DB pre-loaded via the real
                                scrape → process → classify chain against
                                local HTML fixtures. Treat as read-only.
  * ``cli_runner``           — ``click.testing.CliRunner`` for CLI tests.
  * ``cli_env``              — sandboxes CLI side effects: redirects the
                                DB via ``DATABASE_PATH`` env var and
                                neutralizes the file-logging handler so
                                tests don't append to the real toolkit.log.
"""

from __future__ import annotations

import logging as _logging
import sys
from pathlib import Path

import pytest

# Make the repo root importable for every test file without each one having
# to do its own sys.path.insert dance.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.db_loader import DatabaseLoader


# ── Path helpers ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Absolute path to the repository root."""
    return _PROJECT_ROOT


# ── Database fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def tmp_db_path(tmp_path) -> Path:
    """Fresh temp path for a SQLite DB. Test is responsible for loading it."""
    return tmp_path / "test.db"


@pytest.fixture
def tmp_db(tmp_db_path):
    """
    Freshly initialized ``DatabaseLoader`` against a temp SQLite file.

    Function-scoped so each test starts empty. For a pre-populated,
    read-only DB (faster), see :func:`populated_db`.
    """
    loader = DatabaseLoader(db_path=tmp_db_path)
    loader.init_schema()
    yield loader
    loader.close()


# ── Sample data fixtures ──────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def sample_scraped_items() -> list[dict]:
    """
    Two realistic scraped-item dicts covering breach-style and forum-style
    content. Deliberately IOC-rich so entity / classifier / export tests
    have real signal to work with.
    """
    return [
        {
            "source_name": "paste_site",
            "source_url": "http://example.com/paste1",
            "content": (
                "BREACH ALERT: Credentials leaked from corp.com\n"
                "admin@corp.com:Password123!\n"
                "user@corp.com:Welcome2024\n"
                "Affected CVE: CVE-2024-21887\n"
                "C2 Server: 185.220.101.34\n"
                "SHA-256: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b\n"
                "BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            ),
            "content_hash": "abc123",
            "scraped_at": "2024-11-15T08:00:00Z",
            "http_status": 200,
            "metadata": {"title": "Corp breach"},
        },
        {
            "source_name": "simulated_forum",
            "source_url": "http://example.com/forum1",
            "content": (
                "New ransomware variant spotted. MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"
                "Contact the group via Jabber: threat_actor@xmpp.jp\n"
                "They are recruiting developers for their affiliate program.\n"
                "Monero payment: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
            ),
            "content_hash": "def456",
            "scraped_at": "2024-11-15T09:00:00Z",
            "http_status": 200,
            "metadata": {},
        },
    ]


@pytest.fixture(scope="module")
def populated_db(tmp_path_factory):
    """
    Module-scoped DB pre-populated via the real pipeline: scrape local HTML
    fixtures → process → classify.

    Use this when you need realistic data (15 posts, ~100 entities, 4-ish
    classification categories). Treat it as **read-only** across tests in
    the same module; use :func:`tmp_db` if you need to mutate.

    Also inserts two hand-crafted CVE enrichments so analysis tests that
    join against ``cve_enrichment`` have something to find.
    """
    from scraper import PasteScraper, SimulatedMarketScraper
    from pipeline import Pipeline
    from classifier.keyword_classifier import KeywordClassifier
    from classifier.mitre_mapper import MitreMapper

    db_path = tmp_path_factory.mktemp("shared") / "populated.db"
    db = DatabaseLoader(db_path=db_path)

    # Scrape all local fixtures (deterministic — no network)
    ps = PasteScraper()
    ms = SimulatedMarketScraper()
    scraped = ps.scrape(source="fixture") + ms.scrape(fixture="all")

    pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
    pipe.run([item.to_dict() for item in scraped], source_type="simulated")

    # Classify so downstream analysis has category distribution data
    kw = KeywordClassifier()
    mapper = MitreMapper()
    for post in db.get_all_posts():
        result = kw.classify(post["content"])
        enriched = mapper.enrich_classification(result)
        db.insert_classification(
            post_id=post["id"],
            category=enriched["category"],
            model_used="keyword",
            confidence=enriched["confidence"],
            mitre_techniques=enriched.get("mitre_technique_ids"),
        )

    # Seed two CVE enrichments — mirrors what the NVD enricher would write
    db.upsert_cve_enrichment({
        "cve_id": "CVE-2024-21887",
        "cvss_score": 9.1,
        "cvss_version": "3.1",
        "severity": "CRITICAL",
        "description": "Command injection in Ivanti Connect Secure",
        "affected_products": '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
        "published_date": "2024-01-12",
        "last_modified_date": "2024-02-01",
    })
    db.upsert_cve_enrichment({
        "cve_id": "CVE-2024-21893",
        "cvss_score": 8.2,
        "cvss_version": "3.1",
        "severity": "HIGH",
        "description": "SSRF in Ivanti Connect Secure",
        "affected_products": '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
        "published_date": "2024-01-31",
        "last_modified_date": "2024-02-15",
    })

    pipe.close()
    yield db
    db.close()


# ── CLI test fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def cli_runner():
    """Click's ``CliRunner`` for invoking CLI commands in tests."""
    from click.testing import CliRunner
    return CliRunner()


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """
    Sandbox a CLI test's filesystem side effects.

    What this does:
      * Redirects ``DatabaseLoader()`` (no-arg) to a tmp path via the
        ``DATABASE_PATH`` environment variable, which ``config.settings``
        honors via its env-override table.
      * Neutralizes ``setup_logging``'s file handler so the test run
        doesn't append to the real ``data/toolkit.log``.

    Does **not** redirect ``scraper.base_scraper.PROJECT_ROOT`` — tests
    that call the ``scrape`` command should pass ``--no-save`` instead
    of relying on this fixture to catch the raw-JSON write.

    Yields the tmp path so tests can assert on files they explicitly
    drop there.
    """
    from config import settings as _settings

    # Absolute path wins against PROJECT_ROOT / settings.get(...) on both
    # POSIX and Windows (pathlib uses the absolute operand).
    db_path = tmp_path / "cli_test.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path.resolve()))
    _settings.reload()

    # Replace setup_logging in cli's module namespace with a no-op so the
    # FileHandler against PROJECT_ROOT / data/toolkit.log never opens.
    import cli as _cli_module
    monkeypatch.setattr(
        _cli_module,
        "setup_logging",
        lambda name="toolkit": _logging.getLogger(name),
    )

    yield tmp_path

    # monkeypatch auto-reverts env + attr; reload settings so the next test
    # sees the original project.database_path value from settings.yaml.
    _settings.reload()
