"""
Tests for the scraper module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_scraper.py -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scraper.base_scraper import BaseScraper, ScrapedItem, UserAgentRotator
from scraper.paste_scraper import PasteScraper
from scraper.simulated_market_scraper import SimulatedMarketScraper
from scraper.feed_scraper import FeedScraper


# ── ScrapedItem Tests ─────────────────────────────────────────────────────────

class TestScrapedItem:
    def test_creation(self):
        item = ScrapedItem(
            source_name="test",
            source_url="http://example.com",
            content="Hello, world!",
            http_status=200,
        )
        assert item.source_name == "test"
        assert item.source_url == "http://example.com"
        assert item.content == "Hello, world!"
        assert item.http_status == 200
        assert item.content_hash  # SHA-256 should be populated
        assert item.scraped_at    # ISO timestamp should exist

    def test_content_hash_deterministic(self):
        """Same content → same hash, every time."""
        a = ScrapedItem("s", "u", "identical content")
        b = ScrapedItem("s", "u", "identical content")
        assert a.content_hash == b.content_hash

    def test_content_hash_differs(self):
        """Different content → different hash."""
        a = ScrapedItem("s", "u", "content A")
        b = ScrapedItem("s", "u", "content B")
        assert a.content_hash != b.content_hash

    def test_to_dict(self):
        item = ScrapedItem("src", "http://x.com", "data", 200, {"key": "val"})
        d = item.to_dict()
        assert d["source_name"] == "src"
        assert d["metadata"]["key"] == "val"
        assert "content_hash" in d
        assert "scraped_at" in d

    def test_to_json(self):
        item = ScrapedItem("src", "http://x.com", "data")
        j = item.to_json()
        parsed = json.loads(j)
        assert parsed["source_name"] == "src"


# ── UserAgentRotator Tests ────────────────────────────────────────────────────

class TestUserAgentRotator:
    def test_pool_has_minimum_agents(self):
        rotator = UserAgentRotator()
        assert len(rotator) >= 25

    def test_rotation(self):
        rotator = UserAgentRotator()
        agents = [rotator.next() for _ in range(50)]
        # Should cycle through and include variety
        assert len(set(agents)) > 1

    def test_custom_agents(self):
        rotator = UserAgentRotator(extra_agents=["CustomBot/1.0"])
        # Pool should be larger than static list
        assert len(rotator) >= 26


# ── PasteScraper Tests ────────────────────────────────────────────────────────

class TestPasteScraper:
    def test_scrape_fixtures(self):
        """Paste scraper should parse the fixture file successfully."""
        scraper = PasteScraper()
        items = scraper.scrape(source="fixture")
        assert len(items) > 0, "Should extract at least one paste from fixture"

        # Verify structure of first item
        first = items[0]
        assert first.source_name == "paste_site"
        assert first.content_hash
        assert first.content.strip()
        assert first.metadata.get("paste_id")

    def test_fixture_paste_count(self):
        """Fixture has 4 pastes — scraper should find all of them."""
        scraper = PasteScraper()
        items = scraper.scrape(source="fixture")
        assert len(items) == 4

    def test_paste_metadata_fields(self):
        """Each paste should have title, author, and timestamp in metadata."""
        scraper = PasteScraper()
        items = scraper.scrape(source="fixture")
        for item in items:
            assert "title" in item.metadata
            assert "author" in item.metadata
            assert "timestamp" in item.metadata

    def test_save_raw(self, tmp_path, monkeypatch):
        """Verify raw data can be saved to disk as JSON."""
        # Redirect data/raw to tmp_path
        monkeypatch.setattr(
            "scraper.base_scraper.PROJECT_ROOT", tmp_path
        )
        (tmp_path / "data" / "raw").mkdir(parents=True)

        scraper = PasteScraper()
        items = [ScrapedItem("test", "http://test.com", "test content")]
        path = scraper.save_raw(items, "test_output")
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["source_name"] == "test"


# ── SimulatedMarketScraper Tests ──────────────────────────────────────────────

class TestSimulatedMarketScraper:
    def test_scrape_all_fixtures(self):
        """Should parse both marketplace and forum fixtures."""
        scraper = SimulatedMarketScraper()
        items = scraper.scrape(fixture="all")
        assert len(items) > 0

    def test_marketplace_listings(self):
        """Marketplace fixture has 5 listings."""
        scraper = SimulatedMarketScraper()
        items = scraper.scrape(fixture="marketplace")
        assert len(items) == 5

        # Check metadata structure
        for item in items:
            assert item.metadata.get("source_type") == "marketplace"
            assert item.metadata.get("listing_id")
            assert item.metadata.get("vendor")
            assert "price" in item.metadata

    def test_forum_posts(self):
        """Forum fixture has 6 posts."""
        scraper = SimulatedMarketScraper()
        items = scraper.scrape(fixture="forum")
        assert len(items) == 6

        for item in items:
            assert item.metadata.get("source_type") == "forum"
            assert item.metadata.get("post_id")
            assert item.metadata.get("username")
            assert item.metadata.get("thread_title")

    def test_forum_content_has_iocs(self):
        """Forum posts should contain IOC-like content (IPs, hashes, CVEs)."""
        scraper = SimulatedMarketScraper()
        items = scraper.scrape(fixture="forum")
        all_content = " ".join(item.content for item in items)

        assert "CVE-2024-21887" in all_content
        assert "185.174.100.56" in all_content  # C2 IP from fixture

    def test_marketplace_content_has_iocs(self):
        """Marketplace listings should contain crypto wallets, PGP, etc."""
        scraper = SimulatedMarketScraper()
        items = scraper.scrape(fixture="marketplace")
        all_content = " ".join(item.content for item in items)

        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in all_content  # BTC address
        assert "CVE-2024-21887" in all_content

    def test_auto_detect_parse(self):
        """parse() should auto-detect fixture type from HTML content."""
        scraper = SimulatedMarketScraper()
        fixture_path = Path(__file__).resolve().parent.parent / "scraper" / "fixtures" / "marketplace_listing.html"
        html = fixture_path.read_text(encoding="utf-8")
        items = scraper.parse(html, "http://test.com")
        assert len(items) == 5  # marketplace listings


# ── FeedScraper Tests ─────────────────────────────────────────────────────────

class TestFeedScraper:
    def test_instantiation(self):
        """FeedScraper should initialize without errors."""
        scraper = FeedScraper()
        assert scraper.source_name == "threat_feed"

    def test_unknown_feed_logs_error(self):
        """Requesting an unknown feed should return empty list."""
        scraper = FeedScraper()
        items = scraper.scrape(feed="nonexistent")
        assert items == []

    @pytest.mark.skipif(
        not os.getenv("RUN_LIVE_TESTS"),
        reason="Live API tests disabled — set RUN_LIVE_TESTS=1 to enable",
    )
    def test_nvd_live(self):
        """Live test: fetch a known CVE from NVD."""
        scraper = FeedScraper()
        items = scraper.scrape(feed="nvd", cve_id="CVE-2024-21887", limit=1)
        assert len(items) == 1
        assert "CVE-2024-21887" in items[0].content

    @pytest.mark.skipif(
        not os.getenv("RUN_LIVE_TESTS"),
        reason="Live API tests disabled — set RUN_LIVE_TESTS=1 to enable",
    )
    def test_urlhaus_live(self):
        """Live test: fetch recent URLs from URLhaus."""
        scraper = FeedScraper()
        items = scraper.scrape(feed="urlhaus", limit=5)
        assert len(items) > 0


# ── Base Class Tests ──────────────────────────────────────────────────────────

class TestBaseScraper:
    def test_cannot_instantiate_directly(self):
        """BaseScraper is abstract — direct instantiation should fail."""
        with pytest.raises(TypeError):
            BaseScraper("test")

    def test_subclass_must_implement_scrape(self):
        """A subclass missing scrape() should fail."""
        class Incomplete(BaseScraper):
            def parse(self, raw_html, url, **kw):
                return []

        with pytest.raises(TypeError):
            Incomplete("test")

    def test_subclass_must_implement_parse(self):
        """A subclass missing parse() should fail."""
        class Incomplete(BaseScraper):
            def scrape(self, **kw):
                return []

        with pytest.raises(TypeError):
            Incomplete("test")
