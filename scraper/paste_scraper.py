"""
Scraper for public paste sites and local paste-dump fixtures.

Supports:
    - Local HTML fixture files (``scraper/fixtures/paste_dump.html``)
    - Live scraping of dpaste.org recent pastes (public API)

The same ``parse()`` logic handles both sources, so swapping in a new
paste site means changing URLs, not rewriting extraction code.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from config import settings, PROJECT_ROOT
from scraper.base_scraper import BaseScraper, ScrapedItem

logger = logging.getLogger(__name__)


class PasteScraper(BaseScraper):
    """Scrape pastes from public paste services or local fixture files."""

    def __init__(self) -> None:
        super().__init__(source_name="paste_site")
        self._fixtures_dir = PROJECT_ROOT / settings.get(
            "scraper.sources.simulated.fixtures_dir", "scraper/fixtures"
        )
        self._scrape_limit = settings.get("scraper.sources.paste_sites.scrape_limit", 50)

    # ── Public interface ──────────────────────────────────────────────────

    def scrape(self, **kwargs: Any) -> list[ScrapedItem]:
        """
        Run all enabled paste-scraping strategies.

        Keyword Args:
            source: ``"fixture"`` to scrape local HTML only,
                    ``"live"`` for real paste sites,
                    ``"all"`` (default) for both.
            limit:  Max items to return.
        """
        source = kwargs.get("source", "all")
        limit = kwargs.get("limit", self._scrape_limit)
        items: list[ScrapedItem] = []

        if source in ("fixture", "all"):
            items.extend(self._scrape_fixture())

        if source in ("live", "all"):
            items.extend(self._scrape_dpaste(limit=limit))

        logger.info("PasteScraper collected %d items (source=%s)", len(items), source)
        return items[:limit]

    # ── Fixture scraping ──────────────────────────────────────────────────

    def _scrape_fixture(self) -> list[ScrapedItem]:
        """Parse the local paste_dump.html fixture."""
        fixture_path = self._fixtures_dir / "paste_dump.html"
        if not fixture_path.exists():
            logger.warning("Paste fixture not found: %s", fixture_path)
            return []

        html = fixture_path.read_text(encoding="utf-8")
        return self.parse(html, url=f"file://{fixture_path}")

    # ── Live paste-site scraping ──────────────────────────────────────────

    def _scrape_dpaste(self, limit: int = 20) -> list[ScrapedItem]:
        """
        Scrape recent public pastes from dpaste.org.

        dpaste.org exposes a simple web interface. We pull the recent-pastes
        page and extract paste content links, then fetch each paste.
        Falls back gracefully if the site is unreachable.
        """
        items: list[ScrapedItem] = []
        base_url = "https://dpaste.org"

        try:
            # dpaste doesn't have a "recent" page, so we use the API endpoint
            # to create/retrieve pastes. For demo purposes we try fetching
            # a few known-format URLs; in production you'd use their API.
            resp = self.get(f"{base_url}/")
            if resp.status_code != 200:
                logger.warning("dpaste.org returned %d", resp.status_code)
                return items

            soup = BeautifulSoup(resp.text, "lxml")

            # Look for paste links on the homepage (format: /XXXX)
            paste_links: list[str] = []
            for link in soup.select("a[href]"):
                href = link.get("href", "")
                # dpaste paste URLs are short alphanumeric paths
                if (
                    href.startswith("/")
                    and len(href) > 1
                    and len(href) < 12
                    and not href.startswith("/api")
                    and href not in ("/", "/about", "/login", "/register")
                ):
                    paste_links.append(href)

            paste_links = list(dict.fromkeys(paste_links))[:limit]  # dedupe, cap
            logger.info("Found %d paste links on dpaste.org", len(paste_links))

            for path in paste_links:
                paste_url = f"{base_url}{path}"
                try:
                    paste_resp = self.get(f"{paste_url}/raw")
                    if paste_resp.status_code == 200 and paste_resp.text.strip():
                        items.append(
                            ScrapedItem(
                                source_name="dpaste",
                                source_url=paste_url,
                                content=paste_resp.text,
                                http_status=paste_resp.status_code,
                                metadata={"raw_url": f"{paste_url}/raw"},
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed to fetch paste %s: %s", paste_url, exc)
                    continue

        except Exception as exc:
            logger.error("dpaste.org scraping failed: %s", exc)

        return items

    # ── Parsing ───────────────────────────────────────────────────────────

    def parse(self, raw_html: str, url: str, **kwargs: Any) -> list[ScrapedItem]:
        """
        Extract individual pastes from an HTML page containing multiple pastes.

        Works on both the fixture format (``<div class="paste">``) and
        generic pages where paste content lives in ``<pre>`` tags.
        """
        soup = BeautifulSoup(raw_html, "lxml")
        items: list[ScrapedItem] = []

        # Strategy 1: structured paste divs (our fixture format)
        paste_divs = soup.select("div.paste")
        if paste_divs:
            for div in paste_divs:
                paste_id = div.get("data-paste-id", "unknown")
                title_el = div.select_one(".paste-title")
                title = title_el.get_text(strip=True) if title_el else "Untitled"

                author_el = div.select_one(".author")
                author = author_el.get_text(strip=True).replace("Author: ", "") if author_el else "anonymous"

                ts_el = div.select_one(".timestamp")
                timestamp = ts_el.get_text(strip=True) if ts_el else ""

                content_el = div.select_one(".paste-content, pre")
                content = content_el.get_text() if content_el else ""

                if content.strip():
                    items.append(
                        ScrapedItem(
                            source_name="paste_site",
                            source_url=f"{url}#{paste_id}",
                            content=content.strip(),
                            http_status=200,
                            metadata={
                                "paste_id": paste_id,
                                "title": title,
                                "author": author,
                                "timestamp": timestamp,
                            },
                        )
                    )
            logger.debug("Parsed %d structured pastes from %s", len(items), url)
            return items

        # Strategy 2: fallback — grab all <pre> blocks as individual pastes
        for idx, pre in enumerate(soup.select("pre")):
            content = pre.get_text()
            if content.strip():
                items.append(
                    ScrapedItem(
                        source_name="paste_site",
                        source_url=f"{url}#pre-{idx}",
                        content=content.strip(),
                        http_status=200,
                        metadata={"parse_strategy": "pre_fallback", "index": idx},
                    )
                )

        logger.debug("Parsed %d <pre> blocks from %s", len(items), url)
        return items
