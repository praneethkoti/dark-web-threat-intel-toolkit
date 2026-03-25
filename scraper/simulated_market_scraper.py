"""
Scraper for simulated dark web marketplace and forum pages.

Parses local HTML fixture files that realistically mimic:
    - Marketplace product listings (vendors, prices, descriptions)
    - Forum threads (posts, replies, timestamps, usernames)

The scraping logic is identical to what you'd use against a real site —
swap the URL from ``file://`` to an actual endpoint and the code works
unchanged.  This design lets you demo the full pipeline legally.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup, Tag

from config import settings, PROJECT_ROOT
from scraper.base_scraper import BaseScraper, ScrapedItem

logger = logging.getLogger(__name__)


class SimulatedMarketScraper(BaseScraper):
    """Scrape marketplace listings from local HTML fixtures."""

    def __init__(self) -> None:
        super().__init__(source_name="simulated_market")
        self._fixtures_dir = PROJECT_ROOT / settings.get(
            "scraper.sources.simulated.fixtures_dir", "scraper/fixtures"
        )

    def scrape(self, **kwargs: Any) -> list[ScrapedItem]:
        """
        Scrape all fixture files and return combined results.

        Keyword Args:
            fixture: Specific fixture name to scrape (``"marketplace"``,
                     ``"forum"``, or ``"all"`` — default).
        """
        fixture = kwargs.get("fixture", "all")
        items: list[ScrapedItem] = []

        fixture_map = {
            "marketplace": "marketplace_listing.html",
            "forum": "forum_thread.html",
        }

        targets = fixture_map if fixture == "all" else {fixture: fixture_map.get(fixture, "")}

        for name, filename in targets.items():
            path = self._fixtures_dir / filename
            if not path.exists():
                logger.warning("Fixture not found: %s", path)
                continue

            html = path.read_text(encoding="utf-8")
            if name == "marketplace":
                items.extend(self._parse_marketplace(html, f"file://{path}"))
            elif name == "forum":
                items.extend(self._parse_forum(html, f"file://{path}"))

        logger.info("SimulatedMarketScraper collected %d items", len(items))
        return items

    def parse(self, raw_html: str, url: str, **kwargs: Any) -> list[ScrapedItem]:
        """
        Auto-detect fixture type and delegate to the right parser.

        Detection heuristic: if the HTML contains ``<div class="listing">``
        it's a marketplace page; if it has ``<div class="post">`` it's a
        forum thread.
        """
        if 'class="listing"' in raw_html:
            return self._parse_marketplace(raw_html, url)
        elif 'class="post"' in raw_html:
            return self._parse_forum(raw_html, url)
        else:
            logger.warning("Unknown fixture format for %s — trying marketplace parser", url)
            return self._parse_marketplace(raw_html, url)

    # ── Marketplace parser ────────────────────────────────────────────────

    def _parse_marketplace(self, html: str, url: str) -> list[ScrapedItem]:
        """Extract individual product listings from a marketplace page."""
        soup = BeautifulSoup(html, "lxml")
        items: list[ScrapedItem] = []

        for listing in soup.select("div.listing"):
            listing_id = listing.get("data-listing-id", "unknown")

            title = self._text(listing, ".listing-title")
            vendor = self._text(listing, ".vendor")
            price = self._text(listing, ".price")
            category = self._text(listing, ".category")
            date = self._text(listing, ".date")
            sales = self._text(listing, ".sales")
            rating = self._text(listing, ".rating")

            # Full description text
            desc_el = listing.select_one(".listing-description")
            description = desc_el.get_text(separator="\n", strip=True) if desc_el else ""

            # Tags
            tags = [t.get_text(strip=True) for t in listing.select(".tag")]

            # Combine into a single content block the pipeline can process
            content_parts = [
                f"[Marketplace Listing] {title}",
                f"Vendor: {vendor}",
                f"Price: {price}",
                f"Category: {category}",
                f"Date: {date}",
                f"Sales: {sales}",
                f"Rating: {rating}",
                f"Tags: {', '.join(tags)}",
                "",
                description,
            ]
            content = "\n".join(content_parts)

            items.append(
                ScrapedItem(
                    source_name="simulated_market",
                    source_url=f"{url}#listing-{listing_id}",
                    content=content,
                    http_status=200,
                    metadata={
                        "listing_id": listing_id,
                        "title": title,
                        "vendor": vendor.replace("Vendor: ", ""),
                        "price": price.replace("Price: ", ""),
                        "category": category.replace("Category: ", ""),
                        "date": date.replace("Listed: ", "").replace("Date: ", ""),
                        "sales": sales.replace("Sales: ", ""),
                        "rating": rating.replace("Rating: ", ""),
                        "tags": tags,
                        "source_type": "marketplace",
                    },
                )
            )

        logger.debug("Parsed %d marketplace listings from %s", len(items), url)
        return items

    # ── Forum parser ──────────────────────────────────────────────────────

    def _parse_forum(self, html: str, url: str) -> list[ScrapedItem]:
        """Extract individual posts from a forum thread page."""
        soup = BeautifulSoup(html, "lxml")
        items: list[ScrapedItem] = []

        thread_title_el = soup.select_one(".thread-title")
        thread_title = thread_title_el.get_text(strip=True) if thread_title_el else "Unknown Thread"

        for post in soup.select("div.post"):
            post_id = post.get("data-post-id", "unknown")

            username = self._text(post, ".username")
            user_rank = self._text(post, ".user-rank")
            post_count = self._text(post, ".post-count")
            timestamp = self._text(post, ".timestamp")

            body_el = post.select_one(".post-body")
            body = body_el.get_text(separator="\n", strip=True) if body_el else ""

            content_parts = [
                f"[Forum Post] Thread: {thread_title}",
                f"User: {username} ({user_rank})",
                f"Posts: {post_count}",
                f"Date: {timestamp}",
                "",
                body,
            ]
            content = "\n".join(content_parts)

            items.append(
                ScrapedItem(
                    source_name="simulated_forum",
                    source_url=f"{url}#post-{post_id}",
                    content=content,
                    http_status=200,
                    metadata={
                        "post_id": post_id,
                        "thread_title": thread_title,
                        "username": username,
                        "user_rank": user_rank,
                        "timestamp": timestamp,
                        "source_type": "forum",
                    },
                )
            )

        logger.debug("Parsed %d forum posts from %s", len(items), url)
        return items

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _text(parent: Tag, selector: str) -> str:
        """Safely extract text from the first element matching *selector*."""
        el = parent.select_one(selector)
        return el.get_text(strip=True) if el else ""
