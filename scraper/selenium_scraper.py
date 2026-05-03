"""
Headless-browser scraper using Selenium WebDriver.

Why Selenium when we already have ``requests``? Because real-world threat
sources increasingly serve content via JavaScript-rendered SPAs, and
``requests`` only sees the initial HTML shell. ``SeleniumScraper`` exists
to handle that case: it spins up headless Chrome, lets the page render,
optionally waits for a specific element to appear, then hands the rendered
DOM to the same BeautifulSoup parser that the rest of the toolkit uses.

Two modes:

  * ``scrape(source="fixture")`` — drives Chrome against ``file://`` URLs
    of the bundled HTML fixtures. Fully offline, no chromedriver download
    required (Selenium Manager handles it on first use), demo-safe.
  * ``scrape(source="url", url="https://...", wait_for="css.selector")`` —
    hits a single live URL, optionally waiting for a CSS selector to
    appear before reading the DOM. This is the "for real" mode.

Selenium is imported lazily, the same way ``classifier/bert_classifier.py``
imports transformers, so importing this module on a machine without
selenium installed doesn't blow up — it just raises a clear error when
``scrape()`` is actually called.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from bs4 import BeautifulSoup

from config import settings, PROJECT_ROOT
from scraper.base_scraper import BaseScraper, ScrapedItem

logger = logging.getLogger(__name__)


class SeleniumScraper(BaseScraper):
    """
    Headless-browser scraper for JS-rendered threat intel pages.

    Driver lifecycle: a fresh Chrome instance is created per ``scrape()``
    call and torn down before the method returns. This trades a small
    startup cost (~1s) for guaranteed clean state between runs, which
    matters for scheduled jobs that share the same Python process.
    """

    # Default selector to wait for in fixture mode. Matches the existing
    # ``<div class="paste">`` structure produced by PasteScraper's fixture.
    DEFAULT_FIXTURE_WAIT_SELECTOR = "div.paste"

    # Per-fixture wait selectors. Each bundled HTML file uses a different
    # markup pattern, so blindly waiting for ``div.paste`` on a forum or
    # marketplace fixture wastes the full timeout (10s × 2 fixtures = 20s
    # of pure idle in the demo). Map filename → selector that actually
    # exists in that file. Anything not in the map falls back to ``body``,
    # which is always present and exits the wait immediately.
    FIXTURE_WAIT_SELECTORS: dict[str, str] = {
        "paste_dump.html":          "div.paste",
        "forum_thread.html":        "div.post",
        "marketplace_listing.html": "div.listing",
    }

    def __init__(self) -> None:
        super().__init__(source_name="selenium")

        self._fixtures_dir = PROJECT_ROOT / settings.get(
            "scraper.sources.simulated.fixtures_dir", "scraper/fixtures"
        )
        self._wait_timeout = settings.get("scraper.selenium.wait_timeout_seconds", 10)
        self._page_load_timeout = settings.get(
            "scraper.selenium.page_load_timeout_seconds", 30
        )
        self._headless = settings.get("scraper.selenium.headless", True)

    # ── Public interface ──────────────────────────────────────────────────

    def scrape(self, **kwargs: Any) -> list[ScrapedItem]:
        """
        Drive a headless browser against either local fixtures or a live URL.

        Keyword Args:
            source:    ``"fixture"`` (default) drives Chrome against the
                       bundled paste/marketplace/forum HTML files via
                       ``file://`` URLs. ``"url"`` requires a ``url``
                       argument and hits the live web.
            url:       Required when ``source="url"``.
            wait_for:  CSS selector to wait for before reading the DOM.
                       In fixture mode, leave unset to use per-fixture
                       selectors from ``FIXTURE_WAIT_SELECTORS`` (default).
                       Pass an explicit value to force a single selector
                       across all fixtures. In URL mode, defaults to
                       ``"body"`` if not provided.
            fixtures:  Optional iterable of fixture filenames to drive
                       through Chrome. Defaults to all ``*.html`` in
                       ``scraper/fixtures/``.

        Returns:
            List of ``ScrapedItem`` — one per parsed paste/post.
        """
        source = kwargs.get("source", "fixture")

        if source == "fixture":
            fixtures = kwargs.get("fixtures")
            wait_for = kwargs.get("wait_for")  # None → use per-fixture map
            return self._scrape_fixtures(fixtures=fixtures, wait_for=wait_for)

        if source == "url":
            url = kwargs.get("url")
            if not url:
                raise ValueError("scrape(source='url') requires a 'url' argument")
            wait_for = kwargs.get("wait_for", "body")
            return self._scrape_live(url=url, wait_for=wait_for)

        raise ValueError(
            f"Unknown source={source!r}. Use 'fixture' or 'url'."
        )

    # ── Fixture mode (offline, demo-safe) ─────────────────────────────────

    def _scrape_fixtures(
        self,
        fixtures: Iterable[str] | None = None,
        wait_for: str | None = None,
    ) -> list[ScrapedItem]:
        """
        Drive headless Chrome against bundled fixture HTML files.

        Why bother loading fixtures through Chrome when we could just
        ``read_text()``? Because the *point* of this scraper is to
        demonstrate the headless-browser pipeline end-to-end. Doing it
        against ``file://`` URLs means the demo runs offline but the
        WebDriverWait / driver.page_source flow is real.

        The wait selector is resolved per fixture from
        ``FIXTURE_WAIT_SELECTORS`` so we don't burn the full timeout on
        files that don't contain the default ``div.paste`` element.
        Pass ``wait_for=...`` to force a single selector for every
        fixture (escape hatch for power users).
        """
        if fixtures is None:
            fixture_files = sorted(self._fixtures_dir.glob("*.html"))
        else:
            fixture_files = [self._fixtures_dir / name for name in fixtures]

        if not fixture_files:
            logger.warning("No fixture files found in %s", self._fixtures_dir)
            return []

        items: list[ScrapedItem] = []
        driver = self._make_driver()
        try:
            for path in fixture_files:
                if not path.exists():
                    logger.warning("Fixture not found: %s", path)
                    continue

                file_url = path.resolve().as_uri()  # file:///... — works on Win + POSIX

                # Pick the right selector for this fixture. If the caller
                # passed an explicit wait_for, that wins (escape hatch).
                # Otherwise look it up by filename, falling back to ``body``
                # so unknown fixtures don't block on a missing selector.
                selector = (
                    wait_for
                    if wait_for is not None
                    else self.FIXTURE_WAIT_SELECTORS.get(path.name, "body")
                )
                logger.info(
                    "Selenium loading fixture: %s (wait_for=%s)", file_url, selector
                )

                try:
                    driver.get(file_url)
                    self._wait_for_selector(driver, selector)
                    html = driver.page_source
                    items.extend(self.parse(html, url=file_url))
                except Exception as exc:
                    # Don't let one bad fixture kill the whole batch
                    logger.error("Selenium failed on %s: %s", file_url, exc)
        finally:
            self._safe_quit(driver)

        logger.info("SeleniumScraper collected %d items from %d fixture(s)",
                    len(items), len(fixture_files))
        return items

    # ── Live URL mode ─────────────────────────────────────────────────────

    def _scrape_live(self, url: str, wait_for: str = "body") -> list[ScrapedItem]:
        """
        Drive headless Chrome against a single live URL.

        ``wait_for`` is a CSS selector — pass the selector for the content
        you actually care about, not just ``"body"``, so we don't read
        the DOM before the JS bundle has rendered the real content.
        """
        items: list[ScrapedItem] = []
        driver = self._make_driver()
        try:
            logger.info("Selenium loading live URL: %s", url)
            driver.get(url)
            self._wait_for_selector(driver, wait_for)
            html = driver.page_source
            items.extend(self.parse(html, url=url))
        except Exception as exc:
            logger.error("Selenium failed on %s: %s", url, exc)
        finally:
            self._safe_quit(driver)

        logger.info("SeleniumScraper collected %d items from %s", len(items), url)
        return items

    # ── DOM parsing (interchangeable with PasteScraper output) ────────────

    def parse(self, raw_html: str, url: str, **kwargs: Any) -> list[ScrapedItem]:
        """
        Convert a rendered HTML page into ``ScrapedItem`` instances.

        Strategy 1: structured paste divs (``<div class="paste">``) —
            matches the QuickPaste fixture format used by PasteScraper.
        Strategy 2: forum-thread posts (``<article class="forum-post">``).
        Strategy 3: marketplace listings (``<div class="listing">``).
        Strategy 4 (fallback): treat the entire ``<body>`` as one item.

        The order matters — strategies with a more specific selector run
        first so a forum-thread fixture isn't misclassified as a single
        ``<body>`` blob.
        """
        soup = BeautifulSoup(raw_html, "lxml")
        items: list[ScrapedItem] = []

        for selector, name_suffix in (
            ("div.paste",         "paste"),
            ("div.post",          "forum"),
            ("div.listing",       "listing"),
        ):
            elements = soup.select(selector)
            if not elements:
                continue
            for el in elements:
                content = el.get_text(separator="\n", strip=True)
                if len(content) < 20:  # skip empty shells
                    continue
                items.append(
                    ScrapedItem(
                        source_name=f"selenium_{name_suffix}",
                        source_url=url,
                        content=content,
                        http_status=None,  # Selenium doesn't expose HTTP status by default
                        metadata={
                            "selector": selector,
                            "rendered_via": "selenium_chrome",
                        },
                    )
                )
            # If a specific selector matched, don't fall back to <body>
            return items

        # Fallback: nothing matched our known fixture selectors → whole body
        body = soup.find("body")
        if body is not None:
            content = body.get_text(separator="\n", strip=True)
            if len(content) >= 20:
                items.append(
                    ScrapedItem(
                        source_name="selenium_page",
                        source_url=url,
                        content=content,
                        http_status=None,
                        metadata={
                            "selector": "body",
                            "rendered_via": "selenium_chrome",
                        },
                    )
                )

        return items

    # ── Driver management ─────────────────────────────────────────────────

    def _make_driver(self) -> Any:
        """
        Construct a headless Chrome WebDriver.

        Selenium Manager (built into selenium >= 4.6) handles the
        chromedriver download automatically on first use, so this works
        out of the box on any machine that has Chrome installed.

        Override this method in tests to inject a fake driver — that's
        cleaner than monkey-patching ``selenium.webdriver`` globally.
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except ImportError as exc:
            raise ImportError(
                "selenium is required for SeleniumScraper. "
                "Install with: pip install selenium"
            ) from exc

        options = Options()
        if self._headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        # Use the same UA pool as the rest of the scrapers so headless
        # Chrome traffic blends in with the live HTTP traffic.
        options.add_argument(f"user-agent={self._ua_rotator.next()}")

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(self._page_load_timeout)
        return driver

    def _wait_for_selector(self, driver, selector: str) -> None:
        """
        Block until a CSS selector appears in the DOM or the timeout fires.

        We catch the timeout and continue — better to parse what's there
        than to abort the whole run.
        """
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.common.exceptions import TimeoutException
        except ImportError:
            # selenium isn't installed; the driver call will have already
            # raised. Keep the import error from _make_driver as the
            # primary signal.
            return

        try:
            WebDriverWait(driver, self._wait_timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, selector))
            )
        except TimeoutException:
            logger.warning(
                "Selenium wait_for=%r timed out after %ss — parsing whatever rendered",
                selector,
                self._wait_timeout,
            )

    @staticmethod
    def _safe_quit(driver) -> None:
        """Quit the driver, swallowing any teardown errors."""
        if driver is None:
            return
        try:
            driver.quit()
        except Exception as exc:
            logger.debug("Driver quit raised (harmless): %s", exc)
