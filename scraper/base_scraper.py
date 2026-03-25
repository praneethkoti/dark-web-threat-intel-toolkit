"""
Abstract base scraper with production-grade request handling.

Every source-specific scraper inherits from ``BaseScraper`` and only needs
to implement ``scrape()`` and ``parse()``.  All cross-cutting concerns —
rate limiting, retries, user-agent rotation, proxy routing, session
management — live here.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

# ── User-Agent Pool ───────────────────────────────────────────────────────────
# A curated list of realistic browser UAs.  The pool is shuffled at startup
# and rotated per-request so scraping traffic looks organic.

_STATIC_USER_AGENTS: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
    # Brave (same UA base as Chrome)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.62 Safari/537.36",
]


class UserAgentRotator:
    """Thread-safe rotating pool of user-agent strings."""

    def __init__(self, extra_agents: list[str] | None = None) -> None:
        self._pool = list(_STATIC_USER_AGENTS)
        if extra_agents:
            self._pool.extend(extra_agents)
        random.shuffle(self._pool)
        self._index = 0

    def next(self) -> str:
        ua = self._pool[self._index % len(self._pool)]
        self._index += 1
        return ua

    def __len__(self) -> int:
        return len(self._pool)


class ScrapedItem:
    """
    Standard container for a single scraped result.

    Every scraper returns a list of ``ScrapedItem`` instances, which the
    pipeline module consumes without caring which scraper produced them.
    """

    def __init__(
        self,
        source_name: str,
        source_url: str,
        content: str,
        http_status: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.source_name = source_name
        self.source_url = source_url
        self.content = content
        self.http_status = http_status
        self.metadata = metadata or {}
        self.scraped_at = datetime.now(timezone.utc).isoformat()
        self.content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_url": self.source_url,
            "content": self.content,
            "content_hash": self.content_hash,
            "http_status": self.http_status,
            "scraped_at": self.scraped_at,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def __repr__(self) -> str:
        trunc = self.content[:60].replace("\n", " ")
        return f"<ScrapedItem source={self.source_name!r} hash={self.content_hash[:12]}… content={trunc!r}>"


class BaseScraper(abc.ABC):
    """
    Abstract base class for all scrapers.

    Subclasses implement:
        ``scrape(**kwargs) -> list[ScrapedItem]``
        ``parse(raw_html: str, url: str) -> list[ScrapedItem]``

    The base class provides:
        - ``self.session`` — a ``requests.Session`` with retry adapter
        - ``self.get(url)`` — rate-limited, UA-rotated, proxy-aware GET
        - ``self.post(url, **kw)`` — same for POST
        - ``self._rate_limit()`` — sleeps for the configured delay
        - ``self.save_raw(items, filename)`` — persist raw results to JSON
    """

    def __init__(self, source_name: str) -> None:
        self.source_name = source_name

        # ── Load scraper config ───────────────────────────────────────────
        self._delay = settings.get("scraper.default_delay_seconds", 2.0)
        self._timeout = settings.get("scraper.request_timeout", 30)
        self._verify_ssl = settings.get("scraper.verify_ssl", True)
        max_retries = settings.get("scraper.max_retries", 3)
        backoff = settings.get("scraper.retry_backoff_factor", 2.0)

        # ── User-agent rotation ───────────────────────────────────────────
        self._ua_rotator = UserAgentRotator()

        # ── Build session with retry adapter ──────────────────────────────
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # ── Proxy configuration ───────────────────────────────────────────
        self._configure_proxies()

        # ── Cookie / header defaults ──────────────────────────────────────
        self.session.headers.update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "DNT": "1",
            }
        )

        logger.info(
            "Initialized %s scraper (delay=%.1fs, retries=%d, proxies=%s, UAs=%d)",
            self.source_name,
            self._delay,
            max_retries,
            "enabled" if self.session.proxies else "disabled",
            len(self._ua_rotator),
        )

    # ── Proxy setup ───────────────────────────────────────────────────────
    def _configure_proxies(self) -> None:
        proxy_cfg = settings.get("scraper.proxy", {})
        if not proxy_cfg or not proxy_cfg.get("enabled", False):
            return

        proxies: dict[str, str] = {}
        if proxy_cfg.get("socks5"):
            proxies["http"] = proxy_cfg["socks5"]
            proxies["https"] = proxy_cfg["socks5"]
        else:
            if proxy_cfg.get("http"):
                proxies["http"] = proxy_cfg["http"]
            if proxy_cfg.get("https"):
                proxies["https"] = proxy_cfg["https"]

        if proxies:
            self.session.proxies.update(proxies)
            logger.debug("Proxy configured: %s", proxies)

    # ── Rate limiting ─────────────────────────────────────────────────────
    def _rate_limit(self) -> None:
        """Sleep with ±20 % jitter so requests don't look robotic."""
        jitter = self._delay * random.uniform(-0.2, 0.2)
        sleep_time = max(0.1, self._delay + jitter)
        logger.debug("Rate-limit sleep: %.2fs", sleep_time)
        time.sleep(sleep_time)

    # ── HTTP helpers ──────────────────────────────────────────────────────
    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """
        Rate-limited GET with rotating user-agent.

        Raises ``requests.RequestException`` on network errors after all
        retries are exhausted (handled by the Retry adapter).
        """
        self._rate_limit()
        headers = kwargs.pop("headers", {})
        headers["User-Agent"] = self._ua_rotator.next()
        logger.debug("GET %s", url)
        response = self.session.get(
            url,
            headers=headers,
            timeout=self._timeout,
            verify=self._verify_ssl,
            **kwargs,
        )
        logger.debug("GET %s → %d (%d bytes)", url, response.status_code, len(response.content))
        return response

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        """Rate-limited POST with rotating user-agent."""
        self._rate_limit()
        headers = kwargs.pop("headers", {})
        headers["User-Agent"] = self._ua_rotator.next()
        logger.debug("POST %s", url)
        response = self.session.post(
            url,
            headers=headers,
            timeout=self._timeout,
            verify=self._verify_ssl,
            **kwargs,
        )
        logger.debug("POST %s → %d (%d bytes)", url, response.status_code, len(response.content))
        return response

    # ── Persistence ───────────────────────────────────────────────────────
    def save_raw(self, items: list[ScrapedItem], filename: str | None = None) -> Path:
        """
        Persist scraped items to ``data/raw/<filename>.json``.

        Returns the path to the written file.
        """
        if filename is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{self.source_name}_{ts}"

        raw_dir = PROJECT_ROOT / "data" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / f"{filename}.json"

        payload = [item.to_dict() for item in items]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

        logger.info("Saved %d items → %s", len(items), out_path)
        return out_path

    # ── Abstract interface ────────────────────────────────────────────────
    @abc.abstractmethod
    def scrape(self, **kwargs: Any) -> list[ScrapedItem]:
        """
        Execute the scraping workflow and return structured results.

        Subclasses define what URLs to hit, how to paginate, etc.
        """

    @abc.abstractmethod
    def parse(self, raw_html: str, url: str, **kwargs: Any) -> list[ScrapedItem]:
        """
        Parse raw HTML/text into ``ScrapedItem`` instances.

        Separated from ``scrape()`` so the same parsing logic works on
        both live HTTP responses and local fixture files.
        """

    # ── Context manager support ───────────────────────────────────────────
    def __enter__(self) -> "BaseScraper":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.session.close()
