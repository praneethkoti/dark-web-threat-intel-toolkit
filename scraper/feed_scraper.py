"""
Scraper for public threat intelligence feeds.

Supports:
    - **AlienVault OTX** — pulse subscriptions (IOCs, descriptions, tags).
    - **Abuse.ch URLhaus** — recent malware URL submissions.
    - **Abuse.ch MalwareBazaar** — recent malware sample metadata.
    - **NIST NVD** — CVE records with CVSS scores and descriptions.

All APIs are public and legal.  OTX and NVD benefit from API keys
(higher rate limits) but work without them.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from config import settings
from scraper.base_scraper import BaseScraper, ScrapedItem

logger = logging.getLogger(__name__)


class FeedScraper(BaseScraper):
    """
    Unified scraper for multiple public threat-intel feeds.

    Usage::

        scraper = FeedScraper()
        items = scraper.scrape(feed="nvd", cve_year=2024, limit=25)
        items = scraper.scrape(feed="otx", limit=10)
        items = scraper.scrape(feed="urlhaus", limit=50)
        items = scraper.scrape(feed="all")
    """

    def __init__(self) -> None:
        super().__init__(source_name="threat_feed")

        # ── OTX config ────────────────────────────────────────────────────
        self._otx_base = settings.get(
            "scraper.sources.threat_feeds.alientvault_otx.base_url",
            "https://otx.alienvault.com/api/v1",
        )
        self._otx_limit = settings.get(
            "scraper.sources.threat_feeds.alientvault_otx.pulse_limit", 25
        )
        self._otx_key = settings.get("_env.otx_api_key", "")

        # ── Abuse.ch config ───────────────────────────────────────────────
        self._urlhaus_url = settings.get(
            "scraper.sources.threat_feeds.abuse_ch.urlhaus_url",
            "https://urlhaus-api.abuse.ch/v1",
        )
        self._bazaar_url = settings.get(
            "scraper.sources.threat_feeds.abuse_ch.malwarebazaar_url",
            "https://mb-api.abuse.ch/api/v1",
        )

        # ── NVD config ────────────────────────────────────────────────────
        self._nvd_base = settings.get(
            "scraper.sources.threat_feeds.nvd.base_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        )
        self._nvd_per_page = settings.get(
            "scraper.sources.threat_feeds.nvd.results_per_page", 50
        )
        self._nvd_key = settings.get("_env.nvd_api_key", "")
        self._nvd_default_year = settings.get(
            "scraper.sources.threat_feeds.nvd.default_cve_year", 2024
        )

    # ── Public interface ──────────────────────────────────────────────────

    def scrape(self, **kwargs: Any) -> list[ScrapedItem]:
        """
        Scrape one or all feeds.

        Keyword Args:
            feed:      ``"otx"``, ``"urlhaus"``, ``"bazaar"``, ``"nvd"``, or
                       ``"all"`` (default).
            limit:     Max items per feed.
            cve_year:  Year filter for NVD queries (default from config).
            cve_id:    Specific CVE to look up (e.g. ``"CVE-2024-21887"``).
        """
        feed = kwargs.get("feed", "all")
        limit = kwargs.get("limit", 25)
        items: list[ScrapedItem] = []

        dispatch = {
            "otx": self._scrape_otx,
            "urlhaus": self._scrape_urlhaus,
            "bazaar": self._scrape_bazaar,
            "nvd": self._scrape_nvd,
        }

        if feed == "all":
            for name, func in dispatch.items():
                try:
                    items.extend(func(limit=limit, **kwargs))
                except Exception as exc:
                    logger.error("Feed %s failed: %s", name, exc)
        elif feed in dispatch:
            items.extend(dispatch[feed](limit=limit, **kwargs))
        else:
            logger.error("Unknown feed: %s (valid: %s)", feed, list(dispatch.keys()))

        logger.info("FeedScraper collected %d items (feed=%s)", len(items), feed)
        return items

    def parse(self, raw_html: str, url: str, **kwargs: Any) -> list[ScrapedItem]:
        """
        Feed data is JSON, not HTML — this exists to satisfy the abstract
        interface.  In practice, parsing happens inline in each ``_scrape_*``
        method because every API returns a different JSON schema.
        """
        return []

    # ── AlienVault OTX ────────────────────────────────────────────────────

    def _scrape_otx(self, limit: int = 25, **kwargs: Any) -> list[ScrapedItem]:
        """Fetch recent pulses from the OTX subscribed feed."""
        items: list[ScrapedItem] = []
        headers: dict[str, str] = {}
        # Without an API key this hits the public endpoint, which only returns
        # a handful of pulses. Most useful data requires a (free) OTX account.
        if self._otx_key:
            headers["X-OTX-API-KEY"] = self._otx_key

        url = f"{self._otx_base}/pulses/subscribed"
        params = {"limit": min(limit, 50), "page": 1}

        try:
            resp = self.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                logger.warning("OTX API returned %d: %s", resp.status_code, resp.text[:200])
                return items

            data = resp.json()
            pulses = data.get("results", [])

            for pulse in pulses[:limit]:
                pulse_id = pulse.get("id", "unknown")
                name = pulse.get("name", "Untitled Pulse")
                description = pulse.get("description", "")
                tags = pulse.get("tags", [])
                created = pulse.get("created", "")
                modified = pulse.get("modified", "")
                adversary = pulse.get("adversary", "")
                tlp = pulse.get("tlp", "")

                # Extract IOC summaries from indicators
                indicators = pulse.get("indicators", [])
                ioc_lines: list[str] = []
                for ind in indicators[:50]:  # cap per-pulse to avoid huge content
                    ind_type = ind.get("type", "unknown")
                    ind_value = ind.get("indicator", "")
                    ioc_lines.append(f"  [{ind_type}] {ind_value}")

                content_parts = [
                    f"[OTX Pulse] {name}",
                    f"Pulse ID: {pulse_id}",
                    f"Created: {created}",
                    f"Modified: {modified}",
                    f"Tags: {', '.join(tags)}",
                    f"Adversary: {adversary}" if adversary else "",
                    f"TLP: {tlp}" if tlp else "",
                    "",
                    description,
                    "",
                    f"Indicators ({len(indicators)} total):",
                    *ioc_lines,
                ]
                content = "\n".join(line for line in content_parts if line is not None)

                items.append(
                    ScrapedItem(
                        source_name="otx",
                        source_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                        content=content,
                        http_status=resp.status_code,
                        metadata={
                            "pulse_id": pulse_id,
                            "tags": tags,
                            "adversary": adversary,
                            "indicator_count": len(indicators),
                            "tlp": tlp,
                        },
                    )
                )

        except Exception as exc:
            logger.error("OTX scraping failed: %s", exc)

        return items

    # ── Abuse.ch URLhaus ──────────────────────────────────────────────────

    def _scrape_urlhaus(self, limit: int = 25, **kwargs: Any) -> list[ScrapedItem]:
        items: list[ScrapedItem] = []

        try:
            resp = self.post(
                f"{self._urlhaus_url}/urls/recent/",
                data={"limit": min(limit, 100)},
            )
            if resp.status_code != 200:
                logger.warning("URLhaus API returned %d", resp.status_code)
                return items

            data = resp.json()
            urls_list = data.get("urls", [])

            for entry in urls_list[:limit]:
                url_val = entry.get("url", "")
                host = entry.get("host", "")
                date_added = entry.get("dateadded", "")
                threat = entry.get("threat", "")
                url_status = entry.get("url_status", "")
                tags = entry.get("tags", []) or []
                reporter = entry.get("reporter", "")
                urlhaus_ref = entry.get("urlhaus_reference", "")

                content_parts = [
                    f"[URLhaus] Malicious URL Submission",
                    f"URL: {url_val}",
                    f"Host: {host}",
                    f"Date Added: {date_added}",
                    f"Threat: {threat}",
                    f"Status: {url_status}",
                    f"Tags: {', '.join(str(t) for t in tags)}",
                    f"Reporter: {reporter}",
                ]
                content = "\n".join(content_parts)

                items.append(
                    ScrapedItem(
                        source_name="urlhaus",
                        source_url=urlhaus_ref or url_val,
                        content=content,
                        http_status=resp.status_code,
                        metadata={
                            "malicious_url": url_val,
                            "host": host,
                            "threat": threat,
                            "tags": tags,
                            "status": url_status,
                        },
                    )
                )

        except Exception as exc:
            logger.error("URLhaus scraping failed: %s", exc)

        return items

    # ── Abuse.ch MalwareBazaar ────────────────────────────────────────────

    def _scrape_bazaar(self, limit: int = 25, **kwargs: Any) -> list[ScrapedItem]:
        items: list[ScrapedItem] = []

        try:
            resp = self.post(
                f"{self._bazaar_url}/",
                data={"query": "get_recent", "selector": min(limit, 100)},
            )
            if resp.status_code != 200:
                logger.warning("MalwareBazaar API returned %d", resp.status_code)
                return items

            data = resp.json()
            if data.get("query_status") != "ok":
                logger.warning("MalwareBazaar query_status: %s", data.get("query_status"))
                return items

            samples = data.get("data", [])

            for sample in samples[:limit]:
                sha256 = sample.get("sha256_hash", "")
                sha1 = sample.get("sha1_hash", "")
                md5 = sample.get("md5_hash", "")
                file_type = sample.get("file_type", "")
                file_size = sample.get("file_size", 0)
                signature = sample.get("signature", "")
                first_seen = sample.get("first_seen", "")
                reporter = sample.get("reporter", "")
                tags = sample.get("tags", []) or []
                delivery_method = sample.get("delivery_method", "")

                content_parts = [
                    f"[MalwareBazaar] Malware Sample",
                    f"SHA-256: {sha256}",
                    f"SHA-1: {sha1}",
                    f"MD5: {md5}",
                    f"File Type: {file_type}",
                    f"File Size: {file_size} bytes",
                    f"Signature: {signature}",
                    f"First Seen: {first_seen}",
                    f"Delivery Method: {delivery_method}",
                    f"Tags: {', '.join(str(t) for t in tags)}",
                    f"Reporter: {reporter}",
                ]
                content = "\n".join(content_parts)

                items.append(
                    ScrapedItem(
                        source_name="malwarebazaar",
                        source_url=f"https://bazaar.abuse.ch/sample/{sha256}/",
                        content=content,
                        http_status=resp.status_code,
                        metadata={
                            "sha256": sha256,
                            "md5": md5,
                            "signature": signature,
                            "file_type": file_type,
                            "tags": tags,
                        },
                    )
                )

        except Exception as exc:
            logger.error("MalwareBazaar scraping failed: %s", exc)

        return items

    # ── NIST NVD ──────────────────────────────────────────────────────────

    def _scrape_nvd(self, limit: int = 25, **kwargs: Any) -> list[ScrapedItem]:
        """
        Fetch CVE records from the NVD 2.0 API.

        Supports filtering by year or fetching a specific CVE ID.
        """
        items: list[ScrapedItem] = []
        cve_id = kwargs.get("cve_id")
        cve_year = kwargs.get("cve_year", self._nvd_default_year)

        headers: dict[str, str] = {}
        if self._nvd_key:
            headers["apiKey"] = self._nvd_key

        try:
            if cve_id:
                # Fetch a single CVE by ID
                params = {"cveId": cve_id}
            else:
                # Fetch recent CVEs for a given year, sorted by publish date descending
                params = {
                    "pubStartDate": f"{cve_year}-01-01T00:00:00.000",
                    "pubEndDate": f"{cve_year}-12-31T23:59:59.999",
                    "resultsPerPage": min(limit, self._nvd_per_page),
                    "startIndex": 0,
                }

            resp = self.get(self._nvd_base, headers=headers, params=params)
            if resp.status_code != 200:
                logger.warning("NVD API returned %d: %s", resp.status_code, resp.text[:300])
                return items

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln_wrapper in vulnerabilities[:limit]:
                cve = vuln_wrapper.get("cve", {})
                cve_id_val = cve.get("id", "")
                published = cve.get("published", "")
                last_modified = cve.get("lastModified", "")

                # Extract English description
                descriptions = cve.get("descriptions", [])
                desc_en = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_en = d.get("value", "")
                        break

                # Extract CVSS v3.1 score (fall back to v3.0, then v2.0)
                cvss_score = None
                cvss_severity = None
                cvss_version = None
                metrics = cve.get("metrics", {})

                for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(version_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity", "").upper()
                        cvss_version = cvss_data.get("version", version_key[-3:].replace("V", ""))
                        break

                # Extract affected product CPEs
                configs = cve.get("configurations", [])
                cpe_list: list[str] = []
                for config in configs:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable"):
                                cpe_list.append(match.get("criteria", ""))

                content_parts = [
                    f"[NVD CVE] {cve_id_val}",
                    f"Published: {published}",
                    f"Last Modified: {last_modified}",
                    f"CVSS Score: {cvss_score} ({cvss_severity})" if cvss_score else "CVSS: N/A",
                    f"CVSS Version: {cvss_version}" if cvss_version else "",
                    "",
                    f"Description: {desc_en}",
                    "",
                    f"Affected Products ({len(cpe_list)}):",
                    *[f"  {cpe}" for cpe in cpe_list[:20]],  # cap for readability
                ]
                content = "\n".join(line for line in content_parts if line is not None)

                items.append(
                    ScrapedItem(
                        source_name="nvd",
                        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id_val}",
                        content=content,
                        http_status=resp.status_code,
                        metadata={
                            "cve_id": cve_id_val,
                            "cvss_score": cvss_score,
                            "cvss_severity": cvss_severity,
                            "cvss_version": cvss_version,
                            "published": published,
                            "affected_products": cpe_list[:20],
                        },
                    )
                )

        except Exception as exc:
            logger.error("NVD scraping failed: %s", exc)

        return items
