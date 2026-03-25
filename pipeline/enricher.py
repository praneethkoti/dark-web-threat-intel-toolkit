"""
Pipeline Stage 3 — Entity Enrichment.

For extracted CVE IDs, queries the NIST NVD 2.0 API to pull:
    - CVSS score and version
    - Severity rating
    - Description
    - Affected products (CPE strings)

Results are cached in the ``cve_enrichment`` table to avoid redundant
API calls.  Rate limiting respects NVD's published limits.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from config import settings
from pipeline.entity_extractor import ExtractedEntity

logger = logging.getLogger(__name__)


class CVEEnrichmentResult:
    """Structured result of a single CVE enrichment lookup."""

    def __init__(
        self,
        cve_id: str,
        cvss_score: float | None = None,
        cvss_version: str | None = None,
        severity: str | None = None,
        description: str = "",
        affected_products: list[str] | None = None,
        published_date: str = "",
        last_modified_date: str = "",
    ) -> None:
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.cvss_version = cvss_version
        self.severity = severity
        self.description = description
        self.affected_products = affected_products or []
        self.published_date = published_date
        self.last_modified_date = last_modified_date

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "severity": self.severity,
            "description": self.description,
            "affected_products": self.affected_products,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
        }

    def __repr__(self) -> str:
        return (
            f"<CVEEnrichment {self.cve_id} "
            f"cvss={self.cvss_score} severity={self.severity}>"
        )


class Enricher:
    """
    Enrich extracted entities with external intelligence data.

    Currently supports CVE enrichment via NVD.  Designed to be extended
    with IP/domain reputation lookups via the same interface pattern.

    Usage::

        enricher = Enricher()
        results = enricher.enrich_cves(["CVE-2024-21887", "CVE-2024-3400"])
    """

    def __init__(self) -> None:
        self._nvd_url = settings.get(
            "pipeline.enrichment.nvd_api_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        )
        self._nvd_delay = settings.get("pipeline.enrichment.nvd_delay_seconds", 1.0)
        self._nvd_enabled = settings.get("pipeline.enrichment.nvd_enabled", True)
        self._nvd_key = settings.get("_env.nvd_api_key", "")

        # In-memory cache to avoid re-fetching within a single run
        self._cache: dict[str, CVEEnrichmentResult] = {}

    # -- Public API --------------------------------------------------------

    def enrich_cves(
        self,
        cve_ids: list[str],
        skip_cached: set[str] | None = None,
    ) -> list[CVEEnrichmentResult]:
        """
        Enrich a list of CVE IDs via the NVD API.

        Args:
            cve_ids:      List of CVE ID strings.
            skip_cached:  Set of CVE IDs already in the DB.

        Returns:
            List of enrichment results for successfully fetched CVEs.
        """
        if not self._nvd_enabled:
            logger.info("NVD enrichment is disabled in config.")
            return []

        skip = skip_cached or set()
        unique_ids = list(dict.fromkeys(cve_ids))
        results: list[CVEEnrichmentResult] = []

        for cve_id in unique_ids:
            cve_id = cve_id.upper().strip()

            if cve_id in skip:
                logger.debug("Skipping already-enriched CVE: %s", cve_id)
                continue

            if cve_id in self._cache:
                results.append(self._cache[cve_id])
                continue

            result = self._fetch_cve(cve_id)
            if result is not None:
                self._cache[cve_id] = result
                results.append(result)

        logger.info(
            "CVE enrichment: %d requested, %d skipped, %d fetched",
            len(unique_ids), len(skip & set(unique_ids)), len(results),
        )
        return results

    def enrich_entities(
        self,
        entities: list[ExtractedEntity],
        skip_cached: set[str] | None = None,
    ) -> list[CVEEnrichmentResult]:
        """Convenience: extract CVE IDs from entities and enrich them."""
        cve_ids = [e.value for e in entities if e.entity_type == "cve_id"]
        if not cve_ids:
            return []
        return self.enrich_cves(cve_ids, skip_cached)

    # -- NVD API -----------------------------------------------------------

    def _fetch_cve(self, cve_id: str) -> CVEEnrichmentResult | None:
        # NVD rate-limits hard without an API key: 5 req/30s vs 50 req/30s with one
        params: dict[str, str] = {"cveId": cve_id}
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._nvd_key:
            headers["apiKey"] = self._nvd_key

        try:
            time.sleep(self._nvd_delay)
            resp = requests.get(
                self._nvd_url, params=params, headers=headers, timeout=30
            )

            if resp.status_code == 403:
                logger.warning("NVD rate limit hit for %s", cve_id)
                time.sleep(10)
                return None

            if resp.status_code != 200:
                logger.warning("NVD returned %d for %s", resp.status_code, cve_id)
                return None

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                logger.debug("No NVD data for %s", cve_id)
                return None

            cve_data = vulns[0].get("cve", {})
            return self._parse_nvd_response(cve_id, cve_data)

        except requests.RequestException as exc:
            logger.error("NVD request failed for %s: %s", cve_id, exc)
            return None

    def _parse_nvd_response(
        self, cve_id: str, cve_data: dict[str, Any]
    ) -> CVEEnrichmentResult:
        """Parse raw NVD JSON into a structured enrichment result."""

        # Description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        desc_en = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
                break

        # CVSS -- try v3.1, then v3.0, then v2.0
        cvss_score = None
        cvss_severity = None
        cvss_version = None
        metrics = cve_data.get("metrics", {})

        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_obj = metric_list[0].get("cvssData", {})
                cvss_score = cvss_obj.get("baseScore")
                cvss_severity = cvss_obj.get("baseSeverity", "").upper()
                cvss_version = cvss_obj.get("version", "")
                break

        # Affected products (CPE strings)
        cpe_list: list[str] = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe_list.append(match.get("criteria", ""))

        return CVEEnrichmentResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            severity=cvss_severity or self._score_to_severity(cvss_score),
            description=desc_en,
            affected_products=cpe_list[:30],
            published_date=cve_data.get("published", ""),
            last_modified_date=cve_data.get("lastModified", ""),
        )

    @staticmethod
    def _score_to_severity(score: float | None) -> str:
        # Fallback when NVD doesn't include baseSeverity in the response
        if score is None:
            return "NONE"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"
