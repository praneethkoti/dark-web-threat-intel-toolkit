"""
STIX 2.1 Exporter.

Generates STIX 2.1 bundles from extracted IOCs and enrichment data.
Objects created:
    - Identity (the toolkit itself as the reporting source)
    - Indicator (IPs, domains, hashes, emails, URLs, crypto wallets)
    - Vulnerability (from CVE enrichment data)
    - Malware (from ransomware/malware classifications)
    - Relationship (links indicators to vulnerabilities/malware)

Uses the ``stix2`` Python library for spec-compliant output.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import stix2

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

# Map our entity types to STIX indicator patterns
_ENTITY_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
}

# Map threat categories to STIX indicator labels
_CATEGORY_TO_LABELS: dict[str, list[str]] = {
    "data_breach": ["compromised", "credential-theft"],
    "exploit_vulnerability": ["malicious-activity", "exploit-kit"],
    "ransomware_malware": ["malicious-activity", "ransomware"],
    "carding_fraud": ["malicious-activity", "fraud"],
    "threat_actor_comms": ["malicious-activity", "threat-actor"],
    "zero_day": ["malicious-activity", "exploit-kit"],
}


class StixExporter:
    """
    Export IOCs and threat data as STIX 2.1 bundles.

    Usage::

        exporter = StixExporter()
        bundle = exporter.create_bundle(entities, cve_enrichments, classifications)
        exporter.save(bundle, "output.json")
    """

    def __init__(self) -> None:
        self._output_dir = PROJECT_ROOT / settings.get("export.output_dir", "data/exports")
        self._output_dir.mkdir(parents=True, exist_ok=True)

        identity_name = settings.get("export.stix.identity_name", "DarkWebToolkit")
        self._identity = stix2.Identity(
            name=identity_name,
            identity_class="system",
            description="Dark Web Threat Intelligence Toolkit — automated IOC collection and analysis",
        )

    def create_bundle(
        self,
        entities: list[dict[str, Any]],
        cve_enrichments: list[dict[str, Any]] | None = None,
        classifications: list[dict[str, Any]] | None = None,
    ) -> stix2.Bundle:
        """Build a STIX 2.1 bundle from extracted entities, CVE enrichments, and classifications."""
        objects: list[Any] = [self._identity]

        # Track created objects for relationship building
        indicator_map: dict[str, stix2.Indicator] = {}  # value -> Indicator
        vulnerability_map: dict[str, stix2.Vulnerability] = {}  # cve_id -> Vulnerability
        malware_objects: list[stix2.Malware] = []

        # ── Create Indicators from entities ───────────────────────────
        for entity in entities:
            etype = entity.get("entity_type", "")
            value = entity.get("value", "")
            confidence_str = entity.get("confidence", "medium")

            if not value or etype not in _ENTITY_TO_STIX_PATTERN:
                continue

            # Skip if we already created an indicator for this value
            if value in indicator_map:
                continue

            pattern = _ENTITY_TO_STIX_PATTERN[etype].format(value=value)
            confidence_score = {"high": 85, "medium": 50, "low": 25}.get(confidence_str, 50)

            try:
                indicator = stix2.Indicator(
                    name=f"{etype.upper()}: {value}",
                    description=f"Extracted {etype} indicator from dark web intelligence collection",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    confidence=confidence_score,
                    created_by_ref=self._identity.id,
                    labels=["malicious-activity"],
                )
                objects.append(indicator)
                indicator_map[value] = indicator
            except Exception as exc:
                logger.debug("Failed to create indicator for %s=%s: %s", etype, value, exc)

        # ── Create Vulnerability objects from CVE enrichments ─────────
        if cve_enrichments:
            for cve in cve_enrichments:
                cve_id = cve.get("cve_id", "")
                if not cve_id or cve_id in vulnerability_map:
                    continue

                description = cve.get("description", "")
                cvss = cve.get("cvss_score")
                severity = cve.get("severity", "")

                ext_refs = [
                    stix2.ExternalReference(
                        source_name="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        external_id=cve_id,
                    )
                ]

                try:
                    vuln = stix2.Vulnerability(
                        name=cve_id,
                        description=f"{description[:500]}. CVSS: {cvss} ({severity})" if description else f"{cve_id} — CVSS {cvss} ({severity})",
                        external_references=ext_refs,
                        created_by_ref=self._identity.id,
                    )
                    objects.append(vuln)
                    vulnerability_map[cve_id] = vuln
                except Exception as exc:
                    logger.debug("Failed to create vulnerability for %s: %s", cve_id, exc)

        # ── Create Malware objects from ransomware/malware classifications ──
        if classifications:
            seen_malware: set[str] = set()
            for cls in classifications:
                category = cls.get("category", "")
                if category != "ransomware_malware":
                    continue

                # Use a portion of the content as the malware description
                content = cls.get("content", "")[:300]
                # Create a unique key to avoid duplicate malware objects
                content_key = content[:50]
                if content_key in seen_malware:
                    continue
                seen_malware.add(content_key)

                try:
                    malware = stix2.Malware(
                        name=f"Malware/Ransomware (classified)",
                        description=f"Classified as ransomware/malware: {content[:200]}",
                        is_family=False,
                        malware_types=["ransomware"],
                        created_by_ref=self._identity.id,
                    )
                    objects.append(malware)
                    malware_objects.append(malware)
                except Exception as exc:
                    logger.debug("Failed to create malware object: %s", exc)

        # ── Create Relationships ──────────────────────────────────────
        # Link hash indicators to malware objects
        for value, indicator in indicator_map.items():
            if "file:hashes" in indicator.pattern and malware_objects:
                try:
                    rel = stix2.Relationship(
                        source_ref=indicator.id,
                        target_ref=malware_objects[0].id,
                        relationship_type="indicates",
                        created_by_ref=self._identity.id,
                    )
                    objects.append(rel)
                except Exception as exc:
                    logger.debug("Failed to create relationship: %s", exc)

        bundle = stix2.Bundle(objects=objects)
        logger.info(
            "STIX bundle created: %d objects (%d indicators, %d vulnerabilities, %d malware)",
            len(objects),
            len(indicator_map),
            len(vulnerability_map),
            len(malware_objects),
        )
        return bundle

    def save(
        self,
        bundle: stix2.Bundle,
        filename: str = "threat_intel_bundle.json",
    ) -> Path:
        """Save a STIX bundle to disk as JSON."""
        out_path = self._output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(bundle.serialize(pretty=True))
        logger.info("STIX bundle saved: %s (%d objects)", out_path, len(bundle.objects))
        return out_path

    def export(
        self,
        entities: list[dict[str, Any]],
        cve_enrichments: list[dict[str, Any]] | None = None,
        classifications: list[dict[str, Any]] | None = None,
        filename: str = "threat_intel_bundle.json",
    ) -> Path:
        """Convenience method: create bundle and save in one call."""
        bundle = self.create_bundle(entities, cve_enrichments, classifications)
        return self.save(bundle, filename)
