"""
CSV Exporter.

Exports extracted IOCs, classifications, and CVE enrichments as
CSV files for analysts who prefer spreadsheets.

Supports filtering by entity type, date range, and confidence level.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


class CsvExporter:
    """
    Export toolkit data as CSV files.

    Usage::

        exporter = CsvExporter()
        exporter.export_entities(entities)
        exporter.export_entities(entities, ioc_type="ipv4")
        exporter.export_classifications(classifications)
        exporter.export_cve_enrichments(cve_data)
        exporter.export_all(entities, classifications, cve_data)
    """

    def __init__(self) -> None:
        self._output_dir = PROJECT_ROOT / settings.get("export.output_dir", "data/exports")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._include_headers = settings.get("export.csv.include_headers", True)

    def export_entities(
        self,
        entities: list[dict[str, Any]],
        filename: str = "iocs.csv",
        ioc_type: str | None = None,
        min_confidence: str | None = None,
    ) -> Path:
        """
        Export entities/IOCs to CSV.

        Args:
            entities:       List of entity dicts from the database.
            filename:       Output filename.
            ioc_type:       Filter to a specific entity type (e.g. "ipv4", "sha256").
            min_confidence: Minimum confidence level ("low", "medium", "high").

        Returns:
            Path to the written CSV file.
        """
        confidence_order = {"low": 0, "medium": 1, "high": 2}
        min_level = confidence_order.get(min_confidence, -1) if min_confidence else -1

        filtered = []
        for ent in entities:
            if ioc_type and ent.get("entity_type") != ioc_type:
                continue
            ent_conf = confidence_order.get(ent.get("confidence", "low"), 0)
            if ent_conf < min_level:
                continue
            filtered.append(ent)

        headers = [
            "entity_type", "value", "confidence", "extraction_method",
            "raw_match", "post_id", "created_at",
        ]

        out_path = self._output_dir / filename
        self._write_csv(out_path, headers, filtered)
        logger.info("Exported %d entities -> %s", len(filtered), out_path)
        return out_path

    def export_classifications(
        self,
        classifications: list[dict[str, Any]],
        filename: str = "classifications.csv",
    ) -> Path:
        """Export classification results to CSV."""
        headers = [
            "post_id", "category", "model_used", "confidence",
            "mitre_techniques", "classified_at", "content",
        ]

        # Truncate content for CSV readability
        rows = []
        for cls in classifications:
            row = dict(cls)
            content = row.get("content", "")
            row["content"] = content[:500] if content else ""
            rows.append(row)

        out_path = self._output_dir / filename
        self._write_csv(out_path, headers, rows)
        logger.info("Exported %d classifications -> %s", len(rows), out_path)
        return out_path

    def export_cve_enrichments(
        self,
        cve_data: list[dict[str, Any]],
        filename: str = "cve_enrichments.csv",
    ) -> Path:
        """Export CVE enrichment data to CSV."""
        headers = [
            "cve_id", "cvss_score", "cvss_version", "severity",
            "description", "affected_products", "published_date",
            "last_modified_date", "enriched_at",
        ]

        out_path = self._output_dir / filename
        self._write_csv(out_path, headers, cve_data)
        logger.info("Exported %d CVE enrichments -> %s", len(cve_data), out_path)
        return out_path

    def export_all(
        self,
        entities: list[dict[str, Any]],
        classifications: list[dict[str, Any]] | None = None,
        cve_enrichments: list[dict[str, Any]] | None = None,
        prefix: str = "",
    ) -> list[Path]:
        """
        Export all data types to separate CSV files.

        Returns list of paths to all created files.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        p = f"{prefix}_" if prefix else ""
        paths: list[Path] = []

        paths.append(self.export_entities(entities, f"{p}iocs_{ts}.csv"))

        if classifications:
            paths.append(
                self.export_classifications(classifications, f"{p}classifications_{ts}.csv")
            )

        if cve_enrichments:
            paths.append(
                self.export_cve_enrichments(cve_enrichments, f"{p}cve_enrichments_{ts}.csv")
            )

        # Also export per-IOC-type files for convenience
        ioc_types = {ent.get("entity_type") for ent in entities if ent.get("entity_type")}
        for ioc_type in sorted(ioc_types):
            paths.append(
                self.export_entities(
                    entities,
                    f"{p}iocs_{ioc_type}_{ts}.csv",
                    ioc_type=ioc_type,
                )
            )

        logger.info("Exported %d CSV files total", len(paths))
        return paths

    # ── Internal ──────────────────────────────────────────────────────────

    def _write_csv(
        self,
        path: Path,
        headers: list[str],
        rows: list[dict[str, Any]],
    ) -> None:
        """Write rows to a CSV file, extracting only the specified headers."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=headers,
                extrasaction="ignore",
                quoting=csv.QUOTE_MINIMAL,
            )
            if self._include_headers:
                writer.writeheader()
            for row in rows:
                writer.writerow(row)
