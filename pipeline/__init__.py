"""
pipeline — Multi-stage data processing pipeline.

Orchestrates: Cleaning -> Entity Extraction -> Enrichment -> DB Storage.

Usage::

    from pipeline import Pipeline

    pipe = Pipeline()
    stats = pipe.run(scraped_items)          # Full pipeline
    stats = pipe.run_from_files("data/raw")  # From saved JSON files
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT
from pipeline.cleaner import DataCleaner
from pipeline.entity_extractor import EntityExtractor, ExtractedEntity
from pipeline.enricher import Enricher
from pipeline.db_loader import DatabaseLoader

logger = logging.getLogger(__name__)

__all__ = [
    "Pipeline",
    "PipelineStats",
    "DataCleaner",
    "EntityExtractor",
    "ExtractedEntity",
    "Enricher",
    "DatabaseLoader",
]


class PipelineStats:
    """Tracks metrics across a pipeline run for reporting."""

    def __init__(self) -> None:
        self.items_input: int = 0
        self.items_cleaned: int = 0
        self.items_stored: int = 0
        self.duplicates_skipped: int = 0
        self.entities_extracted: int = 0
        self.cves_enriched: int = 0
        self.errors: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "items_input": self.items_input,
            "items_cleaned": self.items_cleaned,
            "items_stored": self.items_stored,
            "duplicates_skipped": self.duplicates_skipped,
            "entities_extracted": self.entities_extracted,
            "cves_enriched": self.cves_enriched,
            "errors": self.errors,
        }

    def __repr__(self) -> str:
        return (
            f"PipelineStats(input={self.items_input}, cleaned={self.items_cleaned}, "
            f"stored={self.items_stored}, dupes={self.duplicates_skipped}, "
            f"entities={self.entities_extracted}, cves={self.cves_enriched}, "
            f"errors={self.errors})"
        )


class Pipeline:
    """
    End-to-end processing pipeline.

    Chains all four stages and handles the handoff between them.
    Designed to be idempotent — running it twice on the same data will
    not create duplicate records in the database.
    """

    def __init__(
        self,
        db: DatabaseLoader | None = None,
        skip_enrichment: bool = False,
        use_ner: bool = True,
    ) -> None:
        self._cleaner = DataCleaner()
        self._extractor = EntityExtractor(use_ner=use_ner)
        self._enricher = Enricher() if not skip_enrichment else None
        self._db = db or DatabaseLoader()
        self._db.init_schema()

    def run(
        self,
        scraped_items: list[dict[str, Any]],
        source_type: str = "unknown",
    ) -> PipelineStats:
        """
        Run the full pipeline on a list of scraped item dicts.

        Each dict should have at minimum: content, source_name,
        source_url, scraped_at, content_hash.

        Args:
            scraped_items: Output from any scraper's .to_dict() calls.
            source_type:   Type label for the source (paste, feed, simulated).

        Returns:
            PipelineStats with counts for each stage.
        """
        stats = PipelineStats()
        stats.items_input = len(scraped_items)
        logger.info("Pipeline started: %d items", stats.items_input)

        # ── Stage 1: Clean ────────────────────────────────────────────
        existing_hashes = self._db.get_existing_hashes()
        cleaned = self._cleaner.clean_batch(scraped_items, seen_hashes=existing_hashes)
        stats.items_cleaned = len(cleaned)
        stats.duplicates_skipped = stats.items_input - stats.items_cleaned
        logger.info(
            "Stage 1 (Clean): %d -> %d items", stats.items_input, stats.items_cleaned
        )

        if not cleaned:
            logger.info("Pipeline finished early — no new items after cleaning")
            return stats

        # ── Stage 2: Extract entities ─────────────────────────────────
        extracted = self._extractor.extract_batch(cleaned)
        stats.entities_extracted = sum(
            len(item.get("entities", [])) for item in extracted
        )
        logger.info(
            "Stage 2 (Extract): %d entities from %d items",
            stats.entities_extracted,
            len(extracted),
        )

        # ── Stage 3: Enrich CVEs ──────────────────────────────────────
        if self._enricher:
            enriched = self._enricher.enrich_batch(extracted)
            stats.cves_enriched = sum(
                len(item.get("cve_enrichments", {})) for item in enriched
            )
            logger.info("Stage 3 (Enrich): %d CVEs enriched", stats.cves_enriched)
        else:
            enriched = extracted
            logger.info("Stage 3 (Enrich): skipped")

        # ── Stage 4: Store in database ────────────────────────────────
        for item in enriched:
            try:
                # Get or create source
                source_name = item.get("source_name", "unknown")
                source_url = item.get("source_url", "")
                source_id = self._db.get_or_create_source(
                    source_name, source_type, source_url
                )

                # Insert raw post
                content_hash = item.get(
                    "cleaned_content_hash", item.get("content_hash", "")
                )
                post_id = self._db.insert_raw_post(
                    source_id=source_id,
                    content=item.get("cleaned_content", item.get("content", "")),
                    content_hash=content_hash,
                    scraped_at=item.get("scraped_at", ""),
                    http_status=item.get("http_status"),
                    url=source_url,
                    metadata=item.get("metadata"),
                )

                if post_id is None:
                    # Duplicate in DB — look up existing post_id for entity insertion
                    post_id = self._db.get_post_id_by_hash(content_hash)
                    if post_id is None:
                        stats.duplicates_skipped += 1
                        continue
                else:
                    stats.items_stored += 1

                # Insert entities
                entities = item.get("entities", [])
                if entities:
                    self._db.insert_entities(post_id, entities)

                # Store CVE enrichments
                cve_enrichments = item.get("cve_enrichments", {})
                for cve_id, cve_data in cve_enrichments.items():
                    self._db.upsert_cve_enrichment(cve_data)

                # Update source last-scraped timestamp
                self._db.update_source_last_scraped(source_id)

            except Exception as exc:
                logger.error("Pipeline storage error: %s", exc)
                stats.errors += 1

        logger.info("Stage 4 (Store): %d new posts stored", stats.items_stored)
        logger.info("Pipeline complete: %s", stats)
        return stats

    def run_from_files(self, input_dir: str | Path) -> PipelineStats:
        """
        Run the pipeline on all JSON files in a directory.

        Useful for reprocessing previously saved raw scrape data.
        """
        input_path = Path(input_dir)
        if not input_path.is_absolute():
            input_path = PROJECT_ROOT / input_path

        all_items: list[dict[str, Any]] = []

        for json_file in sorted(input_path.glob("*.json")):
            try:
                with open(json_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    all_items.extend(data)
                    logger.info("Loaded %d items from %s", len(data), json_file.name)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load %s: %s", json_file, exc)

        if not all_items:
            logger.warning("No items found in %s", input_path)
            return PipelineStats()

        return self.run(all_items)

    def close(self) -> None:
        """Clean up resources."""
        if self._enricher:
            self._enricher.close()
        self._db.close()

    def __enter__(self) -> "Pipeline":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
