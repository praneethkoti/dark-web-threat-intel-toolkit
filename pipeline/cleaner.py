"""
Pipeline Stage 1 — Data Cleaning.

Takes raw scraped content and produces clean, normalized text ready for
entity extraction.  Operations:

    1. HTML tag stripping (preserves meaningful text).
    2. Unicode normalization (NFKC).
    3. Encoding fixes (mojibake repair).
    4. Noise removal (ads, nav elements, boilerplate).
    5. Whitespace normalization.
    6. Content-hash deduplication.

The cleaner is idempotent — running it twice on the same input produces
the same output without side effects.
"""

from __future__ import annotations

import hashlib
import html as html_module
import logging
import re
import unicodedata
from typing import Any

from bs4 import BeautifulSoup

from config import settings

logger = logging.getLogger(__name__)

# Noise patterns — common boilerplate / ad fragments to strip
_NOISE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(advertisement|sponsored|click here to subscribe)"),
    re.compile(r"(?i)(cookie policy|privacy policy|terms of service|all rights reserved)"),
    re.compile(r"(?i)(navigation|breadcrumb|sidebar|footer|header menu)"),
    re.compile(r"\u26a1.*\u26a1"),          # Lightning bolt ad wrappers
    re.compile(r"\U0001f512.*\U0001f512"),   # Lock emoji wrappers
]

# Tags whose entire content is noise
_NOISE_TAGS = {"nav", "header", "footer", "aside", "script", "style", "noscript", "iframe"}


class DataCleaner:
    """
    Stateless text-cleaning pipeline.

    Usage::

        cleaner = DataCleaner()
        cleaned = cleaner.clean(raw_text)
        batch_results = cleaner.clean_batch(items, seen_hashes)
    """

    def __init__(self) -> None:
        self._min_length = settings.get("pipeline.cleaning.min_content_length", 20)
        self._remove_html = settings.get("pipeline.cleaning.remove_html", True)
        self._normalize_unicode = settings.get("pipeline.cleaning.normalize_unicode", True)
        self._dedup = settings.get("pipeline.cleaning.dedup_enabled", True)

    # ── Single-item cleaning ──────────────────────────────────────────────

    def clean(self, text: str) -> str:
        """
        Apply the full cleaning pipeline to a single text string.
        Returns cleaned text, or empty string if content is too short/noise.
        """
        if not text or not text.strip():
            return ""

        text = html_module.unescape(text)

        if self._remove_html and ("<" in text and ">" in text):
            text = self._strip_html(text)

        if self._normalize_unicode:
            text = self._normalize(text)

        text = self._fix_encoding(text)
        text = self._remove_noise(text)
        text = self._normalize_whitespace(text)

        if len(text.strip()) < self._min_length:
            return ""

        return text.strip()

    # ── Batch cleaning with deduplication ─────────────────────────────────

    def clean_batch(
        self,
        items: list[dict[str, Any]],
        seen_hashes: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Clean a batch of scraped items (dicts with "content" key).

        Args:
            items:       List of dicts from ScrapedItem.to_dict().
            seen_hashes: Set of content hashes already in the database.
                         Items whose cleaned content matches are dropped.

        Returns:
            Cleaned items with "cleaned_content" and
            "cleaned_content_hash" added. Duplicates and empty
            items are excluded.
        """
        if seen_hashes is None:
            seen_hashes = set()

        results: list[dict[str, Any]] = []
        batch_hashes: set[str] = set()

        for item in items:
            raw = item.get("content", "")
            cleaned = self.clean(raw)

            if not cleaned:
                logger.debug("Dropped empty/short item from %s", item.get("source_name"))
                continue

            content_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

            if self._dedup:
                if content_hash in seen_hashes or content_hash in batch_hashes:
                    logger.debug("Duplicate skipped: %s...", content_hash[:12])
                    continue
                batch_hashes.add(content_hash)

            enriched = dict(item)
            enriched["cleaned_content"] = cleaned
            enriched["cleaned_content_hash"] = content_hash
            results.append(enriched)

        logger.info(
            "Cleaned batch: %d input -> %d output (%d dropped)",
            len(items), len(results), len(items) - len(results),
        )
        return results

    # ── Internal cleaning steps ───────────────────────────────────────────

    def _strip_html(self, text: str) -> str:
        soup = BeautifulSoup(text, "lxml")

        # Remove entire noise elements
        for tag_name in _NOISE_TAGS:
            for tag in soup.find_all(tag_name):
                tag.decompose()

        # Remove ad banners by class name patterns
        for el in soup.find_all(class_=re.compile(r"(?i)(ad-banner|sponsor|promo|cookie)")):
            el.decompose()

        return soup.get_text(separator="\n")

    def _normalize(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)

    def _fix_encoding(self, text: str) -> str:
        # These byte sequences show up when UTF-8 is decoded as latin-1
        replacements = {
            "\xe2\x80\x99": "'",
            "\xe2\x80\x9c": "\u201c",
            "\xe2\x80\x9d": "\u201d",
            "\xe2\x80\x93": "\u2013",
            "\xe2\x80\x94": "\u2014",
            "\xe2\x80\xa6": "\u2026",
            "\ufffd": "",
            "\x00": "",
        }
        for bad, good in replacements.items():
            text = text.replace(bad, good)
        return text

    def _remove_noise(self, text: str) -> str:
        lines = text.split("\n")
        cleaned_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                if cleaned_lines and cleaned_lines[-1] != "":
                    cleaned_lines.append("")
                continue

            is_noise = False
            for pattern in _NOISE_PATTERNS:
                if pattern.search(stripped):
                    is_noise = True
                    break

            if not is_noise:
                cleaned_lines.append(stripped)

        return "\n".join(cleaned_lines)

    def _normalize_whitespace(self, text: str) -> str:
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        return text

    # ── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def content_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
