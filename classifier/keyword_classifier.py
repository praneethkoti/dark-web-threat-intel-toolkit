"""
Layer 1 — Keyword / Rule-Based Threat Classifier.

Uses weighted keyword dictionaries loaded from YAML to score text
against threat categories.

Scoring logic:
    - For each category, scan the text for matching keywords.
    - Sum the weights of all matched keywords = raw score.
    - Normalize via: confidence = min(1.0, raw_score / saturation_threshold).
      A saturation threshold of 5.0 means matching keywords with total
      weight >= 5 yields confidence 1.0.
    - The category with the highest score wins.
    - If the top score is below min_confidence, return "unknown".
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

# A raw weighted score at or above this value maps to confidence 1.0.
# Tuned so that 2-3 strong keyword matches (weight 2.5-3.0 each) yield
# high confidence, while a single weak match (weight 1.0) stays low.
_DEFAULT_SATURATION = 8.0


class KeywordClassifier:
    """
    Rule-based classifier using weighted keyword dictionaries.

    Usage::

        clf = KeywordClassifier()
        result = clf.classify("Fresh database dump — 50K credentials leaked")
        # result = {"category": "data_breach", "confidence": 0.72, ...}
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            config_path = PROJECT_ROOT / settings.get(
                "classifier.keyword.config_path",
                "classifier/keyword_configs/threat_keywords.yaml",
            )
        self._min_confidence = settings.get("classifier.keyword.min_confidence", 0.3)
        self._saturation = _DEFAULT_SATURATION
        self._categories = self._load_keywords(Path(config_path))
        logger.info(
            "KeywordClassifier loaded: %d categories, %d total keywords",
            len(self._categories),
            sum(len(kws) for kws in self._categories.values()),
        )

    # ── Public interface ──────────────────────────────────────────────────

    def classify(self, text: str) -> dict[str, Any]:
        """
        Classify a single text string.

        Returns:
            Dict with keys: category, confidence, scores,
            matched_keywords, model.
        """
        if not text or not text.strip():
            return self._empty_result()

        text_lower = text.lower()
        raw_scores: dict[str, float] = {}
        all_matches: list[tuple[str, float, str]] = []

        for category, keywords in self._categories.items():
            score = 0.0
            for term, weight in keywords:
                if term in text_lower:
                    score += weight
                    all_matches.append((term, weight, category))
            raw_scores[category] = score

        # Normalize scores using saturation threshold
        normalized: dict[str, float] = {}
        for cat, score in raw_scores.items():
            normalized[cat] = round(min(1.0, score / self._saturation), 4)

        # Find top category
        top_score = max(normalized.values()) if normalized else 0.0
        if top_score < self._min_confidence:
            return {
                "category": "unknown",
                "confidence": top_score,
                "scores": normalized,
                "matched_keywords": all_matches,
                "model": "keyword",
            }

        best_category = max(normalized, key=normalized.get)
        return {
            "category": best_category,
            "confidence": normalized[best_category],
            "scores": normalized,
            "matched_keywords": all_matches,
            "model": "keyword",
        }

    def classify_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Classify a list of texts. Returns list of result dicts."""
        return [self.classify(text) for text in texts]

    # ── Keyword loading ───────────────────────────────────────────────────

    def _load_keywords(self, path: Path) -> dict[str, list[tuple[str, float]]]:
        """Load keyword dictionaries from YAML config."""
        if not path.exists():
            logger.warning("Keyword config not found: %s", path)
            return {}

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        categories = raw.get("categories", {})
        result: dict[str, list[tuple[str, float]]] = {}

        for cat_name, cat_data in categories.items():
            keywords = cat_data.get("keywords", [])
            parsed: list[tuple[str, float]] = []
            for kw in keywords:
                term = kw.get("term", "").lower().strip()
                weight = float(kw.get("weight", 1.0))
                if term:
                    parsed.append((term, weight))
            result[cat_name] = parsed

        return result

    def _empty_result(self) -> dict[str, Any]:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "scores": {},
            "matched_keywords": [],
            "model": "keyword",
        }

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def categories(self) -> list[str]:
        """Return list of known category names."""
        return list(self._categories.keys())

    def get_keywords(self, category: str) -> list[tuple[str, float]]:
        """Return keywords and weights for a given category."""
        return self._categories.get(category, [])
