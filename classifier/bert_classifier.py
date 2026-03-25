"""
Layer 3 — Transformer-Based Threat Classifier.

Uses zero-shot classification via Hugging Face ``transformers`` to
classify threat posts without requiring labeled training data.

Default model: ``facebook/bart-large-mnli`` — a strong zero-shot
classifier that maps text to arbitrary candidate labels.

Falls back gracefully if transformers/torch are not installed.
"""

from __future__ import annotations

import logging
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

# Lazy-loaded pipeline to avoid heavy imports at module load
_pipeline = None


def _get_pipeline():
    """Load the zero-shot classification pipeline lazily."""
    global _pipeline
    if _pipeline is None:
        try:
            from transformers import pipeline as hf_pipeline
            model_name = settings.get(
                "classifier.transformer.model_name",
                "facebook/bart-large-mnli",
            )
            device_str = settings.get("classifier.transformer.device", "cpu")
            device = -1 if device_str == "cpu" else 0

            logger.info("Loading zero-shot model: %s (device=%s)", model_name, device_str)
            _pipeline = hf_pipeline(
                "zero-shot-classification",
                model=model_name,
                device=device,
            )
            logger.info("Zero-shot model loaded successfully")
        except ImportError:
            logger.error(
                "transformers library not installed. "
                "Install with: pip install transformers torch"
            )
            raise
        except Exception as exc:
            logger.error("Failed to load zero-shot model: %s", exc)
            raise
    return _pipeline


class TransformerClassifier:
    """
    Zero-shot threat classifier using pre-trained NLI models.

    Usage::

        clf = TransformerClassifier()
        result = clf.classify("Selling 0day exploit for VPN product")
        # {"category": "zero_day", "confidence": 0.82, ...}

        results = clf.classify_batch(["text1", "text2"])
    """

    def __init__(self) -> None:
        self._candidate_labels = settings.get(
            "classifier.transformer.candidate_labels",
            [
                "data breach",
                "exploit or vulnerability",
                "ransomware or malware",
                "carding or financial fraud",
                "threat actor communication",
                "zero-day discussion",
            ],
        )
        self._batch_size = settings.get("classifier.transformer.batch_size", 16)

        # Map human-readable labels back to our internal category names
        self._label_to_category = {
            "data breach": "data_breach",
            "exploit or vulnerability": "exploit_vulnerability",
            "ransomware or malware": "ransomware_malware",
            "carding or financial fraud": "carding_fraud",
            "threat actor communication": "threat_actor_comms",
            "zero-day discussion": "zero_day",
        }

    # ── Public interface ──────────────────────────────────────────────────

    def classify(self, text: str) -> dict[str, Any]:
        """
        Classify a single text using zero-shot inference.

        Returns:
            Dict with category, confidence, all_scores, and model name.
        """
        if not text or not text.strip():
            return self._empty_result()

        try:
            pipe = _get_pipeline()
        except Exception:
            return self._empty_result()

        # Truncate very long texts (transformers have token limits)
        max_chars = 1024
        truncated = text[:max_chars]

        try:
            result = pipe(
                truncated,
                candidate_labels=self._candidate_labels,
                multi_label=False,
            )

            # result = {"labels": [...], "scores": [...], "sequence": "..."}
            top_label = result["labels"][0]
            top_score = result["scores"][0]
            category = self._label_to_category.get(top_label, "unknown")

            all_scores = {
                self._label_to_category.get(label, label): round(score, 4)
                for label, score in zip(result["labels"], result["scores"])
            }

            return {
                "category": category,
                "confidence": round(top_score, 4),
                "scores": all_scores,
                "model": "zero_shot",
            }

        except Exception as exc:
            logger.error("Zero-shot classification failed: %s", exc)
            return self._empty_result()

    def classify_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """
        Classify multiple texts.  Processes in batches for efficiency.
        """
        if not texts:
            return []

        try:
            pipe = _get_pipeline()
        except Exception:
            return [self._empty_result() for _ in texts]

        results: list[dict[str, Any]] = []
        max_chars = 1024

        # Process in batches
        for i in range(0, len(texts), self._batch_size):
            batch = texts[i:i + self._batch_size]
            truncated = [t[:max_chars] for t in batch]

            try:
                batch_results = pipe(
                    truncated,
                    candidate_labels=self._candidate_labels,
                    multi_label=False,
                    batch_size=self._batch_size,
                )

                # pipe returns a single dict for 1 item, list for multiple
                if isinstance(batch_results, dict):
                    batch_results = [batch_results]

                for result in batch_results:
                    top_label = result["labels"][0]
                    top_score = result["scores"][0]
                    category = self._label_to_category.get(top_label, "unknown")

                    all_scores = {
                        self._label_to_category.get(l, l): round(s, 4)
                        for l, s in zip(result["labels"], result["scores"])
                    }

                    results.append({
                        "category": category,
                        "confidence": round(top_score, 4),
                        "scores": all_scores,
                        "model": "zero_shot",
                    })

            except Exception as exc:
                logger.error("Batch classification failed: %s", exc)
                results.extend([self._empty_result() for _ in batch])

        return results

    # ── Helpers ────────────────────────────────────────────────────────────

    def _empty_result(self) -> dict[str, Any]:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "scores": {},
            "model": "zero_shot",
        }

    @property
    def candidate_labels(self) -> list[str]:
        return list(self._candidate_labels)

    @property
    def category_map(self) -> dict[str, str]:
        return dict(self._label_to_category)
