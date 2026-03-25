"""
Layer 4 — MITRE ATT&CK Technique Mapper.

Maps classified threat categories to relevant MITRE ATT&CK techniques
using the mapping config at ``config/mitre_attack_mapping.yaml``.

This enrichment layer adds ATT&CK context to every classified post,
connecting raw threat intelligence to the industry-standard framework
that defenders use for detection engineering and threat modeling.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


class MitreMapper:
    """
    Map threat classifications to MITRE ATT&CK techniques.

    Usage::

        mapper = MitreMapper()
        techniques = mapper.map("ransomware_malware")
        # [{"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}, ...]

        enriched = mapper.enrich_classification(result_dict)
        # adds "mitre_techniques" key to the classification result
    """

    def __init__(self, mapping_path: str | Path | None = None) -> None:
        if mapping_path is None:
            mapping_path = PROJECT_ROOT / settings.get(
                "classifier.mitre.mapping_path",
                "config/mitre_attack_mapping.yaml",
            )
        self._mapping = self._load_mapping(Path(mapping_path))
        logger.info(
            "MitreMapper loaded: %d categories, %d total techniques",
            len(self._mapping),
            sum(len(techs) for techs in self._mapping.values()),
        )

    # ── Public interface ──────────────────────────────────────────────────

    def map(self, category: str) -> list[dict[str, str]]:
        """
        Return ATT&CK techniques for a given threat category.

        Args:
            category: Internal category name (e.g. "ransomware_malware").

        Returns:
            List of dicts with keys: id, name, tactic.
            Empty list if category is unknown.
        """
        return self._mapping.get(category, [])

    def map_ids(self, category: str) -> list[str]:
        """Return just the technique IDs for a category (e.g. ["T1486", "T1059"])."""
        return [t["id"] for t in self.map(category)]

    def enrich_classification(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Add MITRE ATT&CK techniques to a classification result dict.

        Expects ``result["category"]`` to be set. Adds:
            - ``mitre_techniques``: Full technique dicts.
            - ``mitre_technique_ids``: Just the technique ID strings.
        """
        category = result.get("category", "unknown")
        techniques = self.map(category)

        enriched = dict(result)
        enriched["mitre_techniques"] = techniques
        enriched["mitre_technique_ids"] = [t["id"] for t in techniques]
        return enriched

    def enrich_batch(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich a batch of classification results with ATT&CK techniques."""
        return [self.enrich_classification(r) for r in results]

    def get_technique_summary(self) -> dict[str, list[dict[str, str]]]:
        """Return the full mapping for reporting/export purposes."""
        return dict(self._mapping)

    def get_all_technique_ids(self) -> set[str]:
        """Return all unique technique IDs across all categories."""
        ids: set[str] = set()
        for techniques in self._mapping.values():
            for t in techniques:
                ids.add(t["id"])
        return ids

    def get_display_name(self, category: str) -> str:
        """Return human-readable display name for a category."""
        return self._display_names.get(category, category)

    # ── Loading ───────────────────────────────────────────────────────────

    def _load_mapping(self, path: Path) -> dict[str, list[dict[str, str]]]:
        """Load MITRE ATT&CK mapping from YAML config."""
        if not path.exists():
            logger.warning("MITRE mapping not found: %s", path)
            return {}

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        categories = raw.get("categories", {})
        result: dict[str, list[dict[str, str]]] = {}
        self._display_names: dict[str, str] = {}

        for cat_name, cat_data in categories.items():
            self._display_names[cat_name] = cat_data.get("display_name", cat_name)
            techniques = cat_data.get("techniques", [])
            parsed: list[dict[str, str]] = []
            for tech in techniques:
                parsed.append({
                    "id": tech.get("id", ""),
                    "name": tech.get("name", ""),
                    "tactic": tech.get("tactic", ""),
                })
            result[cat_name] = parsed

        return result

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def categories(self) -> list[str]:
        return list(self._mapping.keys())
