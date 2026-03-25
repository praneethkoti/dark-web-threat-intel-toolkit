"""
MISP Event Exporter.

Generates MISP-compatible JSON events for teams using the MISP
threat sharing platform.  This is a standalone exporter that does
NOT require a running MISP instance or the pymisp library — it
produces spec-compliant JSON files that can be imported directly
into MISP via the REST API or web UI.

MISP event structure:
    - Event metadata (org, threat level, analysis state)
    - Attributes (IOCs mapped to MISP attribute types)
    - Tags (threat category, TLP marking)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

# Map our entity types to MISP attribute types and categories
_ENTITY_TO_MISP: dict[str, dict[str, str]] = {
    "ipv4": {"type": "ip-dst", "category": "Network activity"},
    "ipv6": {"type": "ip-dst", "category": "Network activity"},
    "domain": {"type": "domain", "category": "Network activity"},
    "url": {"type": "url", "category": "Network activity"},
    "email": {"type": "email-src", "category": "Payload delivery"},
    "md5": {"type": "md5", "category": "Payload delivery"},
    "sha1": {"type": "sha1", "category": "Payload delivery"},
    "sha256": {"type": "sha256", "category": "Payload delivery"},
    "bitcoin_address": {"type": "btc", "category": "Financial fraud"},
    "monero_address": {"type": "xmr", "category": "Financial fraud"},
    "cve_id": {"type": "vulnerability", "category": "External analysis"},
    "credential_pair": {"type": "text", "category": "Artifacts dropped"},
}

# Map threat categories to MISP tags
_CATEGORY_TO_TAGS: dict[str, list[str]] = {
    "data_breach": ["misp-galaxy:threat-actor=\"data-breach\"", "tlp:amber"],
    "exploit_vulnerability": ["misp-galaxy:tool=\"exploit-kit\"", "tlp:amber"],
    "ransomware_malware": ["misp-galaxy:ransomware=\"generic\"", "tlp:red"],
    "carding_fraud": ["misp-galaxy:threat-actor=\"financial-crime\"", "tlp:red"],
    "threat_actor_comms": ["misp-galaxy:threat-actor=\"unknown\"", "tlp:amber"],
    "zero_day": ["misp-galaxy:tool=\"0day\"", "tlp:red"],
}


class MispExporter:
    """
    Export IOCs as MISP-compatible JSON events.

    Usage::

        exporter = MispExporter()
        event = exporter.create_event(
            entities=entities,
            classifications=classifications,
            event_info="Dark Web Threat Intel — 2024-11-15",
        )
        exporter.save(event, "misp_event.json")
    """

    def __init__(self) -> None:
        self._output_dir = PROJECT_ROOT / settings.get("export.output_dir", "data/exports")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._org_name = settings.get("export.misp.org_name", "DarkWebToolkit")
        self._threat_level = settings.get("export.misp.event_threat_level", 2)

    def create_event(
        self,
        entities: list[dict[str, Any]],
        classifications: list[dict[str, Any]] | None = None,
        event_info: str = "Dark Web Threat Intelligence Report",
        threat_level: int | None = None,
    ) -> dict[str, Any]:
        """Build a MISP event JSON structure. threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined."""
        now = datetime.now(timezone.utc)
        event_uuid = str(uuid.uuid4())

        # Determine tags from classifications
        tags: list[dict[str, str]] = [
            {"name": "tlp:amber"},
            {"name": "type:OSINT"},
            {"name": f"source:{self._org_name}"},
        ]
        if classifications:
            seen_categories: set[str] = set()
            for cls in classifications:
                cat = cls.get("category", "")
                if cat and cat not in seen_categories:
                    seen_categories.add(cat)
                    for tag_name in _CATEGORY_TO_TAGS.get(cat, []):
                        tags.append({"name": tag_name})

        # Build attributes from entities
        attributes: list[dict[str, Any]] = []
        seen_values: set[str] = set()

        for entity in entities:
            etype = entity.get("entity_type", "")
            value = entity.get("value", "")
            confidence = entity.get("confidence", "medium")

            if not value or value in seen_values:
                continue
            seen_values.add(value)

            misp_mapping = _ENTITY_TO_MISP.get(etype)
            if not misp_mapping:
                continue

            # Map confidence to MISP's IDS flag (high confidence -> set IDS)
            to_ids = confidence == "high"

            attribute = {
                "uuid": str(uuid.uuid4()),
                "type": misp_mapping["type"],
                "category": misp_mapping["category"],
                "value": value,
                "to_ids": to_ids,
                "comment": f"Extracted from dark web intelligence ({etype}, confidence: {confidence})",
                "timestamp": str(int(now.timestamp())),
            }
            attributes.append(attribute)

        # Assemble the MISP event
        event = {
            "Event": {
                "uuid": event_uuid,
                "info": event_info,
                "date": now.strftime("%Y-%m-%d"),
                "threat_level_id": str(threat_level or self._threat_level),
                "analysis": "2",  # 0=Initial, 1=Ongoing, 2=Complete
                "distribution": "0",  # 0=Org only, 1=Community, 2=Connected, 3=All
                "published": False,
                "Orgc": {
                    "name": self._org_name,
                    "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, self._org_name)),
                },
                "Tag": tags,
                "Attribute": attributes,
                "attribute_count": str(len(attributes)),
            }
        }

        logger.info(
            "MISP event created: %d attributes, %d tags, uuid=%s",
            len(attributes), len(tags), event_uuid,
        )
        return event

    def save(
        self,
        event: dict[str, Any],
        filename: str = "misp_event.json",
    ) -> Path:
        """Save a MISP event to disk as JSON."""
        out_path = self._output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(event, f, ensure_ascii=False, indent=2)
        attr_count = len(event.get("Event", {}).get("Attribute", []))
        logger.info("MISP event saved: %s (%d attributes)", out_path, attr_count)
        return out_path

    def export(
        self,
        entities: list[dict[str, Any]],
        classifications: list[dict[str, Any]] | None = None,
        event_info: str = "Dark Web Threat Intelligence Report",
        filename: str = "misp_event.json",
    ) -> Path:
        """Convenience method: create event and save in one call."""
        event = self.create_event(entities, classifications, event_info)
        return self.save(event, filename)
