"""
Tests for the export module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_export.py -v
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from export.stix_exporter import StixExporter
from export.csv_exporter import CsvExporter
from export.misp_exporter import MispExporter


# ── Shared test data ──────────────────────────────────────────────────────────

@pytest.fixture
def sample_entities():
    return [
        {"entity_type": "ipv4", "value": "185.220.101.34", "confidence": "high",
         "extraction_method": "regex", "raw_match": "185.220.101.34", "post_id": 1,
         "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "ipv4", "value": "91.92.240.113", "confidence": "high",
         "extraction_method": "regex", "raw_match": "91.92.240.113", "post_id": 1,
         "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "domain", "value": "update-service-cdn.com", "confidence": "high",
         "extraction_method": "regex", "raw_match": "update-service-cdn[.]com", "post_id": 2,
         "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "sha256", "value": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
         "confidence": "high", "extraction_method": "regex",
         "raw_match": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
         "post_id": 2, "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "md5", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         "confidence": "medium", "extraction_method": "regex",
         "raw_match": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         "post_id": 3, "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "email", "value": "recovery@protonmail.ch", "confidence": "high",
         "extraction_method": "regex", "raw_match": "recovery@protonmail.ch",
         "post_id": 3, "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "bitcoin_address", "value": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
         "confidence": "high", "extraction_method": "regex",
         "raw_match": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
         "post_id": 4, "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "cve_id", "value": "CVE-2024-21887", "confidence": "high",
         "extraction_method": "regex", "raw_match": "CVE-2024-21887",
         "post_id": 1, "created_at": "2024-11-15T00:00:00Z"},
        {"entity_type": "url", "value": "https://malware.example.com/payload.exe",
         "confidence": "high", "extraction_method": "regex",
         "raw_match": "https://malware.example.com/payload.exe",
         "post_id": 5, "created_at": "2024-11-15T00:00:00Z"},
    ]


@pytest.fixture
def sample_cve_enrichments():
    return [
        {
            "cve_id": "CVE-2024-21887",
            "cvss_score": 9.1,
            "cvss_version": "3.1",
            "severity": "CRITICAL",
            "description": "Command injection vulnerability in Ivanti Connect Secure",
            "affected_products": '["cpe:2.3:a:ivanti:connect_secure:*"]',
            "published_date": "2024-01-12",
            "last_modified_date": "2024-02-01",
            "enriched_at": "2024-11-15T00:00:00Z",
        },
        {
            "cve_id": "CVE-2024-3400",
            "cvss_score": 10.0,
            "cvss_version": "3.1",
            "severity": "CRITICAL",
            "description": "Command injection in Palo Alto PAN-OS GlobalProtect",
            "affected_products": '["cpe:2.3:o:paloaltonetworks:pan-os:*"]',
            "published_date": "2024-04-12",
            "last_modified_date": "2024-05-01",
            "enriched_at": "2024-11-15T00:00:00Z",
        },
    ]


@pytest.fixture
def sample_classifications():
    return [
        {"post_id": 1, "category": "exploit_vulnerability", "model_used": "keyword",
         "confidence": 0.85, "mitre_techniques": '["T1190"]',
         "classified_at": "2024-11-15T00:00:00Z", "content": "Exploit for CVE-2024-21887"},
        {"post_id": 2, "category": "ransomware_malware", "model_used": "keyword",
         "confidence": 0.92, "mitre_techniques": '["T1486", "T1059"]',
         "classified_at": "2024-11-15T00:00:00Z", "content": "LockCrypt ransomware affiliate program"},
        {"post_id": 3, "category": "data_breach", "model_used": "logistic_regression",
         "confidence": 0.78, "mitre_techniques": '["T1078"]',
         "classified_at": "2024-11-15T00:00:00Z", "content": "Database dump from MegaCorp"},
    ]


# ── STIX Exporter Tests ──────────────────────────────────────────────────────

class TestStixExporter:
    def test_create_bundle_basic(self, sample_entities, tmp_path):
        exporter = StixExporter()
        exporter._output_dir = tmp_path
        bundle = exporter.create_bundle(sample_entities)

        assert bundle.type == "bundle"
        assert len(bundle.objects) > 1  # At least Identity + some Indicators

    def test_bundle_has_identity(self, sample_entities):
        exporter = StixExporter()
        bundle = exporter.create_bundle(sample_entities)
        identities = [o for o in bundle.objects if o.type == "identity"]
        assert len(identities) == 1
        assert "dark-web-threat-intel-toolkit" in identities[0].name

    def test_bundle_has_indicators(self, sample_entities):
        exporter = StixExporter()
        bundle = exporter.create_bundle(sample_entities)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        # Should have indicators for IPs, domain, hashes, email, url (not btc/cve)
        assert len(indicators) >= 5

    def test_indicator_patterns(self, sample_entities):
        exporter = StixExporter()
        bundle = exporter.create_bundle(sample_entities)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        patterns = [i.pattern for i in indicators]

        # Check that IP pattern is correctly formatted
        ip_patterns = [p for p in patterns if "ipv4-addr" in p]
        assert len(ip_patterns) >= 1
        assert "185.220.101.34" in ip_patterns[0]

    def test_bundle_with_cve_enrichments(self, sample_entities, sample_cve_enrichments):
        exporter = StixExporter()
        bundle = exporter.create_bundle(sample_entities, sample_cve_enrichments)
        vulns = [o for o in bundle.objects if o.type == "vulnerability"]
        assert len(vulns) == 2
        vuln_names = {v.name for v in vulns}
        assert "CVE-2024-21887" in vuln_names
        assert "CVE-2024-3400" in vuln_names

    def test_bundle_with_classifications(self, sample_entities, sample_classifications):
        exporter = StixExporter()
        bundle = exporter.create_bundle(
            sample_entities, classifications=sample_classifications,
        )
        malware_objs = [o for o in bundle.objects if o.type == "malware"]
        assert len(malware_objs) >= 1

    def test_bundle_has_relationships(self, sample_entities, sample_classifications):
        exporter = StixExporter()
        bundle = exporter.create_bundle(
            sample_entities, classifications=sample_classifications,
        )
        rels = [o for o in bundle.objects if o.type == "relationship"]
        # Hash indicators should be linked to malware
        assert len(rels) >= 1
        assert all(r.relationship_type == "indicates" for r in rels)

    def test_save_bundle(self, sample_entities, tmp_path):
        exporter = StixExporter()
        exporter._output_dir = tmp_path
        bundle = exporter.create_bundle(sample_entities)
        path = exporter.save(bundle, "test_bundle.json")

        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert data["type"] == "bundle"
        assert len(data["objects"]) > 0

    def test_export_convenience(self, sample_entities, tmp_path):
        exporter = StixExporter()
        exporter._output_dir = tmp_path
        path = exporter.export(sample_entities, filename="conv_test.json")
        assert path.exists()

    def test_no_duplicate_indicators(self, sample_entities):
        """Same value should only produce one indicator."""
        duped = sample_entities + [sample_entities[0]]  # Duplicate first entity
        exporter = StixExporter()
        bundle = exporter.create_bundle(duped)
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        values = [i.name for i in indicators]
        assert len(values) == len(set(values))

    def test_empty_entities(self):
        exporter = StixExporter()
        bundle = exporter.create_bundle([])
        # Should still have Identity
        assert len(bundle.objects) == 1
        assert bundle.objects[0].type == "identity"


# ── CSV Exporter Tests ────────────────────────────────────────────────────────

class TestCsvExporter:
    def test_export_entities(self, sample_entities, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_entities(sample_entities, "test_iocs.csv")

        assert path.exists()
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == len(sample_entities)
        assert "entity_type" in rows[0]
        assert "value" in rows[0]

    def test_export_filter_by_type(self, sample_entities, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_entities(sample_entities, "ips_only.csv", ioc_type="ipv4")

        with open(path) as f:
            rows = list(csv.DictReader(f))
        assert all(r["entity_type"] == "ipv4" for r in rows)
        assert len(rows) == 2

    def test_export_filter_by_confidence(self, sample_entities, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_entities(
            sample_entities, "high_only.csv", min_confidence="high",
        )

        with open(path) as f:
            rows = list(csv.DictReader(f))
        assert all(r["confidence"] == "high" for r in rows)

    def test_export_classifications(self, sample_classifications, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_classifications(sample_classifications)

        assert path.exists()
        with open(path) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 3
        assert rows[0]["category"] in [
            "exploit_vulnerability", "ransomware_malware", "data_breach",
        ]

    def test_export_cve_enrichments(self, sample_cve_enrichments, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_cve_enrichments(sample_cve_enrichments)

        assert path.exists()
        with open(path) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
        cve_ids = {r["cve_id"] for r in rows}
        assert "CVE-2024-21887" in cve_ids

    def test_export_all(self, sample_entities, sample_classifications,
                        sample_cve_enrichments, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        paths = exporter.export_all(
            sample_entities, sample_classifications, sample_cve_enrichments,
        )
        # Should create: all IOCs + classifications + CVEs + per-type files
        assert len(paths) >= 3
        assert all(p.exists() for p in paths)

    def test_empty_export(self, tmp_path):
        exporter = CsvExporter()
        exporter._output_dir = tmp_path
        path = exporter.export_entities([], "empty.csv")
        assert path.exists()
        with open(path) as f:
            content = f.read()
        # Should just have the header line
        lines = content.strip().split("\n")
        assert len(lines) == 1  # Header only


# ── MISP Exporter Tests ──────────────────────────────────────────────────────

class TestMispExporter:
    def test_create_event_basic(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)

        assert "Event" in event
        evt = event["Event"]
        assert "uuid" in evt
        assert "info" in evt
        assert "Attribute" in evt
        assert len(evt["Attribute"]) > 0

    def test_event_has_correct_attribute_count(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)
        attrs = event["Event"]["Attribute"]
        # All 9 entities should become attributes (all types are mapped)
        assert len(attrs) >= 7  # Some types may not be mapped

    def test_attribute_types(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)
        attrs = event["Event"]["Attribute"]
        attr_types = {a["type"] for a in attrs}
        # Should contain ip-dst, domain, sha256, md5, email-src, btc
        assert "ip-dst" in attr_types
        assert "sha256" in attr_types
        assert "email-src" in attr_types

    def test_ip_attribute_values(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)
        attrs = event["Event"]["Attribute"]
        ip_attrs = [a for a in attrs if a["type"] == "ip-dst"]
        ip_values = {a["value"] for a in ip_attrs}
        assert "185.220.101.34" in ip_values

    def test_high_confidence_sets_ids_flag(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)
        attrs = event["Event"]["Attribute"]
        # High confidence entities should have to_ids=True
        high_conf = [a for a in attrs if a["value"] == "185.220.101.34"]
        assert len(high_conf) == 1
        assert high_conf[0]["to_ids"] is True

    def test_event_with_classifications_has_tags(
        self, sample_entities, sample_classifications,
    ):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities, sample_classifications)
        tags = event["Event"]["Tag"]
        tag_names = {t["name"] for t in tags}
        assert "tlp:amber" in tag_names

    def test_event_org_name(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities)
        assert event["Event"]["Orgc"]["name"] == "dark-web-threat-intel-toolkit"

    def test_save_event(self, sample_entities, tmp_path):
        exporter = MispExporter()
        exporter._output_dir = tmp_path
        event = exporter.create_event(sample_entities)
        path = exporter.save(event, "test_misp.json")

        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert "Event" in data
        assert len(data["Event"]["Attribute"]) > 0

    def test_export_convenience(self, sample_entities, tmp_path):
        exporter = MispExporter()
        exporter._output_dir = tmp_path
        path = exporter.export(sample_entities, filename="conv_misp.json")
        assert path.exists()

    def test_no_duplicate_attributes(self, sample_entities):
        duped = sample_entities + [sample_entities[0]]
        exporter = MispExporter()
        event = exporter.create_event(duped)
        attrs = event["Event"]["Attribute"]
        values = [a["value"] for a in attrs]
        assert len(values) == len(set(values))

    def test_empty_entities(self):
        exporter = MispExporter()
        event = exporter.create_event([])
        assert event["Event"]["Attribute"] == []
        assert event["Event"]["attribute_count"] == "0"

    def test_threat_level_override(self, sample_entities):
        exporter = MispExporter()
        event = exporter.create_event(sample_entities, threat_level=1)
        assert event["Event"]["threat_level_id"] == "1"


# ── Integration: DB -> Export ─────────────────────────────────────────────────

class TestExportIntegration:
    def test_full_pipeline_to_stix(self, tmp_path):
        """Scrape fixtures -> pipeline -> export STIX."""
        from scraper import PasteScraper, SimulatedMarketScraper
        from pipeline import Pipeline
        from pipeline.db_loader import DatabaseLoader

        # Run pipeline on fixtures
        ps = PasteScraper()
        ms = SimulatedMarketScraper()
        items = ps.scrape(source="fixture") + ms.scrape(fixture="all")
        item_dicts = [item.to_dict() for item in items]

        db_path = tmp_path / "export_test.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        pipe.run(item_dicts, source_type="simulated")

        # Export from DB
        entities = db.get_entities()
        cves = db.get_cve_enrichments()

        stix_exp = StixExporter()
        stix_exp._output_dir = tmp_path
        bundle = stix_exp.create_bundle(entities, cves)
        path = stix_exp.save(bundle, "integration_test.json")

        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert data["type"] == "bundle"
        indicators = [o for o in data["objects"] if o["type"] == "indicator"]
        assert len(indicators) > 5  # Fixtures are IOC-rich

        pipe.close()

    def test_full_pipeline_to_csv(self, tmp_path):
        """Scrape fixtures -> pipeline -> export CSV."""
        from scraper import PasteScraper
        from pipeline import Pipeline
        from pipeline.db_loader import DatabaseLoader

        ps = PasteScraper()
        items = ps.scrape(source="fixture")
        item_dicts = [item.to_dict() for item in items]

        db_path = tmp_path / "csv_test.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        pipe.run(item_dicts, source_type="paste")

        entities = db.get_entities()
        csv_exp = CsvExporter()
        csv_exp._output_dir = tmp_path
        path = csv_exp.export_entities(entities)

        assert path.exists()
        with open(path) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) > 5

        pipe.close()
