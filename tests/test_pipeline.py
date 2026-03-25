"""
Tests for the pipeline module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_pipeline.py -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.cleaner import DataCleaner
from pipeline.entity_extractor import EntityExtractor, ExtractedEntity
from pipeline.db_loader import DatabaseLoader
from pipeline import Pipeline, PipelineStats


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def cleaner():
    return DataCleaner()


@pytest.fixture
def extractor():
    return EntityExtractor(use_ner=False)


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    loader = DatabaseLoader(db_path=db_path)
    loader.init_schema()
    yield loader
    loader.close()


@pytest.fixture
def sample_scraped_items():
    return [
        {
            "source_name": "paste_site",
            "source_url": "http://example.com/paste1",
            "content": (
                "BREACH ALERT: Credentials leaked from corp.com\n"
                "admin@corp.com:Password123!\n"
                "user@corp.com:Welcome2024\n"
                "Affected CVE: CVE-2024-21887\n"
                "C2 Server: 185.220.101.34\n"
                "SHA-256: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b\n"
                "BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            ),
            "content_hash": "abc123",
            "scraped_at": "2024-11-15T08:00:00Z",
            "http_status": 200,
            "metadata": {"title": "Corp breach"},
        },
        {
            "source_name": "simulated_forum",
            "source_url": "http://example.com/forum1",
            "content": (
                "New ransomware variant spotted. MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"
                "Contact the group via Jabber: threat_actor@xmpp.jp\n"
                "They are recruiting developers for their affiliate program.\n"
                "Monero payment: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
            ),
            "content_hash": "def456",
            "scraped_at": "2024-11-15T09:00:00Z",
            "http_status": 200,
            "metadata": {},
        },
    ]


# ── DataCleaner Tests ─────────────────────────────────────────────────────────

class TestDataCleaner:
    def test_strip_html(self, cleaner):
        html = "<div><p>Hello world this is a threat alert about malware</p><script>evil()</script></div>"
        result = cleaner.clean(html)
        assert "Hello world" in result
        assert "world" in result
        assert "<div>" not in result
        assert "evil()" not in result

    def test_unicode_normalization(self, cleaner):
        text = "\uff21\uff54\uff54\uff41\uff43\uff4b detected in the threat intelligence feed"  # Fullwidth "Attack"
        result = cleaner.clean(text)
        assert "Attack" in result

    def test_mojibake_fix(self, cleaner):
        text = "The attacker\xe2\x80\x99s infrastructure was compromised"
        result = cleaner.clean(text)
        assert "\xe2\x80\x99" not in result

    def test_noise_removal(self, cleaner):
        text = "Important threat data\n\u26a1 BUY PREMIUM NOW \u26a1\nMore threat data here"
        result = cleaner.clean(text)
        assert "Important threat data" in result
        assert "BUY PREMIUM" not in result
        assert "More threat data" in result

    def test_whitespace_normalization(self, cleaner):
        text = "Line one\n\n\n\n\n\nLine two   with    spaces"
        result = cleaner.clean(text)
        assert "\n\n\n" not in result
        assert "  " not in result

    def test_min_length_filter(self, cleaner):
        result = cleaner.clean("short")
        assert result == ""

    def test_empty_input(self, cleaner):
        assert cleaner.clean("") == ""
        assert cleaner.clean("   ") == ""

    def test_batch_dedup(self, cleaner):
        items = [
            {"content": "Duplicate content here for testing purposes"},
            {"content": "Duplicate content here for testing purposes"},
            {"content": "Unique content that is different and long enough"},
        ]
        result = cleaner.clean_batch(items)
        assert len(result) == 2

    def test_batch_with_existing_hashes(self, cleaner):
        items = [{"content": "Some threat intelligence data for analysis"}]
        cleaned = cleaner.clean(items[0]["content"])
        existing = {DataCleaner.content_hash(cleaned)}
        result = cleaner.clean_batch(items, seen_hashes=existing)
        assert len(result) == 0

    def test_content_hash_static(self):
        h = DataCleaner.content_hash("test")
        assert len(h) == 64
        assert h == DataCleaner.content_hash("test")


# ── EntityExtractor Tests ─────────────────────────────────────────────────────

class TestEntityExtractor:
    def test_ipv4_extraction(self, extractor):
        text = "C2 server at 192.168.1.100 and 10.0.0.1"
        entities = extractor.extract(text)
        ips = [e for e in entities if e.entity_type == "ipv4"]
        values = {e.value for e in ips}
        assert "192.168.1.100" in values
        assert "10.0.0.1" in values

    def test_ipv6_extraction(self, extractor):
        text = "Found traffic from 2001:db8:85a3:0000:0000:8a2e:0370:7334"
        entities = extractor.extract(text)
        ips = [e for e in entities if e.entity_type == "ipv6"]
        assert len(ips) >= 1

    def test_email_extraction(self, extractor):
        text = "Contact: admin@evil-corp.com and user@example.org"
        entities = extractor.extract(text)
        emails = [e for e in entities if e.entity_type == "email"]
        values = {e.value for e in emails}
        assert "admin@evil-corp.com" in values

    def test_cve_extraction(self, extractor):
        text = "Exploiting CVE-2024-21887 and CVE-2024-21893 in the wild"
        entities = extractor.extract(text)
        cves = [e for e in entities if e.entity_type == "cve_id"]
        values = {e.value for e in cves}
        assert "CVE-2024-21887" in values
        assert "CVE-2024-21893" in values

    def test_sha256_extraction(self, extractor):
        text = "Hash: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
        entities = extractor.extract(text)
        hashes = [e for e in entities if e.entity_type == "sha256"]
        assert len(hashes) == 1
        assert hashes[0].confidence == "high"

    def test_md5_extraction(self, extractor):
        text = "MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        entities = extractor.extract(text)
        hashes = [e for e in entities if e.entity_type == "md5"]
        assert len(hashes) == 1

    def test_bitcoin_extraction(self, extractor):
        text = "Pay to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        entities = extractor.extract(text)
        btc = [e for e in entities if e.entity_type == "bitcoin_address"]
        assert len(btc) == 1

    def test_monero_extraction(self, extractor):
        text = "XMR: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
        entities = extractor.extract(text)
        xmr = [e for e in entities if e.entity_type == "monero_address"]
        assert len(xmr) == 1

    def test_credential_extraction(self, extractor):
        text = "Leaked: admin@corp.com:Password123! and root:toor"
        entities = extractor.extract(text)
        creds = [e for e in entities if e.entity_type == "credential_pair"]
        assert len(creds) >= 1

    def test_no_hash_overlap(self, extractor):
        """A 64-char hex string should only be SHA-256, not also MD5/SHA-1."""
        text = "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
        entities = extractor.extract(text)
        types = {e.entity_type for e in entities}
        assert "sha256" in types
        assert "md5" not in types
        assert "sha1" not in types

    def test_dedup_within_text(self, extractor):
        text = "IP 192.168.1.1 found again at 192.168.1.1"
        entities = extractor.extract(text)
        ips = [e for e in entities if e.entity_type == "ipv4"]
        assert len(ips) == 1

    def test_entity_has_context(self, extractor):
        text = "The attacker used the server at 10.20.30.40 for command and control"
        entities = extractor.extract(text)
        ip_ent = [e for e in entities if e.entity_type == "ipv4"][0]
        assert "10.20.30.40" in ip_ent.context
        assert len(ip_ent.context) > 20

    def test_extract_type_utility(self, extractor):
        text = "CVE-2024-1234 and CVE-2023-5678 were exploited"
        cves = extractor.extract_type(text, "cve_id")
        assert "CVE-2024-1234" in cves
        assert "CVE-2023-5678" in cves

    def test_batch_extraction(self, extractor, sample_scraped_items):
        items = [
            {"cleaned_content": item["content"], "content_hash": item["content_hash"]}
            for item in sample_scraped_items
        ]
        results = extractor.extract_batch(items)
        assert len(results) == 2
        assert all("entities" in item for item in results)
        total = sum(len(item["entities"]) for item in results)
        assert total > 0

    def test_empty_text(self, extractor):
        assert extractor.extract("") == []
        assert extractor.extract("   ") == []

    def test_entity_to_dict(self, extractor):
        ent = ExtractedEntity(
            entity_type="ipv4", value="1.2.3.4", raw_match="1.2.3.4",
            confidence="high", extraction_method="regex",
        )
        d = ent.to_dict()
        assert d["entity_type"] == "ipv4"
        assert d["value"] == "1.2.3.4"

    @pytest.mark.skipif(
        not os.getenv("RUN_NER_TESTS"),
        reason="NER tests disabled — set RUN_NER_TESTS=1 and install en_core_web_sm",
    )
    def test_ner_extraction(self):
        ext = EntityExtractor(use_ner=True)
        text = "Microsoft announced that the FBI is investigating."
        entities = ext.extract(text)
        org_names = {e.value for e in entities if e.entity_type == "organization"}
        assert len(org_names) >= 1


# ── DatabaseLoader Tests ──────────────────────────────────────────────────────

class TestDatabaseLoader:
    def test_schema_init(self, db):
        cursor = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row["name"] for row in cursor.fetchall()}
        expected = {
            "sources", "raw_posts", "entities",
            "cve_enrichment", "classifications", "summaries", "scheduler_runs",
        }
        assert expected.issubset(tables)

    def test_idempotent_schema(self, db):
        db.init_schema()
        assert db.get_post_count() == 0

    def test_source_create_and_get(self, db):
        sid = db.get_or_create_source("test_source", "paste", "http://example.com")
        assert sid > 0
        sid2 = db.get_or_create_source("test_source", "paste", "http://example.com")
        assert sid == sid2

    def test_insert_raw_post(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        post_id = db.insert_raw_post(
            source_id=sid,
            content="Test content for pipeline",
            content_hash="hash_abc123",
            scraped_at="2024-01-01T00:00:00Z",
        )
        assert post_id is not None
        assert post_id > 0

    def test_duplicate_post_skipped(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        db.insert_raw_post(sid, "content", "hash_1", "2024-01-01T00:00:00Z")
        result = db.insert_raw_post(sid, "content", "hash_1", "2024-01-01T00:00:00Z")
        assert result is None

    def test_insert_entities(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        post_id = db.insert_raw_post(sid, "content", "hash_ent", "2024-01-01T00:00:00Z")
        entities = [
            {"entity_type": "ipv4", "value": "192.168.1.1", "confidence": "high",
             "extraction_method": "regex", "raw_match": "192.168.1.1"},
            {"entity_type": "cve_id", "value": "CVE-2024-1234", "confidence": "high",
             "extraction_method": "regex", "raw_match": "CVE-2024-1234"},
        ]
        count = db.insert_entities(post_id, entities)
        assert count == 2

    def test_upsert_cve_enrichment(self, db):
        cve_data = {
            "cve_id": "CVE-2024-21887",
            "cvss_score": 9.1,
            "cvss_version": "3.1",
            "severity": "CRITICAL",
            "description": "Command injection in Ivanti Connect Secure",
            "affected_products": "[]",
            "published_date": "2024-01-12",
            "last_modified_date": "2024-02-01",
        }
        db.upsert_cve_enrichment(cve_data)
        enrichments = db.get_cve_enrichments()
        assert len(enrichments) == 1
        assert enrichments[0]["cve_id"] == "CVE-2024-21887"
        assert enrichments[0]["cvss_score"] == 9.1

        cve_data["cvss_score"] = 9.8
        db.upsert_cve_enrichment(cve_data)
        enrichments = db.get_cve_enrichments()
        assert len(enrichments) == 1
        assert enrichments[0]["cvss_score"] == 9.8

    def test_insert_classification(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        post_id = db.insert_raw_post(sid, "content", "hash_cls", "2024-01-01T00:00:00Z")
        cls_id = db.insert_classification(
            post_id=post_id,
            category="ransomware_malware",
            model_used="keyword",
            confidence=0.85,
            mitre_techniques=["T1486", "T1059"],
        )
        assert cls_id is not None

    def test_get_existing_hashes(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        db.insert_raw_post(sid, "a", "hash_a", "2024-01-01T00:00:00Z")
        db.insert_raw_post(sid, "b", "hash_b", "2024-01-01T00:00:00Z")
        hashes = db.get_existing_hashes()
        assert "hash_a" in hashes
        assert "hash_b" in hashes

    def test_get_unclassified_posts(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        pid1 = db.insert_raw_post(sid, "post1", "h1", "2024-01-01T00:00:00Z")
        pid2 = db.insert_raw_post(sid, "post2", "h2", "2024-01-01T00:00:00Z")
        db.insert_classification(pid1, "data_breach", "keyword", 0.9)

        unclassified = db.get_unclassified_posts()
        assert len(unclassified) == 1
        assert unclassified[0]["content"] == "post2"

    def test_entity_counts(self, db):
        sid = db.get_or_create_source("test", "paste", "")
        pid = db.insert_raw_post(sid, "c", "h_cnt", "2024-01-01T00:00:00Z")
        db.insert_entities(pid, [
            {"entity_type": "ipv4", "value": "1.1.1.1", "confidence": "high",
             "extraction_method": "regex", "raw_match": "1.1.1.1"},
            {"entity_type": "ipv4", "value": "2.2.2.2", "confidence": "high",
             "extraction_method": "regex", "raw_match": "2.2.2.2"},
            {"entity_type": "cve_id", "value": "CVE-2024-0001", "confidence": "high",
             "extraction_method": "regex", "raw_match": "CVE-2024-0001"},
        ])
        counts = db.get_entity_counts_by_type()
        assert counts["ipv4"] == 2
        assert counts["cve_id"] == 1

    def test_post_and_entity_counts(self, db):
        assert db.get_post_count() == 0
        assert db.get_entity_count() == 0
        sid = db.get_or_create_source("t", "p", "")
        pid = db.insert_raw_post(sid, "x", "hx", "2024-01-01T00:00:00Z")
        db.insert_entities(pid, [
            {"entity_type": "ipv4", "value": "9.9.9.9", "confidence": "high",
             "extraction_method": "regex", "raw_match": "9.9.9.9"},
        ])
        assert db.get_post_count() == 1
        assert db.get_entity_count() == 1


# ── Full Pipeline Integration Tests ──────────────────────────────────────────

class TestPipeline:
    def test_full_pipeline_run(self, tmp_path, sample_scraped_items):
        db_path = tmp_path / "pipeline_test.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        stats = pipe.run(sample_scraped_items, source_type="test")

        assert stats.items_input == 2
        assert stats.items_cleaned >= 1
        assert stats.items_stored >= 1
        assert stats.entities_extracted > 0
        assert stats.errors == 0
        assert db.get_post_count() >= 1
        assert db.get_entity_count() > 0
        pipe.close()

    def test_idempotent_pipeline(self, tmp_path, sample_scraped_items):
        db_path = tmp_path / "idempotent_test.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        stats1 = pipe.run(sample_scraped_items, source_type="test")
        stats2 = pipe.run(sample_scraped_items, source_type="test")

        assert stats2.items_stored == 0 or stats2.duplicates_skipped >= stats1.items_stored
        assert db.get_post_count() == stats1.items_stored
        pipe.close()

    def test_pipeline_from_files(self, tmp_path, sample_scraped_items):
        db_path = tmp_path / "file_test.db"
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()

        json_file = raw_dir / "test_data.json"
        with open(json_file, "w") as f:
            json.dump(sample_scraped_items, f)

        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        stats = pipe.run_from_files(raw_dir)

        assert stats.items_input == 2
        assert stats.items_stored >= 1
        pipe.close()

    def test_pipeline_stats(self):
        stats = PipelineStats()
        stats.items_input = 10
        stats.items_stored = 8
        d = stats.to_dict()
        assert d["items_input"] == 10
        assert d["items_stored"] == 8

    def test_pipeline_with_real_fixtures(self, tmp_path):
        """Run the pipeline on actual scraper output from fixture files."""
        from scraper import PasteScraper, SimulatedMarketScraper

        ps = PasteScraper()
        ms = SimulatedMarketScraper()
        items = ps.scrape(source="fixture") + ms.scrape(fixture="all")
        item_dicts = [item.to_dict() for item in items]

        db_path = tmp_path / "fixture_pipeline.db"
        db = DatabaseLoader(db_path=db_path)
        pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)
        stats = pipe.run(item_dicts, source_type="simulated")

        assert stats.items_input == 15  # 4 pastes + 5 marketplace + 6 forum
        assert stats.items_stored >= 10
        assert stats.entities_extracted > 20

        counts = db.get_entity_counts_by_type()
        assert "ipv4" in counts
        assert "cve_id" in counts
        assert "sha256" in counts

        pipe.close()
