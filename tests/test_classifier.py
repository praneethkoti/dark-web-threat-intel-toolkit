"""
Tests for the classifier module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_classifier.py -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from classifier.synthetic_data_generator import generate_synthetic_data, CATEGORIES
from classifier.keyword_classifier import KeywordClassifier
from classifier.ml_classifier import MLClassifier
from classifier.mitre_mapper import MitreMapper


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def synthetic_data(tmp_path_factory):
    """Generate a small synthetic dataset for testing (shared across tests)."""
    out_path = tmp_path_factory.mktemp("data") / "test_synth.json"
    data = generate_synthetic_data(
        num_samples=300, balanced=True, seed=42, output_path=out_path,
    )
    return data


@pytest.fixture
def keyword_clf():
    return KeywordClassifier()


@pytest.fixture
def mitre_mapper():
    return MitreMapper()


# ── Synthetic Data Generator Tests ────────────────────────────────────────────

class TestSyntheticDataGenerator:
    def test_generates_correct_count(self, tmp_path):
        data = generate_synthetic_data(
            num_samples=60, balanced=True, seed=99, output_path=tmp_path / "t.json",
        )
        assert len(data) == 60

    def test_balanced_distribution(self, tmp_path):
        data = generate_synthetic_data(
            num_samples=60, balanced=True, seed=99, output_path=tmp_path / "t.json",
        )
        counts = {}
        for item in data:
            counts[item["category"]] = counts.get(item["category"], 0) + 1
        assert len(counts) == 6
        assert all(c == 10 for c in counts.values())

    def test_unbalanced_distribution(self, tmp_path):
        data = generate_synthetic_data(
            num_samples=100, balanced=False, seed=99, output_path=tmp_path / "t.json",
        )
        counts = {}
        for item in data:
            counts[item["category"]] = counts.get(item["category"], 0) + 1
        # data_breach should have more than zero_day
        assert counts["data_breach"] > counts["zero_day"]

    def test_all_categories_present(self, synthetic_data):
        cats = {item["category"] for item in synthetic_data}
        assert cats == set(CATEGORIES.keys())

    def test_items_have_required_fields(self, synthetic_data):
        for item in synthetic_data[:10]:
            assert "content" in item
            assert "category" in item
            assert "timestamp" in item
            assert "source" in item
            assert "username" in item

    def test_content_not_empty(self, synthetic_data):
        for item in synthetic_data[:20]:
            assert len(item["content"].strip()) > 20

    def test_saves_to_disk(self, tmp_path):
        out = tmp_path / "output.json"
        generate_synthetic_data(num_samples=10, output_path=out, seed=42)
        assert out.exists()
        with open(out) as f:
            data = json.load(f)
        assert len(data) == 10

    def test_reproducibility(self, tmp_path):
        d1 = generate_synthetic_data(
            num_samples=10, seed=123, output_path=tmp_path / "a.json",
        )
        d2 = generate_synthetic_data(
            num_samples=10, seed=123, output_path=tmp_path / "b.json",
        )
        # Same seed should produce same content
        assert d1[0]["content"] == d2[0]["content"]


# ── Keyword Classifier Tests ─────────────────────────────────────────────────

class TestKeywordClassifier:
    def test_classifies_data_breach(self, keyword_clf):
        text = "Fresh database dump with credential dump — 50K leaked email:pass combos"
        result = keyword_clf.classify(text)
        assert result["category"] == "data_breach"
        assert result["confidence"] > 0.0

    def test_classifies_ransomware(self, keyword_clf):
        text = "New ransomware variant with AES encryption — affiliate program available"
        result = keyword_clf.classify(text)
        assert result["category"] == "ransomware_malware"

    def test_classifies_exploit(self, keyword_clf):
        text = "CVE-2024-1234 remote code execution exploit proof of concept"
        result = keyword_clf.classify(text)
        assert result["category"] == "exploit_vulnerability"

    def test_classifies_carding(self, keyword_clf):
        text = "Selling fullz with CVV — credit card dump from skimmer network, cashout ready"
        result = keyword_clf.classify(text)
        assert result["category"] == "carding_fraud"

    def test_classifies_zero_day(self, keyword_clf):
        text = "Selling 0day zero-day unpatched private exploit for enterprise VPN"
        result = keyword_clf.classify(text)
        assert result["category"] == "zero_day"

    def test_classifies_threat_actor(self, keyword_clf):
        text = "Hiring developers for affiliate program. Strong opsec required. Jabber only."
        result = keyword_clf.classify(text)
        assert result["category"] == "threat_actor_comms"

    def test_unknown_text(self, keyword_clf):
        text = "The weather is nice today. I like puppies."
        result = keyword_clf.classify(text)
        assert result["category"] == "unknown"
        assert result["confidence"] < 0.3

    def test_empty_text(self, keyword_clf):
        result = keyword_clf.classify("")
        assert result["category"] == "unknown"

    def test_result_has_matched_keywords(self, keyword_clf):
        text = "credential dump leaked database breach"
        result = keyword_clf.classify(text)
        assert len(result["matched_keywords"]) > 0

    def test_result_has_all_scores(self, keyword_clf):
        text = "ransomware encryption"
        result = keyword_clf.classify(text)
        assert "scores" in result
        assert len(result["scores"]) == 6  # All 6 categories

    def test_batch_classification(self, keyword_clf):
        texts = [
            "database dump with credentials leaked",
            "new ransomware variant spotted",
            "selling CVV fullz credit card",
        ]
        results = keyword_clf.classify_batch(texts)
        assert len(results) == 3
        assert results[0]["category"] == "data_breach"
        assert results[1]["category"] == "ransomware_malware"
        assert results[2]["category"] == "carding_fraud"

    def test_weighted_scoring(self, keyword_clf):
        # "database dump" (3.0) should score higher than just "dump" (1.0)
        r1 = keyword_clf.classify("database dump with credentials")
        r2 = keyword_clf.classify("something about a dump")
        assert r1["confidence"] > r2["confidence"]

    def test_categories_property(self, keyword_clf):
        cats = keyword_clf.categories
        assert "data_breach" in cats
        assert "ransomware_malware" in cats
        assert len(cats) == 6


# ── ML Classifier Tests ──────────────────────────────────────────────────────

class TestMLClassifier:
    def test_train_and_classify(self, synthetic_data):
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        results = clf.train(texts, labels, tune=False)  # Skip tuning for speed

        assert clf.is_trained
        assert len(clf.available_models) >= 1
        assert clf.best_model_name is not None

        # Classify a sample
        pred = clf.classify("Fresh credential dump database leak email:password")
        assert pred["category"] in set(labels)
        assert 0 <= pred["confidence"] <= 1.0

    def test_comparison_report(self, synthetic_data):
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        clf.train(texts, labels, tune=False)
        report = clf.get_comparison_report()

        assert "best_model" in report
        assert report["best_model"] in ["logistic_regression", "random_forest", "svm"]
        for model_name in clf.available_models:
            assert model_name in report
            assert "accuracy" in report[model_name]
            assert "weighted_f1" in report[model_name]
            assert "per_category" in report[model_name]

    def test_batch_classify(self, synthetic_data):
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        clf.train(texts, labels, tune=False)
        preds = clf.classify_batch(["ransomware encrypts files", "credential dump leaked"])
        assert len(preds) == 2
        assert all("category" in p for p in preds)

    def test_not_trained_returns_unknown(self):
        clf = MLClassifier()
        pred = clf.classify("some text")
        assert pred["category"] == "unknown"
        assert pred["model"] == "ml_not_trained"

    def test_model_persistence(self, synthetic_data, tmp_path):
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        clf._models_dir = tmp_path  # Override save location
        clf.train(texts, labels, tune=False)
        saved = clf.save_models()
        assert len(saved) >= 1
        assert all(p.exists() for p in saved)

        # Load into a fresh classifier
        clf2 = MLClassifier()
        clf2._models_dir = tmp_path
        assert clf2.load_model("logistic_regression")
        pred = clf2.classify("credential dump leaked database breach")
        assert pred["category"] != "unknown"

    def test_accuracy_above_baseline(self, synthetic_data):
        """Models should beat random chance (1/6 ~ 0.167) by a good margin."""
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        results = clf.train(texts, labels, tune=False)
        for model_name, result in results.items():
            assert result["accuracy"] > 0.4, (
                f"{model_name} accuracy {result['accuracy']} is too low"
            )

    def test_train_with_tuning(self, synthetic_data):
        """GridSearchCV should run without errors."""
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        # Only tune one model for speed
        clf._model_names = ["logistic_regression"]
        results = clf.train(texts, labels, tune=True)
        assert "logistic_regression" in results
        assert results["logistic_regression"]["accuracy"] > 0.3


# ── MITRE ATT&CK Mapper Tests ────────────────────────────────────────────────

class TestMitreMapper:
    def test_map_ransomware(self, mitre_mapper):
        techniques = mitre_mapper.map("ransomware_malware")
        assert len(techniques) > 0
        tech_ids = [t["id"] for t in techniques]
        assert "T1486" in tech_ids  # Data Encrypted for Impact

    def test_map_data_breach(self, mitre_mapper):
        techniques = mitre_mapper.map("data_breach")
        tech_ids = [t["id"] for t in techniques]
        assert "T1078" in tech_ids  # Valid Accounts

    def test_map_exploit(self, mitre_mapper):
        techniques = mitre_mapper.map("exploit_vulnerability")
        tech_ids = [t["id"] for t in techniques]
        assert "T1190" in tech_ids  # Exploit Public-Facing Application

    def test_map_unknown_category(self, mitre_mapper):
        techniques = mitre_mapper.map("nonexistent_category")
        assert techniques == []

    def test_map_ids(self, mitre_mapper):
        ids = mitre_mapper.map_ids("zero_day")
        assert all(id.startswith("T") for id in ids)
        assert len(ids) > 0

    def test_enrich_classification(self, mitre_mapper):
        result = {"category": "ransomware_malware", "confidence": 0.85}
        enriched = mitre_mapper.enrich_classification(result)
        assert "mitre_techniques" in enriched
        assert "mitre_technique_ids" in enriched
        assert "T1486" in enriched["mitre_technique_ids"]

    def test_enrich_batch(self, mitre_mapper):
        results = [
            {"category": "data_breach", "confidence": 0.9},
            {"category": "zero_day", "confidence": 0.7},
        ]
        enriched = mitre_mapper.enrich_batch(results)
        assert len(enriched) == 2
        assert all("mitre_techniques" in r for r in enriched)

    def test_all_categories_have_techniques(self, mitre_mapper):
        for cat in mitre_mapper.categories:
            techniques = mitre_mapper.map(cat)
            assert len(techniques) > 0, f"Category {cat} has no techniques"

    def test_technique_structure(self, mitre_mapper):
        techniques = mitre_mapper.map("carding_fraud")
        for t in techniques:
            assert "id" in t
            assert "name" in t
            assert "tactic" in t
            assert t["id"].startswith("T")

    def test_get_all_technique_ids(self, mitre_mapper):
        all_ids = mitre_mapper.get_all_technique_ids()
        assert len(all_ids) > 15  # We have 25+ unique techniques
        assert all(id.startswith("T") for id in all_ids)

    def test_display_names(self, mitre_mapper):
        name = mitre_mapper.get_display_name("ransomware_malware")
        assert "Ransomware" in name


# ── TransformerClassifier Tests (skipped without transformers) ────────────────

class TestTransformerClassifier:
    @pytest.mark.skipif(
        not os.getenv("RUN_TRANSFORMER_TESTS"),
        reason="Transformer tests disabled — set RUN_TRANSFORMER_TESTS=1 and install transformers+torch",
    )
    def test_zero_shot_classify(self):
        from classifier.bert_classifier import TransformerClassifier
        clf = TransformerClassifier()
        result = clf.classify("Selling credential dump — 50K email:password combos leaked")
        assert result["category"] in [
            "data_breach", "exploit_vulnerability", "ransomware_malware",
            "carding_fraud", "threat_actor_comms", "zero_day", "unknown",
        ]
        assert 0 <= result["confidence"] <= 1.0

    @pytest.mark.skipif(
        not os.getenv("RUN_TRANSFORMER_TESTS"),
        reason="Transformer tests disabled",
    )
    def test_zero_shot_batch(self):
        from classifier.bert_classifier import TransformerClassifier
        clf = TransformerClassifier()
        results = clf.classify_batch([
            "ransomware encrypts all files",
            "selling zero day exploit",
        ])
        assert len(results) == 2


# ── Integration: Full classification pipeline ─────────────────────────────────

class TestClassificationPipeline:
    def test_keyword_then_mitre(self, keyword_clf, mitre_mapper):
        """Keyword classify -> MITRE enrich pipeline."""
        text = "New ransomware variant using AES-256 encryption. Affiliate program open."
        result = keyword_clf.classify(text)
        enriched = mitre_mapper.enrich_classification(result)

        assert enriched["category"] == "ransomware_malware"
        assert "T1486" in enriched["mitre_technique_ids"]

    def test_ml_then_mitre(self, synthetic_data, mitre_mapper):
        """ML classify -> MITRE enrich pipeline."""
        texts = [item["content"] for item in synthetic_data]
        labels = [item["category"] for item in synthetic_data]

        clf = MLClassifier()
        clf.train(texts, labels, tune=False)
        result = clf.classify("selling fullz CVV credit card dump cashout")
        enriched = mitre_mapper.enrich_classification(result)

        assert enriched["category"] in set(labels)
        assert "mitre_techniques" in enriched
