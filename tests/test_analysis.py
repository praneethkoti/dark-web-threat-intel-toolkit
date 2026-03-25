"""
Tests for the analysis module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_analysis.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.db_loader import DatabaseLoader
from analysis.trend_analyzer import TrendAnalyzer
from analysis.anomaly_detector import AnomalyDetector
from analysis.visualizer import Visualizer
from analysis.report_generator import ReportGenerator


# ── Fixture: populated database ──────────────────────────────────────────────

@pytest.fixture(scope="module")
def populated_db(tmp_path_factory):
    """
    Create a database pre-loaded with fixture data through the pipeline.
    Shared across all tests in this module for speed.
    """
    from scraper import PasteScraper, SimulatedMarketScraper
    from pipeline import Pipeline

    db_path = tmp_path_factory.mktemp("analysis") / "analysis_test.db"
    db = DatabaseLoader(db_path=db_path)

    pipe = Pipeline(db=db, skip_enrichment=True, use_ner=False)

    # Scrape all fixtures
    ps = PasteScraper()
    ms = SimulatedMarketScraper()
    items = ps.scrape(source="fixture") + ms.scrape(fixture="all")
    item_dicts = [item.to_dict() for item in items]
    pipe.run(item_dicts, source_type="simulated")

    # Add some classifications so analysis has data to work with
    from classifier.keyword_classifier import KeywordClassifier
    from classifier.mitre_mapper import MitreMapper

    kw_clf = KeywordClassifier()
    mapper = MitreMapper()

    posts = db.get_all_posts()
    for post in posts:
        result = kw_clf.classify(post["content"])
        enriched = mapper.enrich_classification(result)
        db.insert_classification(
            post_id=post["id"],
            category=enriched["category"],
            model_used="keyword",
            confidence=enriched["confidence"],
            mitre_techniques=enriched.get("mitre_technique_ids"),
        )

    # Add a CVE enrichment manually for testing
    db.upsert_cve_enrichment({
        "cve_id": "CVE-2024-21887",
        "cvss_score": 9.1,
        "cvss_version": "3.1",
        "severity": "CRITICAL",
        "description": "Command injection in Ivanti Connect Secure",
        "affected_products": '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
        "published_date": "2024-01-12",
        "last_modified_date": "2024-02-01",
    })
    db.upsert_cve_enrichment({
        "cve_id": "CVE-2024-21893",
        "cvss_score": 8.2,
        "cvss_version": "3.1",
        "severity": "HIGH",
        "description": "SSRF in Ivanti Connect Secure",
        "affected_products": '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
        "published_date": "2024-01-31",
        "last_modified_date": "2024-02-15",
    })

    pipe.close()
    yield db
    db.close()


@pytest.fixture
def analyzer(populated_db):
    return TrendAnalyzer(populated_db)


@pytest.fixture
def detector(populated_db):
    return AnomalyDetector(populated_db)


@pytest.fixture
def viz(tmp_path):
    v = Visualizer()
    v._chart_dir = tmp_path
    return v


@pytest.fixture
def report_gen(tmp_path):
    gen = ReportGenerator()
    gen._output_dir = tmp_path
    return gen


# ── TrendAnalyzer Tests ──────────────────────────────────────────────────────

class TestTrendAnalyzer:
    def test_trending_keywords(self, analyzer):
        keywords = analyzer.get_trending_keywords("90d", top_n=20)
        assert len(keywords) > 0
        assert all("keyword" in kw and "count" in kw for kw in keywords)
        # Keywords should be sorted by count (rank order)
        if len(keywords) >= 2:
            assert keywords[0]["count"] >= keywords[1]["count"]

    def test_top_cves(self, analyzer):
        cves = analyzer.get_top_cves(top_n=10)
        assert len(cves) > 0
        # CVE-2024-21887 appears in multiple fixtures
        cve_ids = {c["cve_id"] for c in cves}
        assert "CVE-2024-21887" in cve_ids
        # Should have enrichment data
        for cve in cves:
            if cve["cve_id"] == "CVE-2024-21887":
                assert cve["cvss_score"] == 9.1
                assert cve["severity"] == "CRITICAL"

    def test_category_distribution(self, analyzer):
        dist = analyzer.get_category_distribution("90d")
        assert "window" in dist
        assert "total" in dist
        assert "categories" in dist
        assert dist["total"] > 0
        # Should have at least some categories
        assert len(dist["categories"]) > 0

    def test_category_distribution_has_timeline(self, analyzer):
        dist = analyzer.get_category_distribution("90d")
        assert "timeline" in dist
        # Timeline entries have date + category counts
        if dist["timeline"]:
            entry = dist["timeline"][0]
            assert "date" in entry

    def test_ioc_distribution(self, analyzer):
        ioc_dist = analyzer.get_ioc_distribution()
        assert isinstance(ioc_dist, dict)
        assert len(ioc_dist) > 0
        # Fixtures should produce IPv4 and CVE entities at minimum
        assert "ipv4" in ioc_dist or "cve_id" in ioc_dist

    def test_summary_stats(self, analyzer):
        stats = analyzer.get_summary_stats()
        assert stats["total_posts"] > 0
        assert stats["total_entities"] > 0
        assert isinstance(stats["entity_distribution"], dict)
        assert isinstance(stats["classification_distribution"], dict)

    def test_threat_actor_patterns(self, analyzer):
        patterns = analyzer.get_threat_actor_patterns()
        # May or may not find patterns depending on fixture metadata
        assert isinstance(patterns, list)
        for p in patterns:
            assert "username" in p
            assert "post_count" in p
            assert p["post_count"] >= 2

    def test_top_targeted_products(self, analyzer):
        products = analyzer.get_top_targeted_products()
        assert isinstance(products, list)
        # We added Ivanti enrichment, so it should appear
        if products:
            vendors = {p["vendor"] for p in products}
            assert "ivanti" in vendors


# ── AnomalyDetector Tests ────────────────────────────────────────────────────

class TestAnomalyDetector:
    def test_detect_returns_list(self, detector):
        anomalies = detector.detect(window_days=365)
        assert isinstance(anomalies, list)
        # With fixture data all on the same day, there may be spikes
        for a in anomalies:
            assert "date" in a
            assert "category" in a
            assert "count" in a
            assert "is_anomaly" in a

    def test_detect_zscore_method(self, populated_db):
        d = AnomalyDetector(populated_db)
        d._method = "zscore"
        anomalies = d.detect(window_days=365)
        assert isinstance(anomalies, list)
        for a in anomalies:
            assert a.get("method") == "zscore"

    def test_detect_rolling_avg_method(self, populated_db):
        d = AnomalyDetector(populated_db)
        d._method = "rolling_avg"
        anomalies = d.detect(window_days=365)
        assert isinstance(anomalies, list)
        for a in anomalies:
            assert a.get("method") == "rolling_avg"


# ── Visualizer Tests ──────────────────────────────────────────────────────────

class TestVisualizer:
    def test_category_bar_chart(self, viz):
        data = {"data_breach": 15, "ransomware_malware": 10, "carding_fraud": 5}
        fig = viz.category_bar_chart(data)
        assert fig is not None
        # Plotly figure should have data
        assert len(fig.data) > 0

    def test_category_pie_chart(self, viz):
        data = {"data_breach": 15, "ransomware_malware": 10, "zero_day": 3}
        fig = viz.category_pie_chart(data)
        assert fig is not None
        assert len(fig.data) > 0

    def test_timeline_chart(self, viz):
        timeline = [
            {"date": "2024-11-10", "data_breach": 3, "ransomware_malware": 2},
            {"date": "2024-11-11", "data_breach": 5, "ransomware_malware": 1},
            {"date": "2024-11-12", "data_breach": 2, "ransomware_malware": 4},
        ]
        fig = viz.timeline_chart(timeline)
        assert fig is not None

    def test_timeline_empty(self, viz):
        fig = viz.timeline_chart([])
        assert fig is not None  # Should return placeholder

    def test_cve_severity_chart(self, viz):
        cve_data = [
            {"cve_id": "CVE-2024-21887", "mention_count": 8, "cvss_score": 9.1, "severity": "CRITICAL"},
            {"cve_id": "CVE-2024-3400", "mention_count": 5, "cvss_score": 10.0, "severity": "CRITICAL"},
            {"cve_id": "CVE-2024-1234", "mention_count": 3, "cvss_score": 6.5, "severity": "MEDIUM"},
        ]
        fig = viz.cve_severity_chart(cve_data)
        assert fig is not None
        assert len(fig.data) > 0

    def test_ioc_distribution_chart(self, viz):
        data = {"ipv4": 25, "sha256": 15, "email": 10, "domain": 8, "cve_id": 5}
        fig = viz.ioc_distribution_chart(data)
        assert fig is not None

    def test_word_cloud(self, viz):
        keywords = [
            {"keyword": "ransomware", "count": 50},
            {"keyword": "exploit", "count": 30},
            {"keyword": "credential", "count": 25},
            {"keyword": "breach", "count": 20},
            {"keyword": "malware", "count": 18},
        ]
        path = viz.word_cloud(keywords, title="test_cloud")
        assert path.exists()
        assert path.suffix == ".png"

    def test_word_cloud_empty(self, viz):
        path = viz.word_cloud([], title="empty_cloud")
        assert path.exists()

    def test_save_chart_html(self, viz):
        data = {"a": 10, "b": 20}
        fig = viz.category_bar_chart(data)
        path = viz.save_chart(fig, "test_chart.html", as_html=True)
        assert path.exists()
        assert path.suffix == ".html"
        content = path.read_text()
        assert "plotly" in content.lower()


# ── ReportGenerator Tests ─────────────────────────────────────────────────────

class TestReportGenerator:
    def _sample_data(self):
        return {
            "stats": {
                "total_posts": 15,
                "total_entities": 87,
                "entity_distribution": {"ipv4": 20, "sha256": 15, "cve_id": 8},
                "classification_distribution": {
                    "exploit_vulnerability": 6, "ransomware_malware": 4,
                    "data_breach": 3, "carding_fraud": 2,
                },
                "cve_enrichments_count": 2,
            },
            "cat_dist": {"window": "30d", "total": 15, "categories": {
                "exploit_vulnerability": 6, "ransomware_malware": 4,
            }, "timeline": []},
            "top_cves": [
                {"cve_id": "CVE-2024-21887", "mention_count": 8,
                 "cvss_score": 9.1, "severity": "CRITICAL", "description": "Command injection"},
            ],
            "keywords": [
                {"keyword": "ransomware", "count": 12, "rank": 1},
                {"keyword": "exploit", "count": 8, "rank": 2},
            ],
            "ioc_dist": {"ipv4": 20, "sha256": 15, "cve_id": 8},
            "anomalies": [
                {"date": "2024-11-14", "category": "ransomware_malware",
                 "count": 8, "zscore": 3.2, "is_anomaly": True},
            ],
        }

    def test_generate_markdown(self, report_gen):
        d = self._sample_data()
        path = report_gen.generate_markdown(
            summary_stats=d["stats"],
            category_dist=d["cat_dist"],
            top_cves=d["top_cves"],
            trending_keywords=d["keywords"],
            ioc_dist=d["ioc_dist"],
            anomalies=d["anomalies"],
        )
        assert path.exists()
        assert path.suffix == ".md"
        content = path.read_text()
        assert "# Dark Web Threat Intelligence Report" in content
        assert "Executive Summary" in content
        assert "CVE-2024-21887" in content
        assert "Recommendations" in content

    def test_generate_html(self, report_gen):
        d = self._sample_data()
        path = report_gen.generate_html(
            summary_stats=d["stats"],
            category_dist=d["cat_dist"],
            top_cves=d["top_cves"],
            trending_keywords=d["keywords"],
            ioc_dist=d["ioc_dist"],
            anomalies=d["anomalies"],
        )
        assert path.exists()
        assert path.suffix == ".html"
        content = path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "CVE-2024-21887" in content
        assert "Recommendations" in content

    def test_markdown_minimal(self, report_gen):
        """Report should work with just summary stats (no optional data)."""
        stats = {"total_posts": 0, "total_entities": 0,
                 "entity_distribution": {}, "classification_distribution": {},
                 "cve_enrichments_count": 0}
        path = report_gen.generate_markdown(summary_stats=stats)
        assert path.exists()
        content = path.read_text()
        assert "Executive Summary" in content

    def test_html_minimal(self, report_gen):
        stats = {"total_posts": 0, "total_entities": 0,
                 "entity_distribution": {}, "classification_distribution": {},
                 "cve_enrichments_count": 0}
        path = report_gen.generate_html(summary_stats=stats)
        assert path.exists()

    def test_custom_filename(self, report_gen):
        stats = {"total_posts": 5, "total_entities": 10,
                 "entity_distribution": {}, "classification_distribution": {"a": 5},
                 "cve_enrichments_count": 0}
        path = report_gen.generate_markdown(summary_stats=stats, filename="custom_report.md")
        assert path.name == "custom_report.md"


# ── Integration: Full pipeline -> analysis -> report ──────────────────────────

class TestAnalysisIntegration:
    def test_full_analysis_pipeline(self, populated_db, tmp_path):
        """End-to-end: populated DB -> trend analysis -> visualize -> report."""
        analyzer = TrendAnalyzer(populated_db)
        detector = AnomalyDetector(populated_db)
        viz = Visualizer()
        viz._chart_dir = tmp_path
        gen = ReportGenerator()
        gen._output_dir = tmp_path

        # Run all analyses
        stats = analyzer.get_summary_stats()
        keywords = analyzer.get_trending_keywords("90d")
        top_cves = analyzer.get_top_cves()
        cat_dist = analyzer.get_category_distribution("90d")
        ioc_dist = analyzer.get_ioc_distribution()
        anomalies = detector.detect(window_days=365)

        # Generate charts
        if cat_dist["categories"]:
            bar_fig = viz.category_bar_chart(cat_dist["categories"])
            viz.save_chart(bar_fig, "cat_bar.html")

        if keywords:
            viz.word_cloud(keywords, "trending")

        # Generate reports
        md_path = gen.generate_markdown(
            summary_stats=stats,
            category_dist=cat_dist,
            top_cves=top_cves,
            trending_keywords=keywords,
            ioc_dist=ioc_dist,
            anomalies=anomalies,
        )
        html_path = gen.generate_html(
            summary_stats=stats,
            category_dist=cat_dist,
            top_cves=top_cves,
            trending_keywords=keywords,
            ioc_dist=ioc_dist,
            anomalies=anomalies,
        )

        assert md_path.exists()
        assert html_path.exists()
        assert stats["total_posts"] > 0
        assert len(keywords) > 0
