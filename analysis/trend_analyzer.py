"""
Trend Analysis Engine.

Analyzes processed + classified data from the database to surface:
    - Trending threat keywords over configurable time windows.
    - Most mentioned CVEs cross-referenced with CVSS severity.
    - Threat category distribution over time.
    - Threat actor patterns (usernames across multiple sources/posts).
    - Top targeted products/vendors from CVE enrichment data.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

# Common stopwords to exclude from keyword trending
_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
    "into", "through", "during", "before", "after", "above", "below",
    "between", "out", "off", "over", "under", "again", "further", "then",
    "once", "here", "there", "when", "where", "why", "how", "all", "each",
    "every", "both", "few", "more", "most", "other", "some", "such", "no",
    "nor", "not", "only", "own", "same", "so", "than", "too", "very",
    "just", "because", "but", "and", "or", "if", "this", "that", "these",
    "those", "it", "its", "i", "me", "my", "we", "our", "you", "your",
    "he", "him", "his", "she", "her", "they", "them", "their", "what",
    "which", "who", "whom", "also", "about", "up", "new", "one", "two",
    "get", "got", "use", "used", "using", "like", "post", "forum",
    "thread", "listing", "marketplace", "vendor", "price", "category",
    "date", "rating", "sales", "tags", "http", "https", "www", "com",
}


def _parse_time_window(window: str) -> timedelta:
    """Convert a string like '7d', '30d', '90d' to a timedelta."""
    match = re.match(r"(\d+)([dhm])", window.lower())
    if not match:
        return timedelta(days=30)
    val, unit = int(match.group(1)), match.group(2)
    if unit == "d":
        return timedelta(days=val)
    elif unit == "h":
        return timedelta(hours=val)
    elif unit == "m":
        return timedelta(days=val * 30)
    return timedelta(days=30)


def _safe_parse_dt(dt_str: str | None) -> datetime | None:
    """Parse an ISO-8601 datetime string, returning None on failure."""
    if not dt_str:
        return None
    try:
        # Handle various ISO formats
        dt_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None


class TrendAnalyzer:
    """
    Analyze threat intelligence data for trends and patterns.

    Usage::

        from pipeline.db_loader import DatabaseLoader
        db = DatabaseLoader()
        analyzer = TrendAnalyzer(db)
        trends = analyzer.get_trending_keywords("30d")
        cves = analyzer.get_top_cves()
        distribution = analyzer.get_category_distribution("7d")
    """

    def __init__(self, db: Any) -> None:
        self._db = db
        self._top_n_keywords = settings.get("analysis.top_n_keywords", 30)
        self._top_n_cves = settings.get("analysis.top_n_cves", 20)

    # ── Trending Keywords ─────────────────────────────────────────────────

    def get_trending_keywords(
        self, window: str = "30d", top_n: int | None = None
    ) -> list[dict[str, Any]]:
        """
        Extract trending keywords from post content within a time window.

        Returns list of dicts: [{"keyword": str, "count": int, "rank": int}]
        """
        top_n = top_n or self._top_n_keywords
        cutoff = datetime.now(timezone.utc) - _parse_time_window(window)
        posts = self._db.get_all_posts(limit=5000)

        word_counter: Counter = Counter()
        for post in posts:
            post_dt = _safe_parse_dt(post.get("scraped_at"))
            if post_dt and post_dt.tzinfo is None:
                post_dt = post_dt.replace(tzinfo=timezone.utc)
            if post_dt and post_dt < cutoff:
                continue

            content = post.get("content", "").lower()
            # Extract words (3+ chars, alpha only)
            words = re.findall(r"\b[a-z]{3,}\b", content)
            meaningful = [w for w in words if w not in _STOPWORDS]
            word_counter.update(meaningful)

        results = []
        for rank, (word, count) in enumerate(word_counter.most_common(top_n), 1):
            results.append({"keyword": word, "count": count, "rank": rank})

        logger.info("Trending keywords (%s): %d terms analyzed", window, len(word_counter))
        return results

    # ── Top CVEs ──────────────────────────────────────────────────────────

    def get_top_cves(self, top_n: int | None = None) -> list[dict[str, Any]]:
        """
        Return most-mentioned CVEs cross-referenced with CVSS severity.

        Returns list of dicts with cve_id, mention_count, cvss_score, severity.
        """
        top_n = top_n or self._top_n_cves
        entities = self._db.get_entities(entity_type="cve_id", limit=5000)
        enrichments = {
            e["cve_id"]: e for e in self._db.get_cve_enrichments()
        }

        cve_counter: Counter = Counter()
        for ent in entities:
            cve_counter[ent["value"]] += 1

        results = []
        for cve_id, count in cve_counter.most_common(top_n):
            enrichment = enrichments.get(cve_id, {})
            results.append({
                "cve_id": cve_id,
                "mention_count": count,
                "cvss_score": enrichment.get("cvss_score"),
                "severity": enrichment.get("severity", "UNKNOWN"),
                "description": enrichment.get("description", "")[:200],
            })

        logger.info("Top CVEs: %d unique CVEs found", len(cve_counter))
        return results

    # ── Category Distribution Over Time ───────────────────────────────────

    def get_category_distribution(
        self, window: str = "30d"
    ) -> dict[str, Any]:
        """
        Get threat category distribution within a time window.

        Returns:
            {
                "window": "30d",
                "total": int,
                "categories": {"data_breach": 15, "ransomware_malware": 10, ...},
                "timeline": [{"date": "2024-11-10", "data_breach": 3, ...}, ...]
            }
        """
        cutoff = datetime.now(timezone.utc) - _parse_time_window(window)
        classifications = self._db.get_classifications(limit=5000)

        category_counts: Counter = Counter()
        daily_counts: dict[str, Counter] = {}

        for cls in classifications:
            cls_dt = _safe_parse_dt(cls.get("classified_at") or cls.get("post_scraped_at"))
            if cls_dt and cls_dt.tzinfo is None:
                cls_dt = cls_dt.replace(tzinfo=timezone.utc)
            if cls_dt and cls_dt < cutoff:
                continue

            category = cls.get("category", "unknown")
            category_counts[category] += 1

            if cls_dt:
                day_key = cls_dt.strftime("%Y-%m-%d")
                if day_key not in daily_counts:
                    daily_counts[day_key] = Counter()
                daily_counts[day_key][category] += 1

        # Build sorted timeline
        timeline = []
        for day in sorted(daily_counts.keys()):
            entry = {"date": day}
            entry.update(dict(daily_counts[day]))
            timeline.append(entry)

        return {
            "window": window,
            "total": sum(category_counts.values()),
            "categories": dict(category_counts),
            "timeline": timeline,
        }

    # ── Threat Actor Patterns ─────────────────────────────────────────────

    def get_threat_actor_patterns(self) -> list[dict[str, Any]]:
        """
        Identify usernames/actors that appear across multiple posts/sources.

        Scans post metadata for username fields and looks for repeated
        appearances, which may indicate active threat actors.
        """
        posts = self._db.get_all_posts(limit=5000)
        actor_posts: dict[str, list[dict[str, Any]]] = {}

        for post in posts:
            meta_raw = post.get("metadata")
            if not meta_raw:
                continue
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
            except (json.JSONDecodeError, TypeError):
                continue

            username = meta.get("username") or meta.get("author") or meta.get("vendor")
            if not username or username.lower() in ("anonymous", "unknown", ""):
                continue

            username = username.strip()
            if username not in actor_posts:
                actor_posts[username] = []
            actor_posts[username].append({
                "post_id": post.get("id"),
                "source_id": post.get("source_id"),
                "scraped_at": post.get("scraped_at"),
            })

        # Filter to actors with multiple appearances
        patterns = []
        for username, appearances in actor_posts.items():
            if len(appearances) >= 2:
                source_ids = {a.get("source_id") for a in appearances}
                patterns.append({
                    "username": username,
                    "post_count": len(appearances),
                    "unique_sources": len(source_ids),
                    "appearances": appearances,
                })

        patterns.sort(key=lambda x: x["post_count"], reverse=True)
        logger.info("Threat actor patterns: %d actors with 2+ posts", len(patterns))
        return patterns

    # ── Top Targeted Products ─────────────────────────────────────────────

    def get_top_targeted_products(self, top_n: int = 15) -> list[dict[str, Any]]:
        """
        Extract most targeted products/vendors from CVE enrichment data.

        Parses CPE strings from affected_products to identify product names.
        """
        enrichments = self._db.get_cve_enrichments()
        product_counter: Counter = Counter()

        for enr in enrichments:
            products_raw = enr.get("affected_products", "[]")
            try:
                products = json.loads(products_raw) if isinstance(products_raw, str) else products_raw
            except (json.JSONDecodeError, TypeError):
                continue

            for cpe in products:
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":") if isinstance(cpe, str) else []
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    product_counter[f"{vendor}/{product}"] += 1

        results = []
        for product, count in product_counter.most_common(top_n):
            vendor, prod = product.split("/", 1) if "/" in product else (product, "")
            results.append({
                "vendor": vendor,
                "product": prod,
                "cve_count": count,
            })

        logger.info("Top targeted products: %d vendors/products found", len(product_counter))
        return results

    # ── IOC Type Distribution ─────────────────────────────────────────────

    def get_ioc_distribution(self) -> dict[str, int]:
        return self._db.get_entity_counts_by_type()

    def get_summary_stats(self) -> dict[str, Any]:
        return {
            "total_posts": self._db.get_post_count(),
            "total_entities": self._db.get_entity_count(),
            "entity_distribution": self._db.get_entity_counts_by_type(),
            "classification_distribution": self._db.get_classification_distribution(),
            "cve_enrichments_count": len(self._db.get_cve_enrichments()),
        }
