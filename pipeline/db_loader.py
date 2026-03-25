"""
Pipeline Stage 4 — Database Loader.

Handles all SQLite interactions:

    - Schema initialization from database/schema.sql.
    - Idempotent ingestion of raw posts (content-hash dedup).
    - Entity storage with source-post foreign keys.
    - CVE enrichment upserts.
    - Classification result storage.
    - Query helpers for downstream modules (analysis, dashboard, export).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


class DatabaseLoader:
    """
    SQLite database interface for the threat intel toolkit.

    Usage::

        db = DatabaseLoader()
        db.init_schema()
        post_id = db.insert_raw_post(source_name, content, ...)
        db.insert_entities(post_id, entities_list)
        db.upsert_cve_enrichment(cve_data)
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = PROJECT_ROOT / settings.get(
                "project.database_path", "data/threat_intel.db"
            )
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    # ── Connection management ─────────────────────────────────────────────

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
                check_same_thread=False,  # Required for Streamlit/multi-thread access
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "DatabaseLoader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ── Schema initialization ─────────────────────────────────────────────

    def init_schema(self) -> None:
        """
        Create all tables and indexes from database/schema.sql.
        Safe to call multiple times (IF NOT EXISTS).
        """
        schema_path = PROJECT_ROOT / "database" / "schema.sql"
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        sql = schema_path.read_text(encoding="utf-8")
        self.conn.executescript(sql)
        logger.info("Database schema initialized: %s", self._db_path)

    # ── Source management ─────────────────────────────────────────────────

    def get_or_create_source(self, name: str, source_type: str, url: str = "") -> int:
        """Return the source ID, creating the source record if needed."""
        cursor = self.conn.execute(
            "SELECT id FROM sources WHERE name = ? AND url = ?", (name, url)
        )
        row = cursor.fetchone()
        if row:
            return row["id"]

        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "INSERT INTO sources (name, source_type, url, created_at) VALUES (?, ?, ?, ?)",
            (name, source_type, url, now),
        )
        self.conn.commit()
        source_id = cursor.lastrowid
        logger.debug("Created source: %s (id=%d)", name, source_id)
        return source_id

    def update_source_last_scraped(self, source_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE sources SET last_scraped_at = ? WHERE id = ?", (now, source_id)
        )
        self.conn.commit()

    # ── Raw post ingestion ────────────────────────────────────────────────

    def insert_raw_post(
        self,
        source_id: int,
        content: str,
        content_hash: str,
        scraped_at: str,
        http_status: int | None = None,
        url: str = "",
        metadata: dict | None = None,
    ) -> int | None:
        """
        Insert a raw post. Returns post ID, or None if duplicate.
        Idempotent: duplicate content_hash silently skipped.
        """
        meta_json = json.dumps(metadata) if metadata else None
        try:
            cursor = self.conn.execute(
                """
                INSERT OR IGNORE INTO raw_posts
                    (source_id, content, content_hash, scraped_at, http_status, url, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (source_id, content, content_hash, scraped_at, http_status, url, meta_json),
            )
            self.conn.commit()
            if cursor.lastrowid and cursor.rowcount > 0:
                return cursor.lastrowid
            return None
        except sqlite3.Error as exc:
            logger.error("Failed to insert raw post: %s", exc)
            return None

    def get_existing_hashes(self) -> set[str]:
        cursor = self.conn.execute("SELECT content_hash FROM raw_posts")
        return {row["content_hash"] for row in cursor.fetchall()}

    def get_post_id_by_hash(self, content_hash: str) -> int | None:
        cursor = self.conn.execute(
            "SELECT id FROM raw_posts WHERE content_hash = ?", (content_hash,)
        )
        row = cursor.fetchone()
        return row["id"] if row else None

    # ── Entity storage ────────────────────────────────────────────────────

    def insert_entities(self, post_id: int, entities: list[dict[str, Any]]) -> int:
        """Insert extracted entities for a post. Returns count inserted."""
        inserted = 0
        for ent in entities:
            try:
                self.conn.execute(
                    """
                    INSERT INTO entities
                        (post_id, entity_type, value, confidence, extraction_method, raw_match)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        post_id,
                        ent.get("entity_type", ""),
                        ent.get("value", ""),
                        ent.get("confidence", "medium"),
                        ent.get("extraction_method", "regex"),
                        ent.get("raw_match", ""),
                    ),
                )
                inserted += 1
            except sqlite3.Error as exc:
                logger.debug("Entity insert error (post %d): %s", post_id, exc)
        self.conn.commit()
        return inserted

    # ── CVE enrichment storage ────────────────────────────────────────────

    def upsert_cve_enrichment(self, cve_data: dict[str, Any]) -> None:
        """Insert or update CVE enrichment data (ON CONFLICT upsert)."""
        try:
            self.conn.execute(
                """
                INSERT INTO cve_enrichment
                    (cve_id, cvss_score, cvss_version, severity, description,
                     affected_products, published_date, last_modified_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    cvss_score = excluded.cvss_score,
                    cvss_version = excluded.cvss_version,
                    severity = excluded.severity,
                    description = excluded.description,
                    affected_products = excluded.affected_products,
                    published_date = excluded.published_date,
                    last_modified_date = excluded.last_modified_date,
                    enriched_at = datetime('now')
                """,
                (
                    cve_data.get("cve_id", ""),
                    cve_data.get("cvss_score"),
                    cve_data.get("cvss_version"),
                    cve_data.get("severity"),
                    cve_data.get("description", ""),
                    cve_data.get("affected_products", "[]"),
                    cve_data.get("published_date", ""),
                    cve_data.get("last_modified_date", ""),
                ),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            logger.error("CVE enrichment upsert failed for %s: %s", cve_data.get("cve_id"), exc)

    # ── Classification storage ────────────────────────────────────────────

    def insert_classification(
        self,
        post_id: int,
        category: str,
        model_used: str,
        confidence: float,
        mitre_techniques: list[str] | None = None,
    ) -> int | None:
        """Insert a classification result for a post."""
        mitre_json = json.dumps(mitre_techniques) if mitre_techniques else None
        try:
            cursor = self.conn.execute(
                """
                INSERT INTO classifications
                    (post_id, category, model_used, confidence, mitre_techniques)
                VALUES (?, ?, ?, ?, ?)
                """,
                (post_id, category, model_used, confidence, mitre_json),
            )
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as exc:
            logger.error("Classification insert failed: %s", exc)
            return None

    # ── Query helpers ─────────────────────────────────────────────────────

    def get_all_posts(self, limit: int = 1000) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM raw_posts ORDER BY scraped_at DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_unclassified_posts(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return posts that have no classification yet."""
        cursor = self.conn.execute(
            """
            SELECT rp.* FROM raw_posts rp
            LEFT JOIN classifications c ON rp.id = c.post_id
            WHERE c.id IS NULL
            ORDER BY rp.scraped_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_entities(
        self, entity_type: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """Return entities, optionally filtered by type."""
        if entity_type:
            cursor = self.conn.execute(
                "SELECT * FROM entities WHERE entity_type = ? ORDER BY created_at DESC LIMIT ?",
                (entity_type, limit),
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM entities ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_classifications(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Return classifications joined with post content."""
        cursor = self.conn.execute(
            """
            SELECT c.*, rp.content, rp.source_id, rp.scraped_at as post_scraped_at
            FROM classifications c
            JOIN raw_posts rp ON c.post_id = rp.id
            ORDER BY c.classified_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_cve_enrichments(self) -> list[dict[str, Any]]:
        cursor = self.conn.execute(
            "SELECT * FROM cve_enrichment ORDER BY cvss_score DESC"
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_entity_counts_by_type(self) -> dict[str, int]:
        cursor = self.conn.execute(
            "SELECT entity_type, COUNT(*) as cnt FROM entities GROUP BY entity_type ORDER BY cnt DESC"
        )
        return {row["entity_type"]: row["cnt"] for row in cursor.fetchall()}

    def get_classification_distribution(self) -> dict[str, int]:
        cursor = self.conn.execute(
            "SELECT category, COUNT(*) as cnt FROM classifications GROUP BY category ORDER BY cnt DESC"
        )
        return {row["category"]: row["cnt"] for row in cursor.fetchall()}

    def get_post_count(self) -> int:
        cursor = self.conn.execute("SELECT COUNT(*) as cnt FROM raw_posts")
        return cursor.fetchone()["cnt"]

    def get_entity_count(self) -> int:
        cursor = self.conn.execute("SELECT COUNT(*) as cnt FROM entities")
        return cursor.fetchone()["cnt"]

    # ── Scheduler run logging ─────────────────────────────────────────────

    def log_scheduler_run(
        self,
        job_name: str,
        status: str,
        started_at: str,
        finished_at: str | None = None,
        records_affected: int = 0,
        error_message: str | None = None,
    ) -> None:
        """Log a scheduler job execution."""
        try:
            self.conn.execute(
                """
                INSERT INTO scheduler_runs
                    (job_name, status, started_at, finished_at, records_affected, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job_name, status, started_at, finished_at, records_affected, error_message),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            logger.error("Scheduler run log failed: %s", exc)
