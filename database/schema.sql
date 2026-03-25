-- =============================================================================
-- Dark Web Threat Intelligence Toolkit — SQLite Schema
-- =============================================================================
-- Normalized schema for storing scraped data, extracted entities,
-- CVE enrichment, and classification results.
--
-- Design decisions:
--   • content_hash in raw_posts enables idempotent ingestion (dedup).
--   • Entities reference their source post via post_id FK.
--   • Classifications are stored separately so the same post can be
--     classified by multiple models and compared.
--   • All timestamps are ISO-8601 strings (SQLite has no native datetime).
-- =============================================================================

PRAGMA journal_mode = WAL;        -- Better concurrency for dashboard reads
PRAGMA foreign_keys = ON;

-- ── Sources ──────────────────────────────────────────────────────────────────
-- Registry of every data source the toolkit has scraped from.
CREATE TABLE IF NOT EXISTS sources (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,                   -- e.g. "dpaste", "nvd", "simulated_market"
    source_type     TEXT    NOT NULL,                   -- paste | feed | simulated | other
    url             TEXT,                               -- base URL or fixture path
    last_scraped_at TEXT,                               -- ISO-8601
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, url)
);

-- ── Raw Posts ────────────────────────────────────────────────────────────────
-- Every piece of content ingested, before any processing.
CREATE TABLE IF NOT EXISTS raw_posts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       INTEGER NOT NULL REFERENCES sources(id),
    content         TEXT    NOT NULL,
    content_hash    TEXT    NOT NULL UNIQUE,            -- SHA-256 of content for dedup
    scraped_at      TEXT    NOT NULL,                   -- ISO-8601
    http_status     INTEGER,
    url             TEXT,                               -- Specific page URL if applicable
    metadata        TEXT,                               -- JSON blob for extra fields
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_raw_posts_source   ON raw_posts(source_id);
CREATE INDEX IF NOT EXISTS idx_raw_posts_hash     ON raw_posts(content_hash);
CREATE INDEX IF NOT EXISTS idx_raw_posts_scraped  ON raw_posts(scraped_at);

-- ── Entities (IOCs) ──────────────────────────────────────────────────────────
-- Extracted Indicators of Compromise linked back to their source post.
CREATE TABLE IF NOT EXISTS entities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER NOT NULL REFERENCES raw_posts(id),
    entity_type     TEXT    NOT NULL,                   -- email | ipv4 | ipv6 | domain | url |
                                                       -- bitcoin_address | monero_address | cve_id |
                                                       -- credential_pair | md5 | sha1 | sha256 |
                                                       -- pgp_fingerprint | person | organization | location
    value           TEXT    NOT NULL,
    confidence      TEXT    NOT NULL DEFAULT 'medium',  -- high | medium | low
    extraction_method TEXT  NOT NULL DEFAULT 'regex',   -- regex | ner | regex+ner
    raw_match       TEXT,                               -- Original matched text (before normalization)
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_entities_post   ON entities(post_id);
CREATE INDEX IF NOT EXISTS idx_entities_type   ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_value  ON entities(value);

-- ── CVE Enrichment ───────────────────────────────────────────────────────────
-- NVD-sourced details for every CVE ID we've extracted.
CREATE TABLE IF NOT EXISTS cve_enrichment (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id              TEXT    NOT NULL UNIQUE,        -- e.g. CVE-2024-12345
    cvss_score          REAL,
    cvss_version        TEXT,                           -- "3.1" or "2.0"
    severity            TEXT,                           -- CRITICAL | HIGH | MEDIUM | LOW | NONE
    description         TEXT,
    affected_products   TEXT,                           -- JSON array of CPE strings
    published_date      TEXT,
    last_modified_date  TEXT,
    enriched_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_enrichment(severity);

-- ── Classifications ──────────────────────────────────────────────────────────
-- Every classification result for a post, supporting multiple models.
CREATE TABLE IF NOT EXISTS classifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER NOT NULL REFERENCES raw_posts(id),
    category        TEXT    NOT NULL,                   -- Threat category label
    model_used      TEXT    NOT NULL,                   -- keyword | logistic_regression | svm |
                                                       -- random_forest | zero_shot | distilbert
    confidence      REAL    NOT NULL,                   -- 0.0 – 1.0
    mitre_techniques TEXT,                              -- JSON array of ATT&CK technique IDs
    classified_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_class_post     ON classifications(post_id);
CREATE INDEX IF NOT EXISTS idx_class_category ON classifications(category);
CREATE INDEX IF NOT EXISTS idx_class_model    ON classifications(model_used);

-- ── Summaries ────────────────────────────────────────────────────────────────
-- AI-generated summaries stored for audit trail.
CREATE TABLE IF NOT EXISTS summaries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    summary_type    TEXT    NOT NULL,                   -- executive | technical | ioc_bulletin | daily_digest
    content         TEXT    NOT NULL,
    backend_used    TEXT    NOT NULL,                   -- openai | local
    model_name      TEXT,
    prompt_template TEXT,
    post_ids        TEXT,                               -- JSON array of post IDs summarized
    generated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Scheduler Run Log ────────────────────────────────────────────────────────
-- Tracks every automated job execution for observability.
CREATE TABLE IF NOT EXISTS scheduler_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_name        TEXT    NOT NULL,
    status          TEXT    NOT NULL,                   -- success | failure | skipped
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    records_affected INTEGER DEFAULT 0,
    error_message   TEXT,
    CONSTRAINT valid_status CHECK (status IN ('success', 'failure', 'skipped'))
);

CREATE INDEX IF NOT EXISTS idx_sched_job    ON scheduler_runs(job_name);
CREATE INDEX IF NOT EXISTS idx_sched_status ON scheduler_runs(status);
