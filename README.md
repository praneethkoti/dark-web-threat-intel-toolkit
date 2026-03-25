# 🛡️ Dark Web Threat Intelligence Toolkit

Python toolkit for collecting, processing, classifying, and analyzing threat intelligence from public OSINT sources and simulated dark web data. Covers the full pipeline from raw scraping through AI-powered summarization, with a Streamlit dashboard and a CLI that wires everything together.

> **⚠️ Legal & Ethical:** This project uses **synthetic/simulated data** and **public APIs only**. No real dark web scraping, no .onion addresses, no stolen data. The architecture is designed so swapping in real sources requires minimal code changes.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLI  (cli.py)                               │
│  scrape │ process │ classify │ analyze │ export │ summarize │ dash   │
└────┬────┴────┬────┴────┬─────┴────┬────┴───┬────┴─────┬─────┴───┬───┘
     │         │         │          │        │          │         │
     ▼         ▼         ▼          ▼        ▼          ▼         ▼
┌─────────┐ ┌──────────┐ ┌───────────┐ ┌────────┐ ┌────────┐ ┌──────────┐
│ Scraper │ │ Pipeline │ │Classifier │ │Analysis│ │ Export │ │   AI     │
│ Engine  │ │ Engine   │ │  Engine   │ │& Report│ │ Engine │ │Summarizer│
│         │ │          │ │           │ │        │ │        │ │          │
│• Paste  │ │• Cleaner │ │• Keyword  │ │• Trends│ │• STIX  │ │• OpenAI  │
│• Feeds  │ │• Entity  │ │• ML (3)   │ │• Anomal│ │• CSV   │ │• Claude  │
│• Market │ │  Extract │ │• Zero-shot│ │• Charts│ │• MISP  │ │• Local   │
│• Forum  │ │• Enrich  │ │• MITRE    │ │• Report│ │        │ │  (HF)   │
└────┬────┘ │• DB Load │ │  ATT&CK   │ └───┬────┘ └───┬────┘ └────┬─────┘
     │      └────┬─────┘ └─────┬─────┘     │         │          │
     │           │             │            │         │          │
     ▼           ▼             ▼            ▼         ▼          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     SQLite Database (WAL mode)                        │
│  sources │ raw_posts │ entities │ cve_enrichment │ classifications    │
└──────────────────────────────────────────────────────────────────────┘
     │                                                        │
     ▼                                                        ▼
┌──────────────┐                                  ┌───────────────────┐
│  Scheduler   │                                  │    Streamlit      │
│ (APScheduler)│                                  │    Dashboard      │
│  5 auto jobs │                                  │  6 pages (live)   │
└──────────────┘                                  └───────────────────┘
```

---

## Project Structure

```
dark-web-threat-intel-toolkit/
├── scraper/                        # Module 1 — Data Scraping Engine
│   ├── base_scraper.py             #   Abstract base: retries, rate limit, UA rotation, proxy
│   ├── paste_scraper.py            #   Paste sites (fixtures + live dpaste.org)
│   ├── feed_scraper.py             #   OTX, Abuse.ch URLhaus/Bazaar, NIST NVD
│   ├── simulated_market_scraper.py #   Marketplace listings + forum threads
│   └── fixtures/                   #   Realistic HTML fixtures (15 posts, IOC-rich)
│       ├── marketplace_listing.html
│       ├── forum_thread.html
│       └── paste_dump.html
├── pipeline/                       # Module 2 — Data Processing Pipeline
│   ├── cleaner.py                  #   HTML strip, Unicode norm, dedup, noise removal
│   ├── entity_extractor.py         #   12 IOC regex patterns + spaCy NER
│   ├── enricher.py                 #   NVD CVE lookup (CVSS, severity, CPE)
│   └── db_loader.py                #   SQLite CRUD, idempotent ingestion, query helpers
├── classifier/                     # Module 3 — Threat Classification Engine
│   ├── keyword_classifier.py       #   Layer 1: weighted keyword scoring from YAML
│   ├── ml_classifier.py            #   Layer 2: TF-IDF → LR/RF/SVM + GridSearchCV
│   ├── bert_classifier.py          #   Layer 3: zero-shot (BART-MNLI)
│   ├── mitre_mapper.py             #   Layer 4: ATT&CK technique enrichment
│   ├── synthetic_data_generator.py #   2,500+ realistic training posts with Faker
│   └── keyword_configs/
│       └── threat_keywords.yaml    #   120+ weighted keywords across 6 categories
├── analysis/                       # Module 4 — Trend Analysis & Reporting
│   ├── trend_analyzer.py           #   Keywords, CVEs, categories, actors, products
│   ├── anomaly_detector.py         #   Z-score + rolling average spike detection
│   ├── visualizer.py               #   6 Plotly chart types + word clouds
│   └── report_generator.py         #   Markdown + styled HTML reports
├── export/                         # Module 5 — IOC Export
│   ├── stix_exporter.py            #   STIX 2.1 bundles (indicators, vulns, malware)
│   ├── csv_exporter.py             #   Filtered CSV (by type, confidence)
│   └── misp_exporter.py            #   MISP-compatible JSON events
├── ai_summarizer/                  # Module 6 — GenAI Threat Summarizer
│   ├── summarizer.py               #   Abstracted interface + prompt template loader
│   ├── openai_backend.py           #   GPT-4o / GPT-4o-mini
│   ├── anthropic_backend.py        #   Claude (claude-sonnet-4-20250514)
│   ├── local_backend.py            #   HuggingFace BART (no API key needed)
│   └── prompt_templates/           #   3 versioned YAML templates
│       ├── executive_summary.yaml
│       ├── technical_brief.yaml
│       └── ioc_bulletin.yaml
├── dashboard/                      # Module 7 — Streamlit Dashboard
│   ├── app.py                      #   Entry point + sidebar nav
│   └── pages/
│       ├── overview.py             #   Metrics, category charts, CVE table
│       ├── threat_feed.py          #   Filterable classified posts + detail view
│       ├── ioc_explorer.py         #   Search/filter IOCs, CSV download, post context
│       ├── trends.py               #   Timeline, anomalies, keywords, actor patterns
│       ├── report_page.py          #   Generate + preview + download reports
│       └── summarizer_page.py      #   On-demand AI summarization
├── scheduler/                      # Module 8 — Scheduler & Automation
│   └── scheduler.py                #   5 APScheduler jobs, CLI, run history logging
├── config/
│   ├── __init__.py                 #   Centralized settings loader (YAML + .env merge)
│   ├── settings.yaml               #   All configurable parameters
│   └── mitre_attack_mapping.yaml   #   6 categories → 25+ ATT&CK techniques
├── database/
│   └── schema.sql                  #   7 normalized tables + indexes
├── tests/                          #   207 passing tests
│   ├── test_scraper.py
│   ├── test_pipeline.py
│   ├── test_classifier.py
│   ├── test_export.py
│   ├── test_analysis.py
│   ├── test_summarizer.py
│   └── test_scheduler.py
├── cli.py                          #   Unified Click CLI (18 commands)
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

**Stats:** 52 Python files · 11,000+ lines of code · 207 tests (8 gated behind optional deps)

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repo
git clone https://github.com/praneethkoti/dark-web-threat-intel-toolkit.git
cd dark-web-threat-intel-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Install spaCy model (for NER entity extraction)
python -m spacy download en_core_web_sm

# Copy environment config
cp .env.example .env
# Edit .env to add API keys (optional — toolkit works without them)
```

### Optional API Keys

| Key | Purpose | Required? |
|-----|---------|-----------|
| `NVD_API_KEY` | Faster NVD rate limits (5→50 req/30s) | No |
| `OTX_API_KEY` | AlienVault OTX pulse access | No |
| `OPENAI_API_KEY` | GPT-4o summarization | Only for AI summarizer |
| `ANTHROPIC_API_KEY` | Claude summarization | Only for AI summarizer |

### Verify Installation

```bash
python -m pytest tests/ -v
# Expected: 207 passed, 8 skipped
```

---

## Quick Start

Run the entire pipeline in one command:

```bash
python cli.py full-pipeline --source fixtures --skip-enrichment
```

This will scrape fixture data → process and extract IOCs → classify threats → generate charts and reports → and show a summary. Then launch the dashboard:

```bash
python cli.py dashboard
# Opens http://localhost:8501
```

---

## CLI Usage

Every module is accessible through the unified CLI. Global flags: `--verbose` (debug logging), `--dry-run` (preview without executing).

### Scraping

```bash
# Scrape local fixture files (safe, offline, instant)
python cli.py scrape --source fixtures

# Scrape live paste sites
python cli.py scrape --source pastes --limit 50

# Scrape all threat feeds (OTX, URLhaus, MalwareBazaar, NVD)
python cli.py scrape --source feeds --limit 25

# Fetch a specific CVE from NVD
python cli.py scrape --source nvd --cve-id CVE-2024-21887

# Scrape NVD for a year's CVEs
python cli.py scrape --source nvd --cve-year 2024 --limit 100

# Scrape everything
python cli.py scrape --source all --limit 100
```

### Processing Pipeline

```bash
# Process all raw JSON files through clean → extract → enrich → store
python cli.py process --input data/raw

# Skip NVD enrichment (faster, no API calls)
python cli.py process --input data/raw --skip-enrichment

# Skip spaCy NER (regex-only extraction)
python cli.py process --input data/raw --skip-ner
```

### Classification

```bash
# Classify unclassified posts with keyword rules + MITRE mapping
python cli.py classify --model keyword --export-mitre

# Train ML models on synthetic data, then classify
python cli.py classify --model ml --train-ml --export-mitre

# Zero-shot classification with BART-MNLI (requires transformers + torch)
python cli.py classify --model bert

# Run all classifiers for comparison
python cli.py classify --model all --export-mitre --train-ml
```

### Analysis & Reporting

```bash
# Analyze last 30 days, generate charts + reports
python cli.py analyze --period 30d --output both

# Markdown report only
python cli.py analyze --period 7d --output report --format markdown

# Charts only
python cli.py analyze --period 90d --output charts
```

### IOC Export

```bash
# Export in all formats (STIX 2.1 + CSV + MISP)
python cli.py export --format all

# STIX 2.1 bundle only
python cli.py export --format stix

# CSV filtered to IP addresses only
python cli.py export --format csv --ioc-type ipv4
```

### AI Summarization

```bash
# Executive summary via OpenAI
python cli.py summarize --mode executive --period 24h --backend openai

# Technical brief via Claude
python cli.py summarize --mode technical --period 7d --backend anthropic

# IOC bulletin via local model (no API key needed)
python cli.py summarize --mode ioc_bulletin --backend local

# Summarize specific posts
python cli.py summarize --mode technical --post-ids 1,2,3
```

### Dashboard

```bash
# Launch Streamlit dashboard
python cli.py dashboard

# Custom port
python cli.py dashboard --port 8080
```

### Scheduler

```bash
# Start automated scheduler daemon
python cli.py scheduler start

# View scheduled jobs
python cli.py scheduler status

# Manually trigger a job
python cli.py scheduler run-now --task scrape_pastes
python cli.py scheduler run-now --task classify_new
python cli.py scheduler run-now --task daily_report

# View run history
python cli.py scheduler history
```

### Utilities

```bash
# Show database statistics
python cli.py db-info

# Generate synthetic training data
python cli.py generate-data --count 2500 --balanced

# Dry run any command
python cli.py --dry-run full-pipeline --source fixtures
```

---

## Threat Categories

The toolkit classifies posts into six categories, each mapped to MITRE ATT&CK techniques:

| Category | ATT&CK Techniques | Example Signals |
|----------|-------------------|-----------------|
| **Data Breach** | T1078, T1110, T1552, T1530, T1567 | "credential dump", "database leak", "combo list", email:pass patterns |
| **Exploit / Vulnerability** | T1190, T1203, T1068 | CVE references, "remote code execution", "proof of concept", "buffer overflow" |
| **Ransomware / Malware** | T1486, T1059, T1547, T1027, T1071 | "ransomware", "RAT", "keylogger", "C2", malware hashes |
| **Carding / Financial Fraud** | T1056, T1185, T1557, T1566 | "fullz", "CVV", "skimmer", "bank logs", "cashout" |
| **Threat Actor Comms** | T1583, T1585, T1588, T1586 | "hiring", "affiliate program", "opsec", Jabber/Tox contacts |
| **Zero-Day** | T1190, T1189, T1195 | "0day", "unpatched", "private exploit", "no CVE assigned" |

---

## IOC Extraction

The entity extractor identifies 12 IOC types using regex patterns with overlap prevention:

| IOC Type | Pattern | Example |
|----------|---------|---------|
| IPv4 | Dotted quad validation | `185.220.101.34` |
| IPv6 | Full + compressed forms | `2001:db8::1` |
| Email | Standard + defanged `[at]` | `admin@evil-corp.com` |
| URL | http/https/hxxp + defanging | `hxxps://malware[.]com/payload` |
| CVE ID | CVE-YYYY-NNNNN+ | `CVE-2024-21887` |
| Bitcoin | P2PKH, P2SH, bech32 | `bc1qar0srrr7xfkvy5l643...` |
| Monero | 95-char base58 | `44AFFq5kSiGBoZ...` |
| MD5 | 32 hex chars | `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6` |
| SHA-1 | 40 hex chars | (no overlap with SHA-256) |
| SHA-256 | 64 hex chars | (matched first to prevent MD5/SHA-1 false positives) |
| Credentials | email:pass and user:pass | `admin@corp.com:Password123!` |
| PGP Fingerprint | 40 hex with optional spaces | `4A2F 8120 D089 3E1A...` |

spaCy NER adds contextual extraction for **organization names**, **person names**, and **locations** mentioned in threat context.

---

## Export Formats

| Format | Library | Use Case |
|--------|---------|----------|
| **STIX 2.1** | `stix2` | Feed into TIP platforms (MISP, OpenCTI, ThreatConnect). Includes Indicators, Vulnerabilities, Malware objects, and Relationships. |
| **CSV** | stdlib | Analyst spreadsheets. Filterable by IOC type and confidence level. Per-type CSV files auto-generated. |
| **MISP** | native JSON | Direct import into MISP via REST API. Proper attribute type mapping, TLP tags, IDS flags based on confidence. |

---

## Database Schema

SQLite with WAL mode for concurrent dashboard reads. 7 normalized tables:

- **`sources`** — scraper source registry with last-scraped timestamps
- **`raw_posts`** — ingested content with SHA-256 dedup (idempotent)
- **`entities`** — extracted IOCs linked to posts via foreign key
- **`cve_enrichment`** — NVD data (CVSS, severity, CPE) with upsert
- **`classifications`** — multi-model results (same post, different models)
- **`summaries`** — AI-generated summary audit trail
- **`scheduler_runs`** — job execution log (status, timing, record counts)

---

## How This Could Be Extended

- **Real dark web sources** — swap fixture URLs for Tor-proxied .onion endpoints (SOCKS5 proxy already configurable)
- **YARA rule generation** — auto-generate YARA rules from extracted file hashes and string patterns
- **Slack/Teams alerting** — add webhook notifications for anomaly spikes or critical CVE mentions
- **Multi-tenant** — replace SQLite with PostgreSQL for team-scale deployment
- **Graph analysis** — build relationship graphs between threat actors, IOCs, and CVEs using NetworkX
- **Fine-tuned classifier** — train DistilBERT on the synthetic data instead of zero-shot for better accuracy
- **Automated SIEM ingestion** — push STIX bundles directly to Splunk/Elastic via API
- **Historical comparison** — week-over-week trend diffing for threat landscape shift detection

---

## Design Notes

**Why a base scraper class?** Every source-specific scraper just implements `scrape()` and `parse()`. Rate limiting, retries, UA rotation, and proxy routing all live in `BaseScraper`. Adding a new source is a ~50-line subclass, not a copy-paste job.

**Idempotent pipeline.** Raw posts are deduped by SHA-256 content hash at two points: in-memory during cleaning, and `INSERT OR IGNORE` at the DB layer. The scheduler can run hourly without creating duplicate records.

**Multi-layer classification tradeoffs.** Keyword is fast and transparent but brittle. TF-IDF + ML generalizes better but needs training data (hence the synthetic generator). Zero-shot transformer needs nothing but is slow — good for triage on low-confidence results, not bulk. In practice I'd cascade them: keyword first, ML for the bulk, zero-shot only when both disagree.

**Why MITRE ATT&CK?** Raw labels like "ransomware" aren't actionable for SOC teams. Mapping to technique IDs (T1486, T1059) connects directly to detection rules and IR playbooks. It's how you make threat intel consumable downstream.

**Synthetic data realism.** The generator includes l33tspeak substitutions, typos, and multilingual fragments (Russian, Chinese, Arabic) because real dark web posts aren't clean English. A classifier trained on sanitized text performs badly on real data. The balanced/imbalanced toggle matters for testing how models handle skewed class distributions.

**Export format choices.** STIX 2.1 for TIP-to-TIP sharing, CSV for analysts in spreadsheets, MISP JSON for direct platform import. Each serves a different consumer in the intel-sharing workflow.

**Config-driven architecture.** Everything tunable — scrape delays, model names, keyword weights, cron expressions, NVD rate limits — lives in `settings.yaml` or `.env`. Nothing hardcoded. Deploying somewhere new is a config change, not a code change.

**Anomaly detection limitations.** Z-score is simple and interpretable but will false-positive on data with weekly cycles. At real scale I'd use Prophet or an isolation forest. The threshold (2.5σ) is configurable for a reason.

**LLM backend abstraction.** The `LLMBackend` Protocol means any class with `generate(system_prompt, user_prompt) → str` works. Swapping backends is one config line. Prompt templates are versioned YAML so you can A/B test without touching code.

**What I'd change at scale.** SQLite → PostgreSQL with connection pooling. APScheduler → Celery + Redis for distributed jobs. Add Playwright for JS-heavy pages. Fine-tune a NER model on threat intel corpora instead of using generic spaCy. Move the dashboard to a proper React frontend with a REST API layer. Add RBAC and audit logging.

---

## License

MIT — see [LICENSE](LICENSE).
