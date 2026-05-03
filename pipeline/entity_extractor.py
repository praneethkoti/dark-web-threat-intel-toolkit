"""
Pipeline Stage 2 — Entity Extraction.

Extracts Indicators of Compromise (IOCs) and contextual entities from
cleaned text using two complementary approaches:

    1. **Regex patterns** — high-precision extraction for structured IOCs
       (IPs, hashes, emails, CVEs, crypto wallets, credentials, etc.).
    2. **spaCy NER** — contextual entity recognition for unstructured
       mentions (organization names, person names, locations).

Each extracted entity gets a confidence score:
    - ``"high"``   — regex match (structured, unambiguous).
    - ``"medium"`` — NER-only match (contextual, may be noisy).
    - ``"high"``   — both regex and NER agree (strongest signal).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

# ── Lazy spaCy loading (heavy import — only when needed) ─────────────────────
_nlp = None


def _get_nlp():
    """Load spaCy model lazily to avoid slow startup when NER isn't needed."""
    global _nlp
    if _nlp is None:
        import spacy

        model_name = settings.get("pipeline.entity_extraction.spacy_model", "en_core_web_sm")
        try:
            _nlp = spacy.load(model_name)
            logger.info("Loaded spaCy model: %s", model_name)
        except OSError:
            logger.warning(
                "spaCy model '%s' not found. Install with: python -m spacy download %s",
                model_name,
                model_name,
            )
            _nlp = spacy.blank("en")
    return _nlp


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class ExtractedEntity:
    """A single IOC or named entity extracted from text."""

    entity_type: str
    value: str
    raw_match: str
    confidence: str
    extraction_method: str
    context: str = ""
    source_ref: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Regex pattern library ─────────────────────────────────────────────────────

def _identity(m: str) -> str:
    return m.strip()

def _lower(m: str) -> str:
    return m.strip().lower()

def _defang(m: str) -> str:
    """Remove defanging brackets: hxxp[://], [.] etc."""
    m = m.replace("hxxp", "http").replace("[://]", "://")
    m = m.replace("[.]", ".").replace("(.)", ".")
    m = m.replace("[at]", "@").replace("[@]", "@")
    return m.strip()


# IPv4
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPv6 (simplified)
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}\b"
)

# Email addresses
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+(?:@|\[at\]|\[@\])(?:[a-zA-Z0-9.\-]+\.)+[a-zA-Z]{2,}\b"
)

# URLs (including defanged hxxp)
_RE_URL = re.compile(
    r"(?:https?|hxxps?|ftp)(?:://|\[://\])[\w\-._~:/?#\[\]@!$&'()*+,;=%]+"
)

# CVE IDs
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Bitcoin addresses (legacy P2PKH, P2SH, and bech32)
_RE_BTC = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b"
)

# Monero addresses (95-char base58, starts with 4 or 8)
_RE_XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# MD5 hashes (exactly 32 hex chars)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# SHA-1 hashes (exactly 40 hex chars)
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")

# SHA-256 hashes (exactly 64 hex chars)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Credential pairs (user:pass, email:pass patterns)
_RE_CREDENTIAL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:[^\s,;]{3,}\b"
    r"|"
    r"\b[a-zA-Z0-9._\-]{3,30}:[^\s,;]{3,30}\b"
)

# PGP key fingerprints (40 hex chars with optional spaces)
_RE_PGP = re.compile(
    r"\b(?:[0-9A-Fa-f]{4}\s+){9}[0-9A-Fa-f]{4}\b"
    r"|"
    r"\b[0-9A-Fa-f]{40}\b"
)

# Domains — permissive regex, post-match filter for non-domain patterns.
#
# Design rationale: threat actors register on new gTLDs constantly (.crypto,
# .xyz, .onion, etc.), so a hardcoded IANA allowlist goes stale the moment
# any new TLD ships. A raw permissive regex, on the other hand, floods the
# IOC explorer with garbage like "report.pdf" or "version.2.0". The hybrid
# approach: permissive match on structure, then `_is_likely_domain()` rejects
# anything whose final label is a known non-domain extension or whose
# second-level label looks like a version number.
#
# Accepts plain (evil-corp.com) and defanged (evil-corp[.]com) forms.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))+"
    r"[a-zA-Z]{2,24}\b"
)

# Final-label strings that structurally look like a TLD but are overwhelmingly
# filenames or archive extensions in threat intel text. Keeping this list
# short and conservative — we only reject extensions that have ~zero real
# TLD usage. (e.g., .py IS a ccTLD for Paraguay, so it is NOT in this set.)
_NON_DOMAIN_TLDS: frozenset[str] = frozenset({
    # Executables & libraries
    "exe", "dll", "msi", "msix", "bat", "cmd", "ps1", "sh", "bin",
    # Archives
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "tbz",
    # Disk images & installers
    "iso", "img", "dmg", "deb", "rpm", "apk", "ipa", "pkg",
    # Transient & dev artefacts
    "bak", "tmp", "old", "log", "swp", "lock", "pid",
    # Config & structured data (never valid TLDs)
    "ini", "cfg", "conf", "sql", "csv", "tsv",
    # Compiled/intermediate code
    "pdb", "obj", "class", "jar", "pyc", "pyo", "o",
    # Fonts
    "ttf", "otf", "woff", "woff2",
})


def _is_likely_domain(candidate: str) -> bool:
    """
    Post-match filter: reject candidates whose shape matches a domain but
    whose semantics point elsewhere (filenames, version strings, etc.).

    Called AFTER regex match + defang/lowercase normalization, so `candidate`
    is already the normalized value (e.g. "evil-corp.com", not
    "evil-corp[.]com").
    """
    labels = candidate.split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]
    if len(tld) < 2 or tld in _NON_DOMAIN_TLDS:
        return False

    # If the second-level label is purely numeric, this is almost certainly
    # a version string ("1.2.beta") or IP-like noise, not a domain.
    sld = labels[-2]
    if sld.isdigit():
        return False

    # Reject candidates that are entirely digits+dots with a stray alpha TLD
    # (unlikely to match the regex at all, but belt-and-braces).
    if all(label.isdigit() for label in labels[:-1]):
        return False

    return True


# Master pattern registry — ORDER MATTERS (longer matches first to prevent overlap)
_REGEX_PATTERNS: list[tuple[str, re.Pattern, callable]] = [
    ("sha256",           _RE_SHA256,      _lower),
    ("sha1",             _RE_SHA1,        _lower),
    ("md5",              _RE_MD5,         _lower),
    ("cve_id",           _RE_CVE,         lambda m: m.strip().upper()),
    ("email",            _RE_EMAIL,       _defang),
    ("url",              _RE_URL,         _defang),
    ("domain",           _RE_DOMAIN,      lambda m: _defang(m).lower()),
    ("ipv6",             _RE_IPV6,        _identity),
    ("ipv4",             _RE_IPV4,        _identity),
    ("bitcoin_address",  _RE_BTC,         _identity),
    ("monero_address",   _RE_XMR,         _identity),
    ("credential_pair",  _RE_CREDENTIAL,  _identity),
    ("pgp_fingerprint",  _RE_PGP,        lambda m: m.replace(" ", "").upper()),
]

_HASH_TYPES = {"sha256", "sha1", "md5", "pgp_fingerprint"}


class EntityExtractor:
    """
    Extract IOCs and named entities from cleaned text.

    Usage::

        extractor = EntityExtractor()
        entities = extractor.extract(text, source_ref="post-123")
        entities = extractor.extract_batch(items)
    """

    def __init__(self, use_ner: bool = True) -> None:
        self._use_ner = use_ner
        enabled_types = settings.get("pipeline.entity_extraction.extract_types", [])
        self._enabled_types: set[str] = set(enabled_types) if enabled_types else set()

    def extract(self, text: str, source_ref: str = "") -> list[ExtractedEntity]:
        """
        Extract all IOCs and named entities from a single text.

        Returns list of ExtractedEntity, deduplicated by (type, value).
        """
        if not text or not text.strip():
            return []

        entities: list[ExtractedEntity] = []
        seen: set[tuple[str, str]] = set()
        matched_spans: set[tuple[int, int]] = set()

        # ── Pass 1: Regex extraction ──────────────────────────────────
        for entity_type, pattern, normalizer in _REGEX_PATTERNS:
            if self._enabled_types and entity_type not in self._enabled_types:
                continue

            for match in pattern.finditer(text):
                start, end = match.span()
                raw = match.group()
                normalized = normalizer(raw)

                # Prevent hash overlap (64-char string shouldn't also match as MD5/SHA1)
                if entity_type in _HASH_TYPES:
                    overlap = False
                    for ms, me in matched_spans:
                        if start >= ms and end <= me and (end - start) < (me - ms):
                            overlap = True
                            break
                    if overlap:
                        continue
                    matched_spans.add((start, end))

                # PGP / SHA-1 disambiguation: both patterns match 40-char hex.
                # SHA-1 is listed first in _REGEX_PATTERNS so it wins by default.
                # When the surrounding text contains PGP/GPG/fingerprint keywords
                # the match is almost certainly a PGP fingerprint, not a file hash,
                # so reclassify it here before dedup.
                if entity_type == "sha1":
                    ctx_window = text[max(0, start - 100): end + 100].lower()
                    if any(kw in ctx_window for kw in ("pgp", "gpg", "fingerprint", "key id", "key fingerprint")):
                        entity_type = "pgp_fingerprint"
                        normalized = normalizer(raw).upper()

                # PGP solid-format (\b[0-9A-Fa-f]{40}\b) overlaps exactly with
                # SHA-1. After the SHA-1 reclassification above handles true PGP
                # hits, any remaining pgp_fingerprint match for a 40-char solid
                # hex string with no PGP keyword context is noise — skip it.
                if entity_type == "pgp_fingerprint" and len(raw.replace(" ", "")) == 40:
                    ctx_window = text[max(0, start - 100): end + 100].lower()
                    if not any(kw in ctx_window for kw in ("pgp", "gpg", "fingerprint", "key id", "key fingerprint")):
                        continue

                # Skip domains that are part of emails/URLs, or that look
                # like filenames/version strings despite matching the regex.
                if entity_type == "domain":
                    context_window = text[max(0, start - 5):end + 5]
                    if "@" in context_window or "://" in context_window:
                        continue
                    if not _is_likely_domain(normalized):
                        continue

                key = (entity_type, normalized)
                if key in seen:
                    continue
                seen.add(key)

                ctx_start = max(0, start - 80)
                ctx_end = min(len(text), end + 80)
                context = text[ctx_start:ctx_end].replace("\n", " ").strip()

                entities.append(
                    ExtractedEntity(
                        entity_type=entity_type,
                        value=normalized,
                        raw_match=raw,
                        confidence="high",
                        extraction_method="regex",
                        context=context,
                        source_ref=source_ref,
                    )
                )

        # ── Pass 2: spaCy NER ─────────────────────────────────────────
        if self._use_ner:
            ner_entities = self._extract_ner(text, source_ref)
            for ent in ner_entities:
                key = (ent.entity_type, ent.value)
                if key in seen:
                    for existing in entities:
                        if existing.entity_type == ent.entity_type and existing.value == ent.value:
                            existing.confidence = "high"
                            existing.extraction_method = "regex+ner"
                            break
                else:
                    seen.add(key)
                    entities.append(ent)

        logger.debug("Extracted %d entities from source %s", len(entities), source_ref)
        return entities

    def extract_batch(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Extract entities from a batch of cleaned items.

        Each item dict should have "cleaned_content". Returns the same
        items with an "entities" key added.
        """
        results: list[dict[str, Any]] = []

        for item in items:
            text = item.get("cleaned_content", item.get("content", ""))
            source_ref = item.get("content_hash", item.get("source_url", ""))

            entities = self.extract(text, source_ref=source_ref)

            enriched = dict(item)
            enriched["entities"] = [e.to_dict() for e in entities]
            results.append(enriched)

        total_entities = sum(len(item["entities"]) for item in results)
        logger.info(
            "Entity extraction batch: %d items -> %d total entities",
            len(items),
            total_entities,
        )
        return results

    def _extract_ner(self, text: str, source_ref: str) -> list[ExtractedEntity]:
        """Run spaCy NER and map labels to our entity types."""
        nlp = _get_nlp()
        entities: list[ExtractedEntity] = []

        max_chars = 100_000
        doc = nlp(text[:max_chars])

        label_map = {
            "ORG": "organization",
            "PERSON": "person",
            "GPE": "location",
            "LOC": "location",
        }

        for ent in doc.ents:
            entity_type = label_map.get(ent.label_)
            if entity_type is None:
                continue

            value = ent.text.strip()
            if len(value) < 2 or value.isdigit():
                continue

            start = max(0, ent.start_char - 80)
            end = min(len(text), ent.end_char + 80)
            context = text[start:end].replace("\n", " ").strip()

            entities.append(
                ExtractedEntity(
                    entity_type=entity_type,
                    value=value,
                    raw_match=ent.text,
                    confidence="medium",
                    extraction_method="ner",
                    context=context,
                    source_ref=source_ref,
                    metadata={"spacy_label": ent.label_},
                )
            )

        return entities

    def extract_type(self, text: str, entity_type: str) -> list[str]:
        """Quick extraction of a single entity type. Returns normalized values."""
        for etype, pattern, normalizer in _REGEX_PATTERNS:
            if etype == entity_type:
                values = (normalizer(m.group()) for m in pattern.finditer(text))
                # Apply the same domain filter that extract() uses, so both
                # paths agree on what is and isn't a domain.
                if entity_type == "domain":
                    values = (v for v in values if _is_likely_domain(v))
                return list(dict.fromkeys(values))
        return []
