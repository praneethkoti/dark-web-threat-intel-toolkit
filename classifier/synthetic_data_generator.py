"""
Synthetic Dark Web Post Generator.

Generates 2,000+ realistic synthetic posts for training the threat
classifiers.  Each post has:
    - content (with typos, slang, l33tspeak, multilingual fragments)
    - category label
    - simulated timestamp
    - simulated source

Uses templates + Faker for variety.  Categories can be balanced or
intentionally imbalanced (configurable).
"""

from __future__ import annotations

import json
import logging
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from faker import Faker

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

fake = Faker()
Faker.seed(settings.get("classifier.synthetic_data.seed", 42))
random.seed(settings.get("classifier.synthetic_data.seed", 42))

# ── L33tspeak and slang transforms ───────────────────────────────────────────

_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
_SLANG = [
    "tbh", "imo", "fwiw", "afaik", "ngl", "fr fr", "no cap", "lmk",
    "dm me", "hmu", "iykyk", "lowkey", "highkey",
]
_MULTILINGUAL = [
    "datos filtrados",        # Spanish: leaked data
    "mot de passe",           # French: password
    "Sicherheitslücke",       # German: security vulnerability
    "уязвимость",             # Russian: vulnerability
    "базы данных",            # Russian: databases
    "信用卡",                  # Chinese: credit card
    "ثغرة أمنية",             # Arabic: security vulnerability
    "хакер",                  # Russian: hacker
]


def _leetspeak(text: str, intensity: float = 0.3) -> str:
    """Apply l33tspeak substitutions with given probability per char."""
    chars = list(text)
    for i, c in enumerate(chars):
        if c.lower() in _LEET_MAP and random.random() < intensity:
            chars[i] = _LEET_MAP[c.lower()]
    return "".join(chars)


def _add_typos(text: str, rate: float = 0.02) -> str:
    """Introduce random typos (swap, drop, double) at given rate."""
    chars = list(text)
    result = []
    for c in chars:
        if random.random() < rate and c.isalpha():
            action = random.choice(["swap", "drop", "double"])
            if action == "swap" and len(result) > 0:
                result[-1], c = c, result[-1]
                result.append(c)
            elif action == "drop":
                continue
            elif action == "double":
                result.append(c)
                result.append(c)
            else:
                result.append(c)
        else:
            result.append(c)
    return "".join(result)


def _maybe_inject(text: str) -> str:
    """Randomly inject slang or multilingual fragments."""
    if random.random() < 0.2:
        text += f" {random.choice(_SLANG)}"
    if random.random() < 0.1:
        text = f"{random.choice(_MULTILINGUAL)} — " + text
    if random.random() < 0.15:
        text = _leetspeak(text, intensity=random.uniform(0.1, 0.4))
    if random.random() < 0.2:
        text = _add_typos(text, rate=random.uniform(0.01, 0.04))
    return text


def _fake_ip() -> str:
    return fake.ipv4_public()


def _fake_btc() -> str:
    prefix = random.choice(["1", "3", "bc1q"])
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789"
    length = 34 if prefix in ("1", "3") else 42
    return prefix + "".join(random.choices(chars, k=length - len(prefix)))


def _fake_hash(bits: int = 256) -> str:
    hex_len = bits // 4
    return "".join(random.choices("0123456789abcdef", k=hex_len))


def _fake_cve() -> str:
    year = random.choice([2022, 2023, 2024, 2025])
    num = random.randint(1000, 59999)
    return f"CVE-{year}-{num}"


def _fake_email() -> str:
    return fake.email()


def _fake_domain() -> str:
    return fake.domain_name()


def _fake_timestamp() -> str:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    offset = timedelta(days=random.randint(0, 365), hours=random.randint(0, 23))
    return (base + offset).isoformat()


def _fake_username() -> str:
    patterns = [
        lambda: fake.user_name(),
        lambda: fake.user_name() + str(random.randint(1, 999)),
        lambda: random.choice(["dark", "shadow", "cyber", "ghost", "null", "x"])
            + random.choice(["_", ""]) + fake.user_name()[:6],
    ]
    return random.choice(patterns)()


# ── Templates per category ────────────────────────────────────────────────────

def _gen_data_breach() -> str:
    company = fake.company()
    count = random.choice(["5K", "10K", "50K", "100K", "500K", "1M", "5M"])
    db_type = random.choice(["MySQL", "MongoDB", "PostgreSQL", "MSSQL", "Oracle", "Elasticsearch"])
    formats = [
        f"🔥 FRESH DUMP: {company} database breach — {count} records\n"
        f"Format: email:password\nSample:\n"
        + "\n".join(f"{_fake_email()}:{fake.password()}" for _ in range(random.randint(3, 6)))
        + f"\nFull dump: {_fake_btc()} for payment\nContact: {_fake_email()}",

        f"Leaked {db_type} dump from {company}. {count} users with plaintext passwords.\n"
        f"Includes: name, email, phone, DOB, SSN for US records.\n"
        f"combo list format — email:pass one per line\n"
        f"BTC: {_fake_btc()}\nPrice: ${random.choice([25, 50, 100, 200, 500])}",

        f"Data breach alert — {company}\n"
        f"Source: {random.choice(['insider', 'SQL injection', 'exposed S3 bucket', 'misconfigured API'])}\n"
        f"Records: {count}\nData includes fullz — name, address, SSN, credit card\n"
        f"dehashed and cracked — {random.randint(60, 95)}% plaintext\n"
        f"Sample credentials:\n"
        + "\n".join(f"{_fake_email()}:{fake.password()}" for _ in range(3)),

        f"selling {company} employee credentials\n"
        f"{count} accounts — all tested working\n"
        f"VPN access included for some accounts\n"
        f"email:password format, bulk discount available\n"
        f"wickr: {_fake_username()}\nBTC only: {_fake_btc()}",
    ]
    return _maybe_inject(random.choice(formats))


def _gen_exploit_vuln() -> str:
    cve = _fake_cve()
    product = random.choice([
        "Apache Struts", "Ivanti Connect Secure", "Palo Alto PAN-OS",
        "Citrix NetScaler", "Fortinet FortiOS", "VMware vCenter",
        "Microsoft Exchange", "Confluence Server", "SonicWall SMA",
        "F5 BIG-IP", "Cisco ASA", "Juniper SRX",
    ])
    cvss = round(random.uniform(7.0, 10.0), 1)
    formats = [
        f"PoC for {cve} — {product} RCE\n"
        f"CVSS: {cvss}\nPre-auth remote code execution\n"
        f"Tested on versions {random.randint(8,12)}.x through {random.randint(13,16)}.x\n"
        f"Bypasses current WAF signatures\n"
        f"Python exploit script + Cobalt Strike module\n"
        f"SHA-256 of toolkit: {_fake_hash(256)}\n"
        f"Price: ${random.choice([500, 1000, 2500, 5000])} BTC\n"
        f"Escrow accepted. PGP required.",

        f"Vulnerability analysis: {cve} in {product}\n"
        f"CVSS v3.1: {cvss} (CRITICAL)\n"
        f"Type: {random.choice(['buffer overflow', 'command injection', 'SSRF', 'deserialization', 'path traversal'])}\n"
        f"~{random.randint(1000, 50000)} internet-facing instances on Shodan\n"
        f"Affected IPs (sample):\n"
        + "\n".join(f"  {_fake_ip()}" for _ in range(4))
        + f"\nPatch available but adoption is slow\n"
        f"Active exploitation confirmed by CISA",

        f"looking for working exploit chain for {cve}\n"
        f"{product} vuln — the public PoCs are getting detected\n"
        f"need something that bypasses {random.choice(['Cloudflare', 'Akamai', 'AWS WAF'])}\n"
        f"willing to pay for private PoC — DM me\n"
        f"jabber: {_fake_username()}@jabber.de",

        f"SELLING: private exploit for {product}\n"
        f"{cve} — {random.choice(['pre-auth', 'post-auth'])} RCE\n"
        f"reliable exploitation, no brute force needed\n"
        f"includes weaponized PoC + evasion techniques\n"
        f"price negotiable. proof of concept video available\n"
        f"contact via PGP only. fingerprint: {_fake_hash(160)[:40]}",
    ]
    return _maybe_inject(random.choice(formats))


def _gen_ransomware_malware() -> str:
    family = random.choice([
        "LockCrypt", "BlackMatter", "Hive", "Royal", "Akira",
        "Cl0p", "Play", "Medusa", "NoEscape", "Rhysida",
    ])
    formats = [
        f"{family} Ransomware-as-a-Service — Affiliate Program\n"
        f"Revenue split: {random.choice(['70/30', '80/20', '75/25'])}\n"
        f"Features: AES-256+RSA-4096, Windows+Linux+ESXi support\n"
        f"Admin panel, auto-negotiation, {random.choice(['BTC', 'XMR'])} payment\n"
        f"FUD against top EDR: {random.choice(['CrowdStrike', 'SentinelOne', 'Defender'])}\n"
        f"Deposit: ${random.choice([300, 500, 1000])} (refundable)\n"
        f"Contact: jabber — {_fake_username()}@xmpp.jp",

        f"New {family} variant spotted in the wild\n"
        f"MD5: {_fake_hash(128)}\nSHA-256: {_fake_hash(256)}\n"
        f"Delivery: {random.choice(['phishing email', 'exploit kit', 'compromised RDP', 'supply chain'])}\n"
        f"C2 servers:\n" + "\n".join(f"  {_fake_ip()}" for _ in range(3))
        + f"\nRansom demand: {random.randint(1, 50)} BTC\n"
        f"Contact in ransom note: {_fake_email()}",

        f"selling custom RAT — fully undetected\n"
        f"features: keylogger, screen capture, file exfiltration\n"
        f"reverse shell over {random.choice(['HTTPS', 'DNS', 'ICMP'])}\n"
        f"written in {random.choice(['C++', 'Rust', 'Go'])} — no .NET dependencies\n"
        f"crypter included — FUD against {random.randint(30, 60)}/{random.randint(60, 72)} engines\n"
        f"price: ${random.choice([200, 500, 1000, 2000])}\n"
        f"BTC: {_fake_btc()}",

        f"Malware analysis report: {family} loader\n"
        f"Hashes:\n  MD5: {_fake_hash(128)}\n  SHA-1: {_fake_hash(160)}\n  SHA-256: {_fake_hash(256)}\n"
        f"C2 domains:\n" + "\n".join(f"  {_fake_domain()}" for _ in range(3))
        + f"\nTechniques: T1059 (PowerShell), T1486 (Encryption), T1547 (Persistence)\n"
        f"Targets: {random.choice(['healthcare', 'financial', 'manufacturing', 'education'])} sector",
    ]
    return _maybe_inject(random.choice(formats))


def _gen_carding_fraud() -> str:
    formats = [
        f"Premium fullz — US/EU\n"
        f"Each includes: name, DOB, SSN, CC#, CVV, billing address, phone\n"
        f"BINs: {random.choice(['Chase', 'BoA', 'Wells Fargo', 'Barclays', 'HSBC'])}\n"
        f"Valid rate: {random.randint(75, 95)}%+\n"
        f"Price: ${random.randint(10, 30)} per fullz\n"
        f"Minimum order: {random.choice([5, 10, 25])} fullz\n"
        f"BTC: {_fake_btc()}\nReplacements for dead cards within 24h",

        f"CC dump — Track 1 & Track 2 data\n"
        f"Freshly skimmed from {random.choice(['US gas stations', 'EU ATMs', 'POS terminals'])}\n"
        f"{random.choice(['500', '1000', '2000'])} cards available\n"
        f"Includes PIN for ATM cashout\n"
        f"bulk pricing: {random.choice(['$5', '$8', '$12'])} per card\n"
        f"escrow accepted\nwickr: {_fake_username()}",

        f"bank logs for sale — verified working\n"
        f"banks: {', '.join(random.sample(['Chase', 'BoA', 'Citi', 'Wells Fargo', 'TD Bank', 'PNC'], 3))}\n"
        f"balance range: ${random.randint(5, 50)}K+\n"
        f"includes email access for 2FA bypass\n"
        f"price: {random.randint(5, 15)}% of balance\n"
        f"cashout method: {random.choice(['Zelle', 'wire transfer', 'crypto', 'ACH'])}\n"
        f"money mule network available for extra fee",

        f"selling cloned cards — ready to use\n"
        f"embossed with correct BIN info\n"
        f"chip + mag stripe\n"
        f"tested at {random.choice(['Walmart', 'Target', 'gas stations', 'ATMs'])}\n"
        f"ships worldwide — stealth packaging\n"
        f"${random.randint(50, 200)} per card, bulk discounts\n"
        f"payment: BTC or XMR only\n{_fake_btc()}",
    ]
    return _maybe_inject(random.choice(formats))


def _gen_threat_actor_comms() -> str:
    formats = [
        f"Hiring experienced developers for our team\n"
        f"Requirements:\n- {random.choice(['C/C++', 'Rust', 'Go', 'Python'])} expertise\n"
        f"- {random.choice(['kernel development', 'network protocols', 'cryptography'])} knowledge\n"
        f"- AV/EDR evasion experience\n"
        f"- Strong opsec practices\n"
        f"Payment: XMR monthly\nRevenue share on operations\n"
        f"Contact via Tox: {_fake_hash(256)[:64]}\n"
        f"DO NOT use email or Telegram",

        f"Partnership opportunity — established team\n"
        f"We handle: initial access, persistence\n"
        f"You handle: {random.choice(['data exfiltration', 'ransomware deployment', 'lateral movement'])}\n"
        f"Split: {random.choice(['50/50', '60/40', '70/30'])}\n"
        f"Proven track record — {random.randint(20, 100)}+ successful ops\n"
        f"Escrow for first job. PGP mandatory.\n"
        f"Jabber: {_fake_username()}@jabber.de\n"
        f"warrant canary active",

        f"Looking for pentester with real-world experience\n"
        f"Target sector: {random.choice(['healthcare', 'financial', 'government', 'energy'])}\n"
        f"Must have: {random.choice(['Cobalt Strike', 'Brute Ratel', 'Sliver'])} experience\n"
        f"Active Directory expertise required\n"
        f"Payment in {random.choice(['BTC', 'XMR'])} — competitive rates\n"
        f"Session ID: {_fake_hash(256)[:64]}\n"
        f"PGP fingerprint: {_fake_hash(160)[:40]}",

        f"new forum for vetted members only\n"
        f"topics: offensive security, tool development, opsec\n"
        f"registration requires vouch from 2 existing members\n"
        f"all comms encrypted — PGP mandatory\n"
        f"no {random.choice(['feds', 'journalists', 'researchers'])} allowed\n"
        f"onion address available after vetting\n"
        f"contact: {_fake_username()} on Session or Wickr",
    ]
    return _maybe_inject(random.choice(formats))


def _gen_zero_day() -> str:
    product = random.choice([
        "enterprise VPN", "cloud management platform", "email gateway",
        "firewall appliance", "IoT controller", "SCADA system",
        "mobile MDM solution", "web application server",
    ])
    formats = [
        f"SELLING: Pre-auth RCE 0day — {product}\n"
        f"Affects all current versions — UNPATCHED\n"
        f"No CVE assigned — completely undisclosed\n"
        f"Reliable exploitation — SYSTEM/root shell\n"
        f"Price: ${random.choice([25000, 50000, 75000, 100000, 250000])}\n"
        f"Exclusive rights negotiable\n"
        f"Video PoC for verified buyers\n"
        f"PGP only: {_fake_hash(160)[:40]}",

        f"fresh 0day in {product}\n"
        f"stack-based buffer overflow in {random.choice(['SSL parser', 'authentication handler', 'API endpoint'])}\n"
        f"pre-authentication — no creds needed\n"
        f"tested against latest version as of {fake.date_this_year().isoformat()}\n"
        f"selling to {random.choice(['first buyer only', 'max 3 buyers', 'highest bidder'])}\n"
        f"starting price: {random.randint(10, 100)}K USD in XMR\n"
        f"no patch available — vendor unaware",

        f"zero-day discussion thread\n"
        f"found an interesting bug in {product}\n"
        f"unpatched remote code execution — pre-auth\n"
        f"affects Fortune 500 companies\n"
        f"debating whether to sell or report to vendor\n"
        f"any brokers here? what's the going rate for {product} 0days?\n"
        f"private exploit — not sharing publicly",

        f"BUYING: 0day exploits for {product}\n"
        f"budget: ${random.randint(50, 500)}K depending on impact\n"
        f"must be: pre-auth, reliable, unpatched\n"
        f"proof required before payment\n"
        f"escrow through trusted third party\n"
        f"contact: Tox or Session only\n"
        f"Tox: {_fake_hash(256)[:64]}",
    ]
    return _maybe_inject(random.choice(formats))


# ── Category registry ─────────────────────────────────────────────────────────

CATEGORIES = {
    "data_breach": _gen_data_breach,
    "exploit_vulnerability": _gen_exploit_vuln,
    "ransomware_malware": _gen_ransomware_malware,
    "carding_fraud": _gen_carding_fraud,
    "threat_actor_comms": _gen_threat_actor_comms,
    "zero_day": _gen_zero_day,
}

SOURCES = [
    "simulated_market", "simulated_forum", "paste_site",
    "dark_forum_alpha", "dark_forum_beta", "onion_paste",
]


def generate_synthetic_data(
    num_samples: int | None = None,
    balanced: bool | None = None,
    seed: int | None = None,
    output_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Generate synthetic dark web posts for training classifiers.

    Args:
        num_samples: Total posts to generate (default from config).
        balanced:    If True, equal samples per category. If False,
                     realistic imbalance (more breaches, fewer 0days).
        seed:        Random seed for reproducibility.
        output_path: Path to save JSON output (default from config).

    Returns:
        List of dicts with keys: content, category, timestamp, source,
        username.
    """
    if num_samples is None:
        num_samples = settings.get("classifier.synthetic_data.num_samples", 2500)
    if balanced is None:
        balanced = settings.get("classifier.synthetic_data.balanced", True)
    if seed is not None:
        random.seed(seed)
        Faker.seed(seed)
    if output_path is None:
        output_path = PROJECT_ROOT / settings.get(
            "classifier.synthetic_data.output_path",
            "data/synthetic_training_data.json",
        )

    output_path = Path(output_path)
    categories = list(CATEGORIES.keys())
    data: list[dict[str, Any]] = []

    if balanced:
        per_category = num_samples // len(categories)
        remainder = num_samples % len(categories)
        distribution = {cat: per_category for cat in categories}
        # Distribute remainder across first N categories
        for i, cat in enumerate(categories):
            if i < remainder:
                distribution[cat] += 1
    else:
        # Realistic imbalance — breaches and malware are more common
        weights = {
            "data_breach": 0.25,
            "exploit_vulnerability": 0.20,
            "ransomware_malware": 0.25,
            "carding_fraud": 0.15,
            "threat_actor_comms": 0.10,
            "zero_day": 0.05,
        }
        distribution = {
            cat: max(1, int(num_samples * w)) for cat, w in weights.items()
        }
        # Adjust to hit exact target
        diff = num_samples - sum(distribution.values())
        if diff > 0:
            distribution["data_breach"] += diff
        elif diff < 0:
            distribution["data_breach"] = max(1, distribution["data_breach"] + diff)

    logger.info(
        "Generating %d synthetic samples (balanced=%s): %s",
        num_samples, balanced, distribution,
    )

    for category, count in distribution.items():
        generator = CATEGORIES[category]
        for _ in range(count):
            content = generator()
            data.append({
                "content": content,
                "category": category,
                "timestamp": _fake_timestamp(),
                "source": random.choice(SOURCES),
                "username": _fake_username(),
            })

    # Shuffle to mix categories
    random.shuffle(data)

    # Save to disk
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    logger.info("Generated %d synthetic samples -> %s", len(data), output_path)

    # Log category distribution
    cat_counts = {}
    for item in data:
        cat_counts[item["category"]] = cat_counts.get(item["category"], 0) + 1
    logger.info("Distribution: %s", cat_counts)

    return data
