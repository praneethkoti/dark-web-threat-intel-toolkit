"""
Centralized configuration loader.

Reads config/settings.yaml once and merges in any .env overrides.
Every module imports settings from here instead of loading YAML themselves.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# ── Resolve project root (two levels up from this file) ──────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"

# Load .env if present (won't overwrite existing env vars)
_dotenv_path = PROJECT_ROOT / ".env"
if _dotenv_path.exists():
    load_dotenv(_dotenv_path)


def _load_yaml(path: Path) -> dict:
    """Read a YAML file and return its contents as a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (override wins)."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class _Settings:
    """
    Lazy-loaded, singleton-ish settings object.

    Access nested keys via ``get("scraper.default_delay_seconds", fallback)``.
    The raw dict is also available as ``settings.data``.
    """

    def __init__(self) -> None:
        self._data: dict | None = None

    @property
    def data(self) -> dict:
        if self._data is None:
            self._data = self._load()
        return self._data

    # ── Public helpers ────────────────────────────────────────────────────
    def get(self, dotted_key: str, default: Any = None) -> Any:
        """
        Retrieve a value using dot-separated keys.

        Example::

            settings.get("scraper.sources.nvd.base_url")
        """
        keys = dotted_key.split(".")
        node: Any = self.data
        for k in keys:
            if isinstance(node, dict):
                node = node.get(k)
            else:
                return default
            if node is None:
                return default
        return node

    def reload(self) -> None:
        """Force a fresh read from disk (useful in tests)."""
        self._data = self._load()

    # ── Internal ──────────────────────────────────────────────────────────
    def _load(self) -> dict:
        if not SETTINGS_PATH.exists():
            raise FileNotFoundError(f"Settings file not found: {SETTINGS_PATH}")

        data = _load_yaml(SETTINGS_PATH)

        # Apply .env overrides for commonly-changed values
        env_overrides: dict[str, tuple[str, type]] = {
            "LOG_LEVEL": ("project.log_level", str),
            "DATABASE_PATH": ("project.database_path", str),
            "NVD_API_KEY": ("_env.nvd_api_key", str),
            "OTX_API_KEY": ("_env.otx_api_key", str),
            "OPENAI_API_KEY": ("_env.openai_api_key", str),
            "ANTHROPIC_API_KEY": ("_env.anthropic_api_key", str),
            "HTTP_PROXY": ("scraper.proxy.http", str),
            "HTTPS_PROXY": ("scraper.proxy.https", str),
            "SOCKS5_PROXY": ("scraper.proxy.socks5", str),
        }

        # Ensure the _env namespace exists for secret keys
        data.setdefault("_env", {})

        for env_var, (dotted_key, cast) in env_overrides.items():
            value = os.getenv(env_var)
            if value:
                keys = dotted_key.split(".")
                node = data
                for k in keys[:-1]:
                    node = node.setdefault(k, {})
                node[keys[-1]] = cast(value)

        return data


# Module-level singleton — import this everywhere
settings = _Settings()

# ── Logging bootstrap ─────────────────────────────────────────────────────────
def setup_logging(name: str = "toolkit") -> logging.Logger:
    """
    Return a logger configured from settings.

    Call once at entry points (cli.py, scheduler.py).  Modules that just
    need a logger can use ``logging.getLogger(__name__)`` after this runs.
    """
    level_str = settings.get("project.log_level", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    log_file = PROJECT_ROOT / settings.get("project.log_file", "data/toolkit.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(level)

    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    # Avoid duplicate handlers on repeated calls
    if not logger.handlers:
        logger.addHandler(console)
        logger.addHandler(file_handler)

    return logger
