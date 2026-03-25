"""
Tests for the ai_summarizer module.

Run with::

    cd dark-web-threat-intel-toolkit
    python -m pytest tests/test_summarizer.py -v

Note: API-calling tests are gated behind environment variables.
Unit tests use a mock backend for deterministic testing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai_summarizer.summarizer import (
    ThreatSummarizer,
    PromptTemplate,
    load_prompt_template,
)


# ── Mock Backend ──────────────────────────────────────────────────────────────

class MockBackend:
    """Deterministic mock backend for testing without API keys."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 1500,
    ) -> str:
        return (
            f"[MOCK SUMMARY] System prompt length: {len(system_prompt)} chars. "
            f"User prompt length: {len(user_prompt)} chars. "
            f"Temperature: {temperature}. Max tokens: {max_tokens}. "
            "This is a mock threat intelligence summary for testing purposes. "
            "Key findings: ransomware activity increased, 3 critical CVEs identified, "
            "15 new IOCs extracted from dark web sources."
        )

    @property
    def name(self) -> str:
        return "mock"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_summarizer():
    """ThreatSummarizer with a mock backend injected."""
    # Patch the _load_backend method to return our mock
    with patch.object(ThreatSummarizer, "_load_backend", return_value=MockBackend()):
        s = ThreatSummarizer("mock")
    return s


# ── PromptTemplate Tests ──────────────────────────────────────────────────────

class TestPromptTemplate:
    def test_load_executive_summary(self):
        tmpl = load_prompt_template("executive_summary")
        assert tmpl.name == "executive_summary"
        assert tmpl.version == "1.0"
        assert len(tmpl.system_prompt) > 50
        assert len(tmpl.user_prompt_template) > 100
        assert tmpl.temperature > 0

    def test_load_technical_brief(self):
        tmpl = load_prompt_template("technical_brief")
        assert tmpl.name == "technical_brief"
        assert "MITRE" in tmpl.user_prompt_template or "mitre" in tmpl.user_prompt_template.lower()

    def test_load_ioc_bulletin(self):
        tmpl = load_prompt_template("ioc_bulletin")
        assert tmpl.name == "ioc_bulletin"
        assert "IOC" in tmpl.user_prompt_template or "ioc" in tmpl.user_prompt_template.lower()

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_prompt_template("nonexistent_template")

    def test_render_variables(self):
        tmpl = load_prompt_template("executive_summary")
        rendered = tmpl.render(
            time_period="24h",
            total_posts="150",
            category_breakdown="ransomware: 45, data_breach: 30",
            critical_cves="CVE-2024-21887 (9.1)",
            ioc_summary="25 IPs, 15 hashes",
            trends="Ransomware up 40%",
        )
        assert "24h" in rendered
        assert "150" in rendered
        assert "ransomware: 45" in rendered

    def test_render_missing_variables(self):
        """Missing variables should be replaced with N/A, not raise errors."""
        tmpl = load_prompt_template("executive_summary")
        rendered = tmpl.render(time_period="7d")
        assert "N/A" in rendered  # Other vars replaced with N/A
        assert "7d" in rendered

    def test_template_repr(self):
        tmpl = load_prompt_template("executive_summary")
        r = repr(tmpl)
        assert "executive_summary" in r
        assert "1.0" in r

    def test_all_templates_have_required_fields(self):
        """Every template in the directory should have system/user prompts."""
        templates_dir = PROJECT_ROOT / "ai_summarizer" / "prompt_templates"
        for path in templates_dir.glob("*.yaml"):
            tmpl = load_prompt_template(path.stem)
            assert tmpl.system_prompt, f"{path.stem} missing system_prompt"
            assert tmpl.user_prompt_template, f"{path.stem} missing user_prompt_template"
            assert tmpl.temperature > 0, f"{path.stem} has invalid temperature"
            assert tmpl.max_tokens > 0, f"{path.stem} has invalid max_tokens"


# ── ThreatSummarizer Tests (with mock) ───────────────────────────────────────

class TestThreatSummarizer:
    def test_summarize_executive(self, mock_summarizer):
        result = mock_summarizer.summarize(
            mode="executive",
            time_period="24h",
            total_posts="150",
            category_breakdown="ransomware: 45",
            critical_cves="CVE-2024-21887",
            ioc_summary="25 IPs",
            trends="Up 40%",
        )
        assert "[MOCK SUMMARY]" in result
        assert len(result) > 50

    def test_summarize_technical(self, mock_summarizer):
        result = mock_summarizer.summarize(
            mode="technical",
            time_period="7d",
            total_posts="300",
        )
        assert "[MOCK SUMMARY]" in result

    def test_summarize_ioc_bulletin(self, mock_summarizer):
        result = mock_summarizer.summarize(
            mode="ioc_bulletin",
            time_period="48h",
            ioc_data="185.220.101.34, malware.example.com",
        )
        assert "[MOCK SUMMARY]" in result

    def test_invalid_mode_raises(self, mock_summarizer):
        with pytest.raises(ValueError, match="Unknown summary mode"):
            mock_summarizer.summarize(mode="nonexistent")

    def test_backend_name(self, mock_summarizer):
        assert mock_summarizer.backend_name == "mock"

    def test_summarize_posts(self, mock_summarizer):
        posts = [
            {"content": "ransomware found", "category": "ransomware_malware"},
            {"content": "data breach at corp", "category": "data_breach"},
            {"content": "another ransomware", "category": "ransomware_malware"},
        ]
        result = mock_summarizer.summarize_posts(posts, mode="executive", time_period="24h")
        assert "[MOCK SUMMARY]" in result
        assert len(result) > 50


# ── Backend Structure Tests ───────────────────────────────────────────────────

class TestBackendStructure:
    def test_openai_backend_importable(self):
        from ai_summarizer.openai_backend import OpenAIBackend
        backend = OpenAIBackend()
        assert backend.name.startswith("openai/")

    def test_anthropic_backend_importable(self):
        from ai_summarizer.anthropic_backend import AnthropicBackend
        backend = AnthropicBackend()
        assert backend.name.startswith("anthropic/")
        assert "claude" in backend.name

    def test_local_backend_importable(self):
        from ai_summarizer.local_backend import LocalBackend
        backend = LocalBackend()
        assert backend.name.startswith("local/")

    def test_openai_requires_api_key(self):
        from ai_summarizer.openai_backend import OpenAIBackend
        backend = OpenAIBackend()
        backend._api_key = ""
        with pytest.raises((ValueError, ImportError)):
            backend._get_client()

    def test_anthropic_requires_api_key(self):
        from ai_summarizer.anthropic_backend import AnthropicBackend
        backend = AnthropicBackend()
        backend._api_key = ""
        with pytest.raises((ValueError, ImportError)):
            backend._get_client()

    def test_invalid_backend_name_raises(self):
        with patch.object(ThreatSummarizer, "__init__", lambda self, name: None):
            s = ThreatSummarizer.__new__(ThreatSummarizer)
            with pytest.raises(ValueError, match="Unknown backend"):
                s._load_backend("nonexistent_provider")


# ── Live API Tests (gated) ────────────────────────────────────────────────────

class TestLiveAPIs:
    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY"),
        reason="OPENAI_API_KEY not set — skipping live OpenAI test",
    )
    def test_openai_live(self):
        s = ThreatSummarizer("openai")
        result = s.summarize(
            mode="executive",
            time_period="24h",
            total_posts="10",
            category_breakdown="ransomware: 5, data_breach: 3, exploit: 2",
            critical_cves="CVE-2024-21887 (CVSS 9.1)",
            ioc_summary="5 IPs, 3 hashes",
            trends="Ransomware steady",
        )
        assert len(result) > 100
        print(f"\n--- OpenAI Response ({len(result)} chars) ---\n{result[:500]}")

    @pytest.mark.skipif(
        not os.getenv("ANTHROPIC_API_KEY"),
        reason="ANTHROPIC_API_KEY not set — skipping live Anthropic test",
    )
    def test_anthropic_live(self):
        s = ThreatSummarizer("anthropic")
        result = s.summarize(
            mode="executive",
            time_period="24h",
            total_posts="10",
            category_breakdown="ransomware: 5, data_breach: 3, exploit: 2",
            critical_cves="CVE-2024-21887 (CVSS 9.1)",
            ioc_summary="5 IPs, 3 hashes",
            trends="Ransomware steady",
        )
        assert len(result) > 100
        print(f"\n--- Anthropic Response ({len(result)} chars) ---\n{result[:500]}")

    @pytest.mark.skipif(
        not os.getenv("RUN_LOCAL_MODEL_TESTS"),
        reason="Local model tests disabled — set RUN_LOCAL_MODEL_TESTS=1",
    )
    def test_local_backend_live(self):
        s = ThreatSummarizer("local")
        result = s.summarize(
            mode="executive",
            time_period="24h",
            total_posts="10",
            category_breakdown="ransomware: 5, data_breach: 3",
            critical_cves="CVE-2024-21887",
            ioc_summary="5 IPs",
            trends="Steady",
        )
        assert len(result) > 20
        print(f"\n--- Local Model Response ({len(result)} chars) ---\n{result[:500]}")
