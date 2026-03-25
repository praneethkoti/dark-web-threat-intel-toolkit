"""
Abstracted LLM Summarizer Interface.

Provides a unified interface for generating threat intelligence
summaries regardless of the backend (OpenAI, Anthropic, local HF).

Prompt templates are loaded from YAML files in prompt_templates/ and
support variable interpolation for dynamic content.

Supports three summary modes:
    - executive  — non-technical, leadership-facing
    - technical  — detailed, SOC/IR-facing with MITRE references
    - ioc_bulletin — actionable indicator bulletin
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol

import yaml

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)


# ── Backend Protocol ──────────────────────────────────────────────────────────

class LLMBackend(Protocol):
    """Interface that all LLM backends must satisfy."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 1500,
    ) -> str:
        """Generate a completion from the LLM. Returns the response text."""
        ...

    @property
    def name(self) -> str:
        """Human-readable backend name."""
        ...


# ── Prompt Template Loader ────────────────────────────────────────────────────

class PromptTemplate:
    """
    A loaded prompt template with variable interpolation.

    Templates are YAML files with keys: name, version, description,
    system_prompt, user_prompt_template, parameters.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self.name = data.get("name", "unnamed")
        self.version = data.get("version", "1.0")
        self.description = data.get("description", "")
        self.system_prompt = data.get("system_prompt", "")
        self.user_prompt_template = data.get("user_prompt_template", "")
        self.temperature = data.get("parameters", {}).get("temperature", 0.3)
        self.max_tokens = data.get("parameters", {}).get("max_tokens", 1500)

    def render(self, **kwargs: Any) -> str:
        """
        Render the user prompt template with provided variables.

        Missing variables are replaced with 'N/A' to avoid KeyError.
        """
        template = self.user_prompt_template
        for key, value in kwargs.items():
            template = template.replace(f"{{{key}}}", str(value))
        # Replace any remaining unset placeholders
        import re
        template = re.sub(r"\{[a-z_]+\}", "N/A", template)
        return template

    def __repr__(self) -> str:
        return f"PromptTemplate(name={self.name!r}, version={self.version!r})"


def load_prompt_template(name: str) -> PromptTemplate:
    """
    Load a prompt template by name from the templates directory.

    Args:
        name: Template name without extension (e.g. 'executive_summary').

    Returns:
        A PromptTemplate instance.
    """
    templates_dir = PROJECT_ROOT / settings.get(
        "ai_summarizer.prompt_templates_dir",
        "ai_summarizer/prompt_templates",
    )
    path = templates_dir / f"{name}.yaml"

    if not path.exists():
        raise FileNotFoundError(f"Prompt template not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    logger.debug("Loaded prompt template: %s (v%s)", data.get("name"), data.get("version"))
    return PromptTemplate(data)


# ── Main Summarizer ───────────────────────────────────────────────────────────

class ThreatSummarizer:
    """
    Generate threat intelligence summaries using configurable LLM backends.

    Usage::

        summarizer = ThreatSummarizer()          # Uses default backend from config
        summarizer = ThreatSummarizer("openai")   # Force specific backend
        summarizer = ThreatSummarizer("anthropic")
        summarizer = ThreatSummarizer("local")

        # Generate an executive summary
        text = summarizer.summarize(
            mode="executive",
            time_period="24h",
            total_posts=150,
            category_breakdown="ransomware: 45, data_breach: 30, ...",
            critical_cves="CVE-2024-21887 (9.1), CVE-2024-3400 (10.0)",
            ioc_summary="25 IPs, 15 hashes, 8 domains",
            trends="Ransomware activity increased 40% this week",
        )
    """

    def __init__(self, backend_name: str | None = None) -> None:
        if backend_name is None:
            backend_name = settings.get("ai_summarizer.default_backend", "openai")

        self._backend = self._load_backend(backend_name)
        self._templates: dict[str, PromptTemplate] = {}
        logger.info("ThreatSummarizer initialized with backend: %s", self._backend.name)

    def summarize(self, mode: str = "executive", **kwargs: Any) -> str:
        """
        Generate a summary using the specified mode.

        Args:
            mode: One of 'executive', 'technical', 'ioc_bulletin'.
            **kwargs: Variables to interpolate into the prompt template.

        Returns:
            The generated summary text.
        """
        template_map = {
            "executive": "executive_summary",
            "technical": "technical_brief",
            "ioc_bulletin": "ioc_bulletin",
        }

        template_name = template_map.get(mode)
        if not template_name:
            raise ValueError(f"Unknown summary mode: {mode}. Valid: {list(template_map.keys())}")

        template = self._get_template(template_name)
        user_prompt = template.render(**kwargs)

        logger.info("Generating %s summary (template=%s, backend=%s)", mode, template_name, self._backend.name)

        try:
            response = self._backend.generate(
                system_prompt=template.system_prompt,
                user_prompt=user_prompt,
                temperature=template.temperature,
                max_tokens=template.max_tokens,
            )
            logger.info("Summary generated: %d chars", len(response))
            return response
        except Exception as exc:
            logger.error("Summary generation failed: %s", exc)
            raise

    def summarize_posts(
        self,
        posts: list[dict[str, Any]],
        mode: str = "executive",
        time_period: str = "24h",
    ) -> str:
        """
        Summarize a list of classified posts.

        Automatically builds the template variables from post data.
        """
        # Build category breakdown
        categories: dict[str, int] = {}
        cves: list[str] = []
        ioc_types: dict[str, int] = {}

        for post in posts:
            cat = post.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1

        cat_str = ", ".join(f"{k}: {v}" for k, v in sorted(categories.items(), key=lambda x: x[1], reverse=True))

        # Templates have more variables than posts alone can fill;
        # caller can use summarize() directly with full context if needed
        return self.summarize(
            mode=mode,
            time_period=time_period,
            total_posts=len(posts),
            category_breakdown=cat_str or "N/A",
            critical_cves="N/A",
            ioc_summary="N/A",
            trends="N/A",
            cve_details="N/A",
            mitre_techniques="N/A",
            ioc_details="N/A",
            anomalies="N/A",
            ioc_data="N/A",
            categories=cat_str or "N/A",
        )

    # ── Backend loading ───────────────────────────────────────────────────

    def _load_backend(self, name: str) -> LLMBackend:
        if name == "openai":
            from ai_summarizer.openai_backend import OpenAIBackend
            return OpenAIBackend()
        elif name == "anthropic":
            from ai_summarizer.anthropic_backend import AnthropicBackend
            return AnthropicBackend()
        elif name == "local":
            from ai_summarizer.local_backend import LocalBackend
            return LocalBackend()
        else:
            raise ValueError(f"Unknown backend: {name}. Valid: openai, anthropic, local")

    def _get_template(self, name: str) -> PromptTemplate:
        if name not in self._templates:
            self._templates[name] = load_prompt_template(name)
        return self._templates[name]

    @property
    def backend_name(self) -> str:
        return self._backend.name
