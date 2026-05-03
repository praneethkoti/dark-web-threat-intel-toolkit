"""
Anthropic / Claude LLM Backend.

Uses the Anthropic Python SDK to call Claude models for threat
intelligence summarization.

Default model: claude-sonnet-4-20250514
Requires ANTHROPIC_API_KEY in .env or environment variables.
"""

from __future__ import annotations

import logging
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


class AnthropicBackend:
    """
    Anthropic API backend for the ThreatSummarizer.

    Configurable via settings.yaml:
        ai_summarizer.anthropic.model
        ai_summarizer.anthropic.temperature
        ai_summarizer.anthropic.max_tokens
    """

    def __init__(self) -> None:
        self._model = settings.get(
            "ai_summarizer.anthropic.model", "claude-sonnet-4-20250514"
        )
        self._default_temp = settings.get("ai_summarizer.anthropic.temperature", 0.3)
        self._default_max_tokens = settings.get("ai_summarizer.anthropic.max_tokens", 1500)
        self._api_key = settings.get("_env.anthropic_api_key", "")
        self._client = None

    def _get_client(self) -> "Anthropic":  # type: ignore[name-defined]
        """Lazy-load the Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. Install with: pip install anthropic"
                )

            if not self._api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not set. Add it to .env or environment variables."
                )

            self._client = Anthropic(api_key=self._api_key)
            logger.info("Anthropic client initialized (model=%s)", self._model)
        return self._client

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """
        Generate a completion using the Anthropic Messages API.

        Args:
            system_prompt: System message for Claude.
            user_prompt:   User message with the actual request.
            temperature:   Sampling temperature (0.0–1.0).
            max_tokens:    Maximum tokens in the response.

        Returns:
            The generated text.
        """
        client = self._get_client()
        temp = temperature if temperature is not None else self._default_temp
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        logger.debug(
            "Anthropic request: model=%s, temp=%.1f, max_tokens=%d",
            self._model, temp, tokens,
        )

        response = client.messages.create(
            model=self._model,
            max_tokens=tokens,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
            temperature=temp,
        )

        # Extract text from response content blocks
        text_parts = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)

        text = "\n".join(text_parts)
        logger.debug(
            "Anthropic response: %d chars, stop_reason=%s",
            len(text), response.stop_reason,
        )
        return text.strip()

    @property
    def name(self) -> str:
        return f"anthropic/{self._model}"
