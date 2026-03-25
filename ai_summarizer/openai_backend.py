"""
OpenAI LLM Backend.

Uses the OpenAI Python SDK to call GPT-4o / GPT-4o-mini for
threat intelligence summarization.

Requires OPENAI_API_KEY in .env or environment variables.
"""

from __future__ import annotations

import logging
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


class OpenAIBackend:
    """
    OpenAI API backend for the ThreatSummarizer.

    Configurable via settings.yaml:
        ai_summarizer.openai.model
        ai_summarizer.openai.temperature
        ai_summarizer.openai.max_tokens
    """

    def __init__(self) -> None:
        self._model = settings.get("ai_summarizer.openai.model", "gpt-4o-mini")
        self._default_temp = settings.get("ai_summarizer.openai.temperature", 0.3)
        self._default_max_tokens = settings.get("ai_summarizer.openai.max_tokens", 1500)
        self._api_key = settings.get("_env.openai_api_key", "")
        self._client = None

    def _get_client(self):
        """Lazy-load the OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise ImportError(
                    "openai package not installed. Install with: pip install openai"
                )

            if not self._api_key:
                raise ValueError(
                    "OPENAI_API_KEY not set. Add it to .env or environment variables."
                )

            self._client = OpenAI(api_key=self._api_key)
            logger.info("OpenAI client initialized (model=%s)", self._model)
        return self._client

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """
        Generate a completion using the OpenAI Chat API.

        Args:
            system_prompt: System message for the LLM.
            user_prompt:   User message with the actual request.
            temperature:   Sampling temperature (0.0–2.0).
            max_tokens:    Maximum tokens in the response.

        Returns:
            The generated text.
        """
        client = self._get_client()
        temp = temperature if temperature is not None else self._default_temp
        tokens = max_tokens if max_tokens is not None else self._default_max_tokens

        logger.debug("OpenAI request: model=%s, temp=%.1f, max_tokens=%d", self._model, temp, tokens)

        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temp,
            max_tokens=tokens,
        )

        text = response.choices[0].message.content or ""
        logger.debug(
            "OpenAI response: %d chars, finish_reason=%s",
            len(text), response.choices[0].finish_reason,
        )
        return text.strip()

    @property
    def name(self) -> str:
        return f"openai/{self._model}"
