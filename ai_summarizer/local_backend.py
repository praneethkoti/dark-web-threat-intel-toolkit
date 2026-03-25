"""
Local Hugging Face LLM Backend.

Runs a summarization model locally without requiring API keys.
Default model: facebook/bart-large-cnn (good for news-style summarization).

Falls back gracefully if transformers/torch are not installed.
"""

from __future__ import annotations

import logging
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

# Lazy-loaded pipeline
_pipeline = None


def _get_pipeline(model_name: str, max_length: int, device: str):
    """Load the summarization pipeline lazily."""
    global _pipeline
    if _pipeline is None:
        try:
            from transformers import pipeline as hf_pipeline
        except ImportError:
            raise ImportError(
                "transformers package not installed. "
                "Install with: pip install transformers torch"
            )

        device_val = -1 if device == "cpu" else 0
        logger.info("Loading local model: %s (device=%s)", model_name, device)
        _pipeline = hf_pipeline(
            "summarization",
            model=model_name,
            device=device_val,
        )
        logger.info("Local model loaded successfully")
    return _pipeline


class LocalBackend:
    """
    Local Hugging Face backend for the ThreatSummarizer.

    Uses a summarization model (e.g. BART, Pegasus) to generate
    summaries without any API calls. Good for:
        - Environments without internet access.
        - Avoiding API costs during development.
        - Privacy-sensitive deployments.

    Note: Local models produce shorter, more extractive summaries
    compared to GPT-4 / Claude. The system_prompt is prepended to
    the user_prompt as context since local summarization models
    don't natively support system messages.

    Configurable via settings.yaml:
        ai_summarizer.local.model_name
        ai_summarizer.local.max_length
        ai_summarizer.local.device
    """

    def __init__(self) -> None:
        self._model_name = settings.get(
            "ai_summarizer.local.model_name", "facebook/bart-large-cnn"
        )
        self._max_length = settings.get("ai_summarizer.local.max_length", 512)
        self._device = settings.get("ai_summarizer.local.device", "cpu")

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        # temperature is ignored by most summarization pipelines
        pipe = _get_pipeline(self._model_name, self._max_length, self._device)
        max_len = max_tokens if max_tokens else self._max_length

        # Combine prompts — summarization models expect a single input
        combined = f"{system_prompt}\n\n{user_prompt}".strip()

        # BART/Pegasus have a token limit (~1024); truncate if needed
        # Rough char-to-token ratio: ~4 chars per token
        max_input_chars = 3500
        if len(combined) > max_input_chars:
            combined = combined[:max_input_chars]
            logger.debug("Input truncated to %d chars for local model", max_input_chars)

        logger.debug(
            "Local model request: input=%d chars, max_length=%d",
            len(combined), max_len,
        )

        try:
            results = pipe(
                combined,
                max_length=max_len,
                min_length=50,
                do_sample=False,
                num_beams=4,
                length_penalty=1.0,
                no_repeat_ngram_size=3,
            )
            text = results[0].get("summary_text", "")
            logger.debug("Local model response: %d chars", len(text))
            return text.strip()
        except Exception as exc:
            logger.error("Local model generation failed: %s", exc)
            raise

    @property
    def name(self) -> str:
        return f"local/{self._model_name}"
