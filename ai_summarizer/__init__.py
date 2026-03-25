"""
ai_summarizer — GenAI-powered threat intelligence summarization.

Supports three backends (swappable via config):
    - OpenAI (GPT-4o / GPT-4o-mini)
    - Anthropic (Claude claude-sonnet-4-20250514)
    - Local (Hugging Face BART / Pegasus)

Usage::

    from ai_summarizer import ThreatSummarizer

    s = ThreatSummarizer("openai")     # or "anthropic" or "local"
    text = s.summarize(mode="executive", time_period="24h", ...)
"""

from ai_summarizer.summarizer import ThreatSummarizer, PromptTemplate, load_prompt_template

__all__ = [
    "ThreatSummarizer",
    "PromptTemplate",
    "load_prompt_template",
]
