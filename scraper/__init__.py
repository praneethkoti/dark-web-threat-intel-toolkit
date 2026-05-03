"""
scraper — Data collection engine.

Public API::

    from scraper import (
        PasteScraper, FeedScraper, SimulatedMarketScraper,
        SeleniumScraper, ScrapedItem,
    )
"""

from scraper.base_scraper import BaseScraper, ScrapedItem, UserAgentRotator
from scraper.paste_scraper import PasteScraper
from scraper.feed_scraper import FeedScraper
from scraper.simulated_market_scraper import SimulatedMarketScraper
from scraper.selenium_scraper import SeleniumScraper

__all__ = [
    "BaseScraper",
    "ScrapedItem",
    "UserAgentRotator",
    "PasteScraper",
    "FeedScraper",
    "SimulatedMarketScraper",
    "SeleniumScraper",
]
