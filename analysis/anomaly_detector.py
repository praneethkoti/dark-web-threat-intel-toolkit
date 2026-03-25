"""
Anomaly Detection for Threat Activity.

Flags sudden spikes in activity for any threat category using:
    - **Z-score method**: Flags data points > N standard deviations
      from the rolling mean.
    - **Rolling average deviation**: Flags when a value exceeds M times
      the rolling average.

Operates on daily category counts from the database.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


def _safe_parse_dt(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        dt_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None


class AnomalyDetector:
    """
    Detect anomalous spikes in threat category activity.

    Usage::

        detector = AnomalyDetector(db)
        anomalies = detector.detect()
        # [{"date": "2024-11-14", "category": "ransomware_malware",
        #   "count": 15, "mean": 3.2, "zscore": 3.7, "is_anomaly": True}]
    """

    def __init__(self, db: Any) -> None:
        self._db = db
        method = settings.get("analysis.anomaly_detection.method", "zscore")
        self._method = method
        self._zscore_threshold = settings.get(
            "analysis.anomaly_detection.zscore_threshold", 2.5
        )
        self._rolling_window = settings.get(
            "analysis.anomaly_detection.rolling_window_days", 7
        )

    def detect(self, window_days: int = 90) -> list[dict[str, Any]]:
        """
        Run anomaly detection on classification data.

        Args:
            window_days: How many days of history to analyze.

        Returns:
            List of anomaly dicts, sorted by severity (z-score descending).
        """
        daily_data = self._build_daily_counts(window_days)

        if not daily_data:
            logger.info("No classification data for anomaly detection")
            return []

        if self._method == "zscore":
            anomalies = self._detect_zscore(daily_data)
        else:
            anomalies = self._detect_rolling_avg(daily_data)

        anomalies.sort(key=lambda x: abs(x.get("zscore", x.get("deviation", 0))), reverse=True)
        logger.info(
            "Anomaly detection (%s): %d anomalies found in %d days of data",
            self._method, len(anomalies), window_days,
        )
        return anomalies

    # ── Z-score detection ─────────────────────────────────────────────────

    def _detect_zscore(
        self, daily_data: dict[str, dict[str, int]]
    ) -> list[dict[str, Any]]:
        categories: set[str] = set()
        for day_counts in daily_data.values():
            categories.update(day_counts.keys())

        sorted_dates = sorted(daily_data.keys())
        anomalies: list[dict[str, Any]] = []

        for category in categories:
            # Get time series for this category
            series = [daily_data[d].get(category, 0) for d in sorted_dates]

            if len(series) < 3:
                continue

            mean = sum(series) / len(series)
            variance = sum((x - mean) ** 2 for x in series) / len(series)
            std = math.sqrt(variance) if variance > 0 else 0.0

            if std == 0:
                continue

            for i, date in enumerate(sorted_dates):
                count = series[i]
                zscore = (count - mean) / std

                if zscore > self._zscore_threshold:
                    anomalies.append({
                        "date": date,
                        "category": category,
                        "count": count,
                        "mean": round(mean, 2),
                        "std": round(std, 2),
                        "zscore": round(zscore, 2),
                        "is_anomaly": True,
                        "method": "zscore",
                    })

        return anomalies

    # ── Rolling average detection ─────────────────────────────────────────

    def _detect_rolling_avg(
        self, daily_data: dict[str, dict[str, int]]
    ) -> list[dict[str, Any]]:
        categories: set[str] = set()
        for day_counts in daily_data.values():
            categories.update(day_counts.keys())

        sorted_dates = sorted(daily_data.keys())
        anomalies: list[dict[str, Any]] = []
        window = self._rolling_window

        for category in categories:
            series = [daily_data[d].get(category, 0) for d in sorted_dates]

            for i in range(window, len(series)):
                lookback = series[i - window:i]
                rolling_mean = sum(lookback) / len(lookback) if lookback else 0
                current = series[i]

                if rolling_mean > 0 and current > rolling_mean * 2.5:
                    deviation = current / rolling_mean if rolling_mean else 0
                    anomalies.append({
                        "date": sorted_dates[i],
                        "category": category,
                        "count": current,
                        "rolling_mean": round(rolling_mean, 2),
                        "deviation": round(deviation, 2),
                        "is_anomaly": True,
                        "method": "rolling_avg",
                    })

        return anomalies

    # ── Data preparation ──────────────────────────────────────────────────

    def _build_daily_counts(
        self, window_days: int
    ) -> dict[str, dict[str, int]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        classifications = self._db.get_classifications(limit=10000)

        daily: dict[str, dict[str, int]] = {}

        for cls in classifications:
            dt = _safe_parse_dt(cls.get("classified_at") or cls.get("post_scraped_at"))
            if dt and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt and dt < cutoff:
                continue

            day_key = dt.strftime("%Y-%m-%d") if dt else "unknown"
            category = cls.get("category", "unknown")

            if day_key not in daily:
                daily[day_key] = {}
            daily[day_key][category] = daily[day_key].get(category, 0) + 1

        return daily
