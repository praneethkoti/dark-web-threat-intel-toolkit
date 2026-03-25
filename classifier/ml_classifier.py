"""
Layer 2 — Traditional ML Threat Classifier.

Pipeline: TF-IDF vectorization -> model training -> prediction.

Supported models:
    - Logistic Regression
    - Random Forest
    - Support Vector Machine (LinearSVC)

Includes:
    - Hyperparameter tuning via GridSearchCV.
    - Model persistence (joblib).
    - Classification report generation (precision, recall, F1).
    - Comparison table across all models.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline as SKPipeline

from config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

# ── Model registry ────────────────────────────────────────────────────────────

_MODEL_CONFIGS: dict[str, dict[str, Any]] = {
    "logistic_regression": {
        "class": LogisticRegression,
        "default_params": {"max_iter": 1000, "random_state": 42, "solver": "lbfgs"},
        "grid": {
            "classifier__C": [0.1, 1.0, 10.0],
        },
    },
    "random_forest": {
        "class": RandomForestClassifier,
        "default_params": {"n_estimators": 100, "random_state": 42},
        "grid": {
            "classifier__n_estimators": [50, 100, 200],
            "classifier__max_depth": [None, 20, 50],
        },
    },
    "svm": {
        "class": LinearSVC,
        "default_params": {"max_iter": 2000, "random_state": 42},
        "grid": {
            "classifier__C": [0.1, 1.0, 10.0],
        },
    },
}


class MLClassifier:
    """
    TF-IDF + traditional ML classifier with GridSearchCV tuning.

    Usage::

        clf = MLClassifier()
        clf.train(texts, labels)
        results = clf.classify("some threat text")
        report = clf.get_comparison_report()
    """

    def __init__(self) -> None:
        self._max_features = settings.get("classifier.ml.max_features", 10000)
        self._test_size = settings.get("classifier.ml.test_size", 0.2)
        self._random_state = settings.get("classifier.ml.random_state", 42)
        self._cv_folds = settings.get("classifier.ml.grid_search_cv", 3)
        self._model_names = settings.get(
            "classifier.ml.models",
            ["logistic_regression", "random_forest", "svm"],
        )
        self._models_dir = PROJECT_ROOT / "data" / "models"
        self._models_dir.mkdir(parents=True, exist_ok=True)

        # Trained pipelines: model_name -> sklearn Pipeline
        self._trained: dict[str, SKPipeline] = {}
        # Evaluation reports: model_name -> classification_report dict
        self._reports: dict[str, dict] = {}
        # Best model name (by accuracy)
        self._best_model: str | None = None

    # ── Training ──────────────────────────────────────────────────────────

    def train(
        self,
        texts: list[str],
        labels: list[str],
        tune: bool = True,
    ) -> dict[str, Any]:
        """
        Train all configured models on the provided data.

        Args:
            texts:  List of text samples.
            labels: Corresponding category labels.
            tune:   If True, run GridSearchCV for hyperparameter tuning.

        Returns:
            Dict with training results per model.
        """
        logger.info(
            "Training ML classifiers: %d samples, %d categories",
            len(texts), len(set(labels)),
        )

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels,
            test_size=self._test_size,
            random_state=self._random_state,
            stratify=labels,
        )

        results: dict[str, Any] = {}
        best_accuracy = 0.0

        for model_name in self._model_names:
            if model_name not in _MODEL_CONFIGS:
                logger.warning("Unknown model: %s — skipping", model_name)
                continue

            config = _MODEL_CONFIGS[model_name]
            logger.info("Training %s...", model_name)

            # Build sklearn pipeline: TF-IDF -> Classifier
            vectorizer = TfidfVectorizer(
                max_features=self._max_features,
                ngram_range=(1, 2),
                sublinear_tf=True,
                strip_accents="unicode",
            )
            classifier = config["class"](**config["default_params"])
            pipeline = SKPipeline([
                ("tfidf", vectorizer),
                ("classifier", classifier),
            ])

            if tune and config.get("grid"):
                logger.info("  Running GridSearchCV (%d folds)...", self._cv_folds)
                grid = GridSearchCV(
                    pipeline,
                    param_grid=config["grid"],
                    cv=self._cv_folds,
                    scoring="f1_weighted",
                    n_jobs=-1,
                    verbose=0,
                )
                grid.fit(X_train, y_train)
                pipeline = grid.best_estimator_
                best_params = grid.best_params_
                logger.info("  Best params: %s", best_params)
            else:
                pipeline.fit(X_train, y_train)
                best_params = config["default_params"]

            # Evaluate
            y_pred = pipeline.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(
                y_test, y_pred, output_dict=True, zero_division=0,
            )

            self._trained[model_name] = pipeline
            self._reports[model_name] = report

            results[model_name] = {
                "accuracy": round(accuracy, 4),
                "best_params": best_params,
                "report": report,
            }

            logger.info(
                "  %s accuracy: %.4f (weighted F1: %.4f)",
                model_name, accuracy,
                report.get("weighted avg", {}).get("f1-score", 0),
            )

            if accuracy > best_accuracy:
                best_accuracy = accuracy
                self._best_model = model_name

        logger.info("Best model: %s (accuracy: %.4f)", self._best_model, best_accuracy)
        return results

    # ── Prediction ────────────────────────────────────────────────────────

    def classify(
        self,
        text: str,
        model_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Classify a single text using a trained model.

        Args:
            text:       Text to classify.
            model_name: Which model to use (default: best model).

        Returns:
            Dict with category, confidence, and model name.
        """
        model_name = model_name or self._best_model
        if not model_name or model_name not in self._trained:
            available = list(self._trained.keys())
            if not available:
                return {
                    "category": "unknown",
                    "confidence": 0.0,
                    "model": "ml_not_trained",
                }
            model_name = available[0]

        pipeline = self._trained[model_name]
        prediction = pipeline.predict([text])[0]

        # Get confidence via decision_function or predict_proba
        try:
            if hasattr(pipeline.named_steps["classifier"], "predict_proba"):
                probs = pipeline.predict_proba([text])[0]
                confidence = float(max(probs))
            elif hasattr(pipeline.named_steps["classifier"], "decision_function"):
                decisions = pipeline.decision_function([text])[0]
                # Convert decision scores to pseudo-probabilities via softmax
                if hasattr(decisions, '__len__'):
                    exp_d = np.exp(decisions - np.max(decisions))
                    probs = exp_d / exp_d.sum()
                    confidence = float(max(probs))
                else:
                    confidence = min(1.0, abs(float(decisions)) / 5.0)
            else:
                confidence = 0.5  # Fallback
        except Exception:
            confidence = 0.5

        return {
            "category": prediction,
            "confidence": round(confidence, 4),
            "model": model_name,
        }

    def classify_batch(
        self,
        texts: list[str],
        model_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Classify a list of texts."""
        return [self.classify(text, model_name) for text in texts]

    # ── Reporting ─────────────────────────────────────────────────────────

    def get_comparison_report(self) -> dict[str, Any]:
        """
        Generate a comparison table across all trained models.

        Returns dict with per-model accuracy, weighted F1, and
        per-category F1 scores.
        """
        if not self._reports:
            return {"error": "No models trained yet"}

        comparison: dict[str, Any] = {}
        for model_name, report in self._reports.items():
            weighted = report.get("weighted avg", {})
            comparison[model_name] = {
                "accuracy": report.get("accuracy", 0),
                "weighted_f1": weighted.get("f1-score", 0),
                "weighted_precision": weighted.get("precision", 0),
                "weighted_recall": weighted.get("recall", 0),
                "per_category": {
                    cat: {
                        "precision": vals.get("precision", 0),
                        "recall": vals.get("recall", 0),
                        "f1": vals.get("f1-score", 0),
                        "support": vals.get("support", 0),
                    }
                    for cat, vals in report.items()
                    if cat not in ("accuracy", "macro avg", "weighted avg")
                },
            }

        comparison["best_model"] = self._best_model
        return comparison

    # ── Persistence ───────────────────────────────────────────────────────

    def save_models(self, prefix: str = "ml") -> list[Path]:
        """Save all trained models to disk using joblib."""
        saved: list[Path] = []
        for name, pipeline in self._trained.items():
            path = self._models_dir / f"{prefix}_{name}.joblib"
            joblib.dump(pipeline, path)
            saved.append(path)
            logger.info("Saved model: %s", path)
        return saved

    def load_model(self, model_name: str, prefix: str = "ml") -> bool:
        """Load a previously trained model from disk."""
        path = self._models_dir / f"{prefix}_{model_name}.joblib"
        if not path.exists():
            logger.warning("Model file not found: %s", path)
            return False
        self._trained[model_name] = joblib.load(path)
        if self._best_model is None:
            self._best_model = model_name
        logger.info("Loaded model: %s", path)
        return True

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def is_trained(self) -> bool:
        return len(self._trained) > 0

    @property
    def available_models(self) -> list[str]:
        return list(self._trained.keys())

    @property
    def best_model_name(self) -> str | None:
        return self._best_model
