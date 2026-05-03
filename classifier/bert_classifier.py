"""
Layer 3 — Transformer-Based Threat Classifiers.

Two classifiers live here and coexist as siblings:

    TransformerClassifier   — zero-shot via facebook/bart-large-mnli.
                              No training required; works out of the box.

    DistilBertClassifier    — fine-tuned DistilBERT sequence classifier.
                              Requires labeled training data and a fine_tune()
                              call (or load_from_checkpoint()) before use.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

# Lazy-loaded pipeline to avoid heavy imports at module load
_pipeline = None


def _get_pipeline() -> Any:
    """Load the zero-shot classification pipeline lazily."""
    global _pipeline
    if _pipeline is None:
        try:
            from transformers import pipeline as hf_pipeline
            model_name = settings.get(
                "classifier.transformer.model_name",
                "facebook/bart-large-mnli",
            )
            device_str = settings.get("classifier.transformer.device", "cpu")
            device = -1 if device_str == "cpu" else 0

            logger.info("Loading zero-shot model: %s (device=%s)", model_name, device_str)
            _pipeline = hf_pipeline(
                "zero-shot-classification",
                model=model_name,
                device=device,
            )
            logger.info("Zero-shot model loaded successfully")
        except ImportError:
            logger.error(
                "transformers library not installed. "
                "Install with: pip install transformers torch"
            )
            raise
        except Exception as exc:
            logger.error("Failed to load zero-shot model: %s", exc)
            raise
    return _pipeline


class TransformerClassifier:
    """
    Zero-shot threat classifier using pre-trained NLI models.

    Usage::

        clf = TransformerClassifier()
        result = clf.classify("Selling 0day exploit for VPN product")
        # {"category": "zero_day", "confidence": 0.82, ...}

        results = clf.classify_batch(["text1", "text2"])
    """

    def __init__(self) -> None:
        self._candidate_labels = settings.get(
            "classifier.transformer.candidate_labels",
            [
                "data breach",
                "exploit or vulnerability",
                "ransomware or malware",
                "carding or financial fraud",
                "threat actor communication",
                "zero-day discussion",
            ],
        )
        self._batch_size = settings.get("classifier.transformer.batch_size", 16)

        # Map human-readable labels back to our internal category names
        self._label_to_category = {
            "data breach": "data_breach",
            "exploit or vulnerability": "exploit_vulnerability",
            "ransomware or malware": "ransomware_malware",
            "carding or financial fraud": "carding_fraud",
            "threat actor communication": "threat_actor_comms",
            "zero-day discussion": "zero_day",
        }

    # ── Public interface ──────────────────────────────────────────────────

    def classify(self, text: str) -> dict[str, Any]:
        """
        Classify a single text using zero-shot inference.

        Returns:
            Dict with category, confidence, all_scores, and model name.
        """
        if not text or not text.strip():
            return self._empty_result()

        try:
            pipe = _get_pipeline()
        except Exception:
            return self._empty_result()

        # Truncate very long texts (transformers have token limits)
        max_chars = 1024
        truncated = text[:max_chars]

        try:
            result = pipe(
                truncated,
                candidate_labels=self._candidate_labels,
                multi_label=False,
            )

            # result = {"labels": [...], "scores": [...], "sequence": "..."}
            top_label = result["labels"][0]
            top_score = result["scores"][0]
            category = self._label_to_category.get(top_label, "unknown")

            all_scores = {
                self._label_to_category.get(label, label): round(score, 4)
                for label, score in zip(result["labels"], result["scores"])
            }

            return {
                "category": category,
                "confidence": round(top_score, 4),
                "scores": all_scores,
                "model": "zero_shot",
            }

        except Exception as exc:
            logger.error("Zero-shot classification failed: %s", exc)
            return self._empty_result()

    def classify_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """
        Classify multiple texts.  Processes in batches for efficiency.
        """
        if not texts:
            return []

        try:
            pipe = _get_pipeline()
        except Exception:
            return [self._empty_result() for _ in texts]

        results: list[dict[str, Any]] = []
        max_chars = 1024

        # Process in batches
        for i in range(0, len(texts), self._batch_size):
            batch = texts[i:i + self._batch_size]
            truncated = [t[:max_chars] for t in batch]

            try:
                batch_results = pipe(
                    truncated,
                    candidate_labels=self._candidate_labels,
                    multi_label=False,
                    batch_size=self._batch_size,
                )

                # pipe returns a single dict for 1 item, list for multiple
                if isinstance(batch_results, dict):
                    batch_results = [batch_results]

                for result in batch_results:
                    top_label = result["labels"][0]
                    top_score = result["scores"][0]
                    category = self._label_to_category.get(top_label, "unknown")

                    all_scores = {
                        self._label_to_category.get(l, l): round(s, 4)
                        for l, s in zip(result["labels"], result["scores"])
                    }

                    results.append({
                        "category": category,
                        "confidence": round(top_score, 4),
                        "scores": all_scores,
                        "model": "zero_shot",
                    })

            except Exception as exc:
                logger.error("Batch classification failed: %s", exc)
                results.extend([self._empty_result() for _ in batch])

        return results

    # ── Helpers ────────────────────────────────────────────────────────────

    def _empty_result(self) -> dict[str, Any]:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "scores": {},
            "model": "zero_shot",
        }

    @property
    def candidate_labels(self) -> list[str]:
        return list(self._candidate_labels)

    @property
    def category_map(self) -> dict[str, str]:
        return dict(self._label_to_category)


# ── Category constants shared between classifiers ──────────────────────────

# Ordered list matches the integer label IDs used by DistilBertClassifier.
# Index 0 = data_breach, 1 = exploit_vulnerability, …, 5 = zero_day.
_FINE_TUNE_CATEGORIES = [
    "data_breach",
    "exploit_vulnerability",
    "ransomware_malware",
    "carding_fraud",
    "threat_actor_comms",
    "zero_day",
]


class DistilBertClassifier:
    """
    Fine-tuned DistilBERT sequence classifier for threat-post categorisation.

    Design note — per-instance model caching:
      self._model / self._tokenizer live on the instance, not at module level.
      This lets two DistilBertClassifier objects hold different checkpoints
      simultaneously (e.g. epoch-3 vs epoch-10), which is useful for
      side-by-side comparison during eval.  Module-level caching would
      silently reuse the first checkpoint loaded.

    Typical usage::

        clf = DistilBertClassifier()
        metrics = clf.fine_tune(training_data, output_dir="data/models/db/")
        result  = clf.classify("Selling 0day exploit for enterprise VPN")

        # Or load a previously saved checkpoint:
        clf2 = DistilBertClassifier()
        clf2.load_from_checkpoint("data/models/db/")
        result2 = clf2.classify("credential dump 50K emails")
    """

    def __init__(self, config: dict | None = None) -> None:
        # Per-instance model/tokenizer storage — see design note above
        self._model = None
        self._tokenizer = None
        self._label2id: dict[str, int] = {c: i for i, c in enumerate(_FINE_TUNE_CATEGORIES)}
        self._id2label: dict[int, str] = {i: c for i, c in enumerate(_FINE_TUNE_CATEGORIES)}

        # Config: explicit dict overrides settings.yaml
        cfg = config or {}
        self._model_name: str = cfg.get(
            "model_name",
            settings.get("classifier.distilbert.model_name", "distilbert-base-uncased"),
        )
        self._max_length: int = cfg.get(
            "max_length",
            settings.get("classifier.distilbert.max_length", 512),
        )
        self._default_epochs: int = cfg.get(
            "epochs",
            settings.get("classifier.distilbert.epochs", 3),
        )
        self._default_batch_size: int = cfg.get(
            "batch_size",
            settings.get("classifier.distilbert.batch_size", 16),
        )
        self._default_lr: float = cfg.get(
            "learning_rate",
            settings.get("classifier.distilbert.learning_rate", 2e-5),
        )
        self._checkpoint_dir: str = cfg.get(
            "checkpoint_dir",
            settings.get(
                "classifier.distilbert.checkpoint_dir",
                "data/models/distilbert_finetuned/",
            ),
        )

    # ── Public interface ───────────────────────────────────────────────────

    def fine_tune(
        self,
        training_data: list[dict],
        output_dir: str | None = None,
        epochs: int | None = None,
        batch_size: int | None = None,
        learning_rate: float | None = None,
    ) -> dict[str, Any]:
        """
        Fine-tune DistilBERT on labeled threat-post data.

        Args:
            training_data: List of {"content": str, "category": str} dicts.
            output_dir:    Where to save the checkpoint (defaults to
                           classifier.distilbert.checkpoint_dir in settings).
            epochs:        Training epochs (default from settings).
            batch_size:    Per-device batch size (default from settings).
            learning_rate: AdamW learning rate (default from settings).

        Returns:
            Metrics dict: {accuracy, f1, epochs, training_samples, output_dir}.
        """
        import torch  # noqa: PLC0415 — lazy import, heavy dep
        from transformers import (  # noqa: PLC0415
            DistilBertForSequenceClassification,
            DistilBertTokenizerFast,
            TrainingArguments,
            Trainer,
        )
        from torch.utils.data import Dataset  # noqa: PLC0415

        if not torch.cuda.is_available():
            print(
                "[DistilBertClassifier] WARNING: CUDA not available — fine-tuning on CPU. "
                "This will be very slow. Set up a GPU or use a small dataset for demos."
            )

        save_dir = output_dir or self._checkpoint_dir
        epochs = epochs if epochs is not None else self._default_epochs
        batch_size = batch_size if batch_size is not None else self._default_batch_size
        lr = learning_rate if learning_rate is not None else self._default_lr

        texts = [item["content"] for item in training_data]
        labels = [self._label2id[item["category"]] for item in training_data]

        tokenizer = DistilBertTokenizerFast.from_pretrained(self._model_name)
        encodings = tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=self._max_length,
            return_tensors="pt",
        )

        class _ThreatDataset(Dataset):
            def __init__(self, enc: Any, labs: list) -> None:
                self.enc = enc
                self.labs = labs

            def __len__(self) -> int:
                return len(self.labs)

            def __getitem__(self, idx: int) -> dict:
                item = {k: v[idx] for k, v in self.enc.items()}
                item["labels"] = torch.tensor(self.labs[idx], dtype=torch.long)
                return item

        dataset = _ThreatDataset(encodings, labels)

        # 80/20 train/eval split
        split = int(0.8 * len(dataset))
        train_ds = torch.utils.data.Subset(dataset, range(split))
        eval_ds = torch.utils.data.Subset(dataset, range(split, len(dataset)))

        model = DistilBertForSequenceClassification.from_pretrained(
            self._model_name,
            num_labels=len(_FINE_TUNE_CATEGORIES),
            id2label=self._id2label,
            label2id=self._label2id,
        )

        training_args = TrainingArguments(
            output_dir=save_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            learning_rate=lr,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            logging_steps=10,
            report_to="none",  # don't push to wandb/hub
        )

        def _compute_metrics(eval_pred: Any) -> dict[str, float]:
            from sklearn.metrics import accuracy_score, f1_score  # noqa: PLC0415
            logits, label_ids = eval_pred
            preds = logits.argmax(axis=-1)
            return {
                "accuracy": float(accuracy_score(label_ids, preds)),
                "f1": float(f1_score(label_ids, preds, average="weighted")),
            }

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=eval_ds,
            compute_metrics=_compute_metrics,
        )

        trainer.train()

        # Evaluate on the held-out split
        eval_results = trainer.evaluate()
        accuracy = eval_results.get("eval_accuracy", 0.0)
        f1 = eval_results.get("eval_f1", 0.0)

        # Persist checkpoint and keep model in memory
        trainer.save_model(save_dir)
        tokenizer.save_pretrained(save_dir)

        self._model = model
        self._tokenizer = tokenizer

        logger.info(
            "DistilBERT fine-tuning complete: accuracy=%.4f f1=%.4f saved=%s",
            accuracy, f1, save_dir,
        )

        return {
            "accuracy": round(accuracy, 4),
            "f1": round(f1, 4),
            "epochs": epochs,
            "training_samples": len(training_data),
            "output_dir": save_dir,
        }

    def load_from_checkpoint(self, path: str) -> None:
        """
        Load a fine-tuned checkpoint from disk.

        The path-existence check intentionally runs BEFORE the lazy torch/
        transformers imports so that a missing path raises FileNotFoundError
        immediately without triggering a heavy import chain.
        """
        # Existence check first — heavy imports come after
        checkpoint_path = Path(path)
        if not checkpoint_path.exists():
            raise FileNotFoundError(
                f"DistilBERT checkpoint not found: {path!r}. "
                "Run fine_tune() first to generate a checkpoint."
            )

        import torch  # noqa: PLC0415
        from transformers import (  # noqa: PLC0415
            DistilBertForSequenceClassification,
            DistilBertTokenizerFast,
        )

        self._tokenizer = DistilBertTokenizerFast.from_pretrained(str(checkpoint_path))
        self._model = DistilBertForSequenceClassification.from_pretrained(
            str(checkpoint_path)
        )
        self._model.eval()

        logger.info("DistilBERT checkpoint loaded from %s", path)

    def classify(self, text: str) -> dict[str, Any]:
        """
        Classify a single text using the fine-tuned model.

        Raises:
            RuntimeError: If called before fine_tune() or load_from_checkpoint().
        """
        if self._model is None or self._tokenizer is None:
            raise RuntimeError(
                "No model loaded. Call fine_tune() or load_from_checkpoint() first."
            )

        if not text or not text.strip():
            return self._empty_result()

        import torch  # noqa: PLC0415

        inputs = self._tokenizer(
            text[:self._max_length * 4],  # rough char cap before tokenisation
            truncation=True,
            padding=True,
            max_length=self._max_length,
            return_tensors="pt",
        )

        with torch.no_grad():
            logits = self._model(**inputs).logits

        probs = torch.softmax(logits, dim=-1)[0].tolist()
        top_id = int(logits.argmax(dim=-1).item())
        category = self._id2label[top_id]
        confidence = round(probs[top_id], 4)

        all_scores = {
            self._id2label[i]: round(p, 4) for i, p in enumerate(probs)
        }

        return {
            "category": category,
            "confidence": confidence,
            "scores": all_scores,
            "model": "distilbert_finetuned",
        }

    def classify_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """
        Classify multiple texts.

        Raises:
            RuntimeError: If called before fine_tune() or load_from_checkpoint().
        """
        if self._model is None or self._tokenizer is None:
            raise RuntimeError(
                "No model loaded. Call fine_tune() or load_from_checkpoint() first."
            )

        if not texts:
            return []

        import torch  # noqa: PLC0415

        results: list[dict[str, Any]] = []
        batch_size = self._default_batch_size

        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            inputs = self._tokenizer(
                batch,
                truncation=True,
                padding=True,
                max_length=self._max_length,
                return_tensors="pt",
            )

            with torch.no_grad():
                logits = self._model(**inputs).logits

            probs_batch = torch.softmax(logits, dim=-1).tolist()
            top_ids = logits.argmax(dim=-1).tolist()

            for top_id, probs in zip(top_ids, probs_batch):
                category = self._id2label[top_id]
                all_scores = {
                    self._id2label[j]: round(p, 4) for j, p in enumerate(probs)
                }
                results.append({
                    "category": category,
                    "confidence": round(probs[top_id], 4),
                    "scores": all_scores,
                    "model": "distilbert_finetuned",
                })

        return results

    # ── Helpers ────────────────────────────────────────────────────────────

    def _empty_result(self) -> dict[str, Any]:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "scores": {},
            "model": "distilbert_finetuned",
        }

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None

    @property
    def categories(self) -> list[str]:
        return list(_FINE_TUNE_CATEGORIES)
