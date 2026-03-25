"""
classifier — Multi-layer threat classification engine.

Layers:
    1. KeywordClassifier  — rule-based weighted keyword scoring
    2. MLClassifier       — TF-IDF + LR/RF/SVM with GridSearchCV
    3. TransformerClassifier — zero-shot via HuggingFace
    4. MitreMapper        — ATT&CK technique enrichment

Plus: synthetic_data_generator for training data creation.
"""

from classifier.keyword_classifier import KeywordClassifier
from classifier.ml_classifier import MLClassifier
from classifier.bert_classifier import TransformerClassifier
from classifier.mitre_mapper import MitreMapper
from classifier.synthetic_data_generator import generate_synthetic_data, CATEGORIES

__all__ = [
    "KeywordClassifier",
    "MLClassifier",
    "TransformerClassifier",
    "MitreMapper",
    "generate_synthetic_data",
    "CATEGORIES",
]
