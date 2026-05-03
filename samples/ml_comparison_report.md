# ML Model Comparison Report

> Generated on synthetic threat-post data (50 samples, balanced, seed=42)
> Models: Logistic Regression, Random Forest, LinearSVC
> Vectorizer: TF-IDF (max_features=10000), no GridSearchCV (tune=False)

## Summary

| Model | Accuracy | Weighted F1 | Weighted Precision | Weighted Recall | Best? |
|-------|----------|-------------|-------------------|-----------------|-------|
| logistic_regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Yes |
| random_forest | 0.8000 | 0.7267 | 0.6833 | 0.8000 |  |
| svm | 1.0000 | 1.0000 | 1.0000 | 1.0000 |  |

**Best model:** `logistic_regression`

## Per-Category Accuracy

### logistic_regression

| Category | Precision | Recall | F1 | Support |
|----------|-----------|--------|----|---------|
| carding_fraud | 1.0000 | 1.0000 | 1.0000 | 2 |
| data_breach | 1.0000 | 1.0000 | 1.0000 | 2 |
| exploit_vulnerability | 1.0000 | 1.0000 | 1.0000 | 2 |
| ransomware_malware | 1.0000 | 1.0000 | 1.0000 | 1 |
| threat_actor_comms | 1.0000 | 1.0000 | 1.0000 | 2 |
| zero_day | 1.0000 | 1.0000 | 1.0000 | 1 |

### random_forest

| Category | Precision | Recall | F1 | Support |
|----------|-----------|--------|----|---------|
| carding_fraud | 1.0000 | 1.0000 | 1.0000 | 2 |
| data_breach | 0.6667 | 1.0000 | 0.8000 | 2 |
| exploit_vulnerability | 0.0000 | 0.0000 | 0.0000 | 2 |
| ransomware_malware | 0.5000 | 1.0000 | 0.6667 | 1 |
| threat_actor_comms | 1.0000 | 1.0000 | 1.0000 | 2 |
| zero_day | 1.0000 | 1.0000 | 1.0000 | 1 |

### svm

| Category | Precision | Recall | F1 | Support |
|----------|-----------|--------|----|---------|
| carding_fraud | 1.0000 | 1.0000 | 1.0000 | 2 |
| data_breach | 1.0000 | 1.0000 | 1.0000 | 2 |
| exploit_vulnerability | 1.0000 | 1.0000 | 1.0000 | 2 |
| ransomware_malware | 1.0000 | 1.0000 | 1.0000 | 1 |
| threat_actor_comms | 1.0000 | 1.0000 | 1.0000 | 2 |
| zero_day | 1.0000 | 1.0000 | 1.0000 | 1 |
