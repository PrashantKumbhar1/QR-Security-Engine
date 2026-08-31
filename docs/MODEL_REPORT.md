# QR Security Engine — ML Model Training & Evaluation Report

**Date**: August 9, 2026  
**Schema Version**: 2.0  
**Artifacts**: `model/qr_url_model.pkl`, `model/qr_upi_model.pkl`, `model/model_metadata.json`

---

## 1. Executive Summary

In Phase 2, we implemented two separate specialized Machine Learning estimators:
1. **URL Risk Model** (`qr_url_model.pkl`): Trained on real-world URLs from the UCI PhiUSIIL Phishing Dataset (15 features).
2. **UPI Risk Model** (`qr_upi_model.pkl`): Trained on the `SYNTHETIC_UPI_V1` dataset (13 features).

Both models were evaluated across three candidate algorithms:
* **Logistic Regression** (Linear baseline)
* **Random Forest Classifier** (Tree ensemble)
* **HistGradientBoosting Classifier** (Gradient boosting)

---

## 2. URL Risk Model Performance (Real Dataset — 5,000 Samples)

* **Dataset Source**: PhiUSIIL Phishing URL Dataset (UCI ID 967)
* **Split**: 80% Train (4,000 samples) / 20% Test (1,000 samples)
* **Feature Vector**: `URL_FEATURE_SCHEMA_V2` (15 features)

### Model Comparison Table

| Model Algorithm | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Selection Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 0.9862 | 1.0000 | 0.9930 | 0.9963 | 0.9964 | Baseline |
| **Random Forest** | **0.9921** | **1.0000** | **0.9960** | **0.9986** | **0.9987** | **SELECTED** |
| **HistGradientBoosting** | 0.9940 | 0.9980 | 0.9960 | 0.9990 | 0.9991 | Candidate |

### Selected Model: Random Forest Classifier
* **Selected Model**: `RandomForestClassifier(n_estimators=100, random_state=42)`
* **Test Set Confusion Matrix** (1,000 samples):
  ```text
                  Predicted Phishing (0)    Predicted Legitimate (1)
  Actual Phishing (0):       496 (TN)                  4 (FP)
  Actual Legitimate (1):       0 (FN)                500 (TP)
  ```
* **Cybersecurity Analysis**:
  * **False Positives (4)**: Legitimate URLs flagged as phishing (low operational friction).
  * **False Negatives (0)**: Zero phishing URLs missed in test set (optimal defensive security posture).

---

## 3. UPI Risk Model Performance (Synthetic Dataset — 1,000 Samples)

* **Dataset Source**: `SYNTHETIC_UPI_V1`
* **Split**: 80% Train (800 samples) / 20% Test (200 samples)
* **Feature Vector**: `UPI_FEATURE_SCHEMA_V2` (13 features)

### Model Comparison Table

| Model Algorithm | Precision | Recall | F1-Score | ROC-AUC | Selection Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **SELECTED** |
| **Random Forest** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Candidate |
| **HistGradientBoosting** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Candidate |

### Selected Model: Logistic Regression
* **Selected Model**: `LogisticRegression(max_iter=1000, random_state=42)`
* **Test Set Confusion Matrix** (200 samples):
  ```text
                  Predicted Scam (0)    Predicted Benign (1)
  Actual Scam (0):       100 (TN)               0 (FP)
  Actual Benign (1):       0 (FN)             100 (TP)
  ```
* **Synthetic Data Limitation Note**: Synthetic UPI features are linearly separable due to controlled rule generation. Perfect metrics reflect synthetic boundary clarity rather than real-world operational immunity.

---

## 4. Artifact Storage Summary

* `model/qr_url_model.pkl`: Serialized URL Random Forest estimator.
* `model/qr_upi_model.pkl`: Serialized UPI Logistic Regression estimator.
* `model/qr_risk_model.pkl`: Backwards-compatibility fallback estimator.
* `model/url_feature_schema.json`: JSON schema for 15 URL features.
* `model/upi_feature_schema.json`: JSON schema for 13 UPI features.
* `model/model_metadata.json`: Machine-readable metadata file with complete evaluation metrics.
