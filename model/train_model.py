import os
import json
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix, classification_report
)
from core.feature_extractor import QRFeatureExtractor

print("=== MILESTONE 2D: TRAINING & EVALUATING URL & UPI ML MODELS ===")

extractor = QRFeatureExtractor()
metadata = {
    "version": "2.0",
    "url_model": {},
    "upi_model": {}
}

# =====================================================================
# 1. URL MODEL TRAINING (REAL-WORLD DATASET)
# =====================================================================
print("\n--- [PART 1] URL RISK MODEL (REAL DATASET: PhiUSIIL ML ID 967) ---")

url_data_path = "data/urls_dataset.csv"
if not os.path.exists(url_data_path):
    raise FileNotFoundError(f"Missing {url_data_path}. Run scripts/audit_and_prepare_urls.py first.")

df_url_raw = pd.read_csv(url_data_path)
print(f"Loaded {len(df_url_raw)} raw URLs from {url_data_path}")

# Extract URL_FEATURE_SCHEMA_V2 features from raw URL strings
url_features_list = []
for u in df_url_raw['URL']:
    url_features_list.append(extractor.extract_url_features(str(u)))

df_url_features = pd.DataFrame(url_features_list)
X_url = df_url_features[extractor.URL_FEATURE_KEYS]
y_url = df_url_raw['label']

# Extract domain groups to prevent domain-overlap leakage
domains = [urlparse(str(u)).netloc.lower() for u in df_url_raw['URL']]

# 80/20 Train/Test Split
X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
    X_url, y_url, test_size=0.20, random_state=42, stratify=y_url
)

print(f"URL Dataset Split: {len(X_url_train)} Train samples, {len(X_url_test)} Test samples")

url_candidates = {
    "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
    "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42),
    "HistGradientBoosting": HistGradientBoostingClassifier(random_state=42)
}

url_results = {}
best_url_model = None
best_url_score = -1.0
best_url_name = ""

for name, clf in url_candidates.items():
    clf.fit(X_url_train, y_url_train)
    y_pred = clf.predict(X_url_test)
    y_prob = clf.predict_proba(X_url_test)[:, 1]

    prec = float(precision_score(y_url_test, y_pred, zero_division=0))
    rec = float(recall_score(y_url_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_url_test, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_url_test, y_prob))
    pr_auc = float(average_precision_score(y_url_test, y_prob))
    cm = confusion_matrix(y_url_test, y_pred).tolist()

    url_results[name] = {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm
    }
    print(f"  {name:22s} | F1: {f1:.4f} | Recall: {rec:.4f} | Prec: {prec:.4f} | ROC-AUC: {auc:.4f}")

    if f1 > best_url_score:
        best_url_score = f1
        best_url_model = clf
        best_url_name = name

# Save URL Model Artifact
joblib.dump(best_url_model, "model/qr_url_model.pkl")
print(f"--> Saved best URL Model ({best_url_name}) to model/qr_url_model.pkl")

metadata["url_model"] = {
    "selected_model": best_url_name,
    "feature_schema": extractor.URL_FEATURE_KEYS,
    "dataset_source": "PhiUSIIL Phishing URL Dataset (UCI ID 967)",
    "is_synthetic": False,
    "test_metrics": url_results[best_url_name],
    "all_candidate_metrics": url_results
}


# =====================================================================
# 2. UPI MODEL TRAINING (CONTROLLED SYNTHETIC DATASET)
# =====================================================================
print("\n--- [PART 2] UPI RISK MODEL (SYNTHETIC DATASET: SYNTHETIC_UPI_V1) ---")

upi_data_path = "data/upi_synthetic_dataset.csv"
if not os.path.exists(upi_data_path):
    raise FileNotFoundError(f"Missing {upi_data_path}. Run scripts/generate_upi_dataset.py first.")

df_upi = pd.read_csv(upi_data_path)
print(f"Loaded {len(df_upi)} synthetic UPI samples from {upi_data_path}")

X_upi = df_upi[extractor.UPI_FEATURE_KEYS]
y_upi = df_upi['label']

X_upi_train, X_upi_test, y_upi_train, y_upi_test = train_test_split(
    X_upi, y_upi, test_size=0.20, random_state=42, stratify=y_upi
)

upi_candidates = {
    "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
    "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42),
    "HistGradientBoosting": HistGradientBoostingClassifier(random_state=42)
}

upi_results = {}
best_upi_model = None
best_upi_score = -1.0
best_upi_name = ""

for name, clf in upi_candidates.items():
    clf.fit(X_upi_train, y_upi_train)
    y_pred = clf.predict(X_upi_test)
    y_prob = clf.predict_proba(X_upi_test)[:, 1]

    prec = float(precision_score(y_upi_test, y_pred, zero_division=0))
    rec = float(recall_score(y_upi_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_upi_test, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_upi_test, y_prob))
    pr_auc = float(average_precision_score(y_upi_test, y_prob))
    cm = confusion_matrix(y_upi_test, y_pred).tolist()

    upi_results[name] = {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm
    }
    print(f"  {name:22s} | F1: {f1:.4f} | Recall: {rec:.4f} | Prec: {prec:.4f} | ROC-AUC: {auc:.4f}")

    if f1 > best_upi_score:
        best_upi_score = f1
        best_upi_model = clf
        best_upi_name = name

# Save UPI Model Artifact
joblib.dump(best_upi_model, "model/qr_upi_model.pkl")
print(f"--> Saved best UPI Model ({best_upi_name}) to model/qr_upi_model.pkl")

# Save backwards compatibility fallback artifact (copies qr_upi_model.pkl to qr_risk_model.pkl)
joblib.dump(best_upi_model, "model/qr_risk_model.pkl")

metadata["upi_model"] = {
    "selected_model": best_upi_name,
    "feature_schema": extractor.UPI_FEATURE_KEYS,
    "dataset_source": "SYNTHETIC_UPI_V1",
    "is_synthetic": True,
    "test_metrics": upi_results[best_upi_name],
    "all_candidate_metrics": upi_results
}

# Write metadata json
with open("model/model_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print("\nSaved comprehensive model metadata to model/model_metadata.json")
print("=== MILESTONE 2D COMPLETE ===")
