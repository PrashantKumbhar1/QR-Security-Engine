import os
import json
import re
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix
)
from core.feature_extractor import QRFeatureExtractor

print("=== PHASE 2 VALIDATION GATE AUDIT ===")

extractor = QRFeatureExtractor()

# ---------------------------------------------------------------------
# 1. DATASET PROVENANCE & DUPLICATE ANALYSIS (URL DATASET)
# ---------------------------------------------------------------------
url_file = "data/urls_dataset.csv"
df_url = pd.read_csv(url_file)

print(f"\n--- [1] URL DATASET PROVENANCE ---")
print(f"File: {url_file}")
print(f"Total Rows: {len(df_url)}")
print(f"Class Distribution: {df_url['label'].value_counts().to_dict()}")

# Duplicate Analysis
exact_dups = df_url.duplicated(subset=['URL']).sum()

# Normalized URLs (strip trailing slashes, lowercase, strip http/https)
def normalize_url(u):
    s = str(u).lower().strip()
    s = re.sub(r"^https?://", "", s)
    s = s.rstrip("/")
    return s

df_url['norm_url'] = df_url['URL'].apply(normalize_url)
norm_dups = df_url.duplicated(subset=['norm_url']).sum()

def extract_registered_domain(u):
    netloc = urlparse(str(u).strip()).netloc.lower().split(":")[0]
    parts = [p for p in netloc.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc if netloc else "unknown"

df_url['domain'] = df_url['URL'].apply(extract_registered_domain)
unique_domains_total = df_url['domain'].nunique()

print(f"\n--- [2] DUPLICATE & DOMAIN ANALYSIS ---")
print(f"Exact URL Duplicates: {exact_dups}")
print(f"Normalized URL Duplicates: {norm_dups}")
print(f"Unique Registered Domains: {unique_domains_total}")

# ---------------------------------------------------------------------
# 2. TRAIN/TEST DOMAIN OVERLAP (CURRENT STRATIFIED SPLIT)
# ---------------------------------------------------------------------
# Compute 15 URL features dynamically from raw URL strings
df_url_features = pd.DataFrame([extractor.extract_url_features(str(u)) for u in df_url['URL']])
X_url = df_url_features[extractor.URL_FEATURE_KEYS]
y_url = df_url['label']
domains = df_url['domain']


X_tr, X_te, y_tr, y_te, dom_tr, dom_te = train_test_split(
    X_url, y_url, domains, test_size=0.20, random_state=42, stratify=y_url
)

tr_unique_domains = set(dom_tr)
te_unique_domains = set(dom_te)
overlapping_domains = tr_unique_domains.intersection(te_unique_domains)
pct_test_domains_in_train = (len(overlapping_domains) / len(te_unique_domains)) * 100

print(f"\n--- [3] DOMAIN OVERLAP (STRATIFIED SPLIT) ---")
print(f"Unique Training Domains: {len(tr_unique_domains)}")
print(f"Unique Test Domains:     {len(te_unique_domains)}")
print(f"Overlapping Domains:     {len(overlapping_domains)}")
print(f"Percentage of Test Domains Seen in Training: {pct_test_domains_in_train:.2f}%")

# ---------------------------------------------------------------------
# 3. COMPARE EVALUATION STRATEGIES (STRATIFIED VS DOMAIN-GROUPED SPLIT)
# ---------------------------------------------------------------------
print(f"\n--- [4] EVALUATION STRATEGY COMPARISON ---")

# Strategy A: Current Stratified Split
clf_strat = RandomForestClassifier(n_estimators=100, random_state=42)
clf_strat.fit(X_tr, y_tr)
y_pred_strat = clf_strat.predict(X_te)
y_prob_strat = clf_strat.predict_proba(X_te)[:, 1]

f1_strat = f1_score(y_te, y_pred_strat)
rec_strat = recall_score(y_te, y_pred_strat)
prec_strat = precision_score(y_te, y_pred_strat)
auc_strat = roc_auc_score(y_te, y_prob_strat)
cm_strat = confusion_matrix(y_te, y_pred_strat).tolist()

print(f"Strategy A (Stratified Split):")
print(f"  F1: {f1_strat:.4f} | Recall: {rec_strat:.4f} | Precision: {prec_strat:.4f} | ROC-AUC: {auc_strat:.4f}")
print(f"  Confusion Matrix [TN, FP, FN, TP]: {cm_strat}")

# Strategy B: Domain-Grouped Split (GroupShuffleSplit)
gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(X_url, y_url, groups=domains))

X_tr_grp, X_te_grp = X_url.iloc[train_idx], X_url.iloc[test_idx]
y_tr_grp, y_te_grp = y_url.iloc[train_idx], y_url.iloc[test_idx]
dom_tr_grp = set(domains.iloc[train_idx])
dom_te_grp = set(domains.iloc[test_idx])

grp_overlap = dom_tr_grp.intersection(dom_te_grp)

clf_grp = RandomForestClassifier(n_estimators=100, random_state=42)
clf_grp.fit(X_tr_grp, y_tr_grp)
y_pred_grp = clf_grp.predict(X_te_grp)
y_prob_grp = clf_grp.predict_proba(X_te_grp)[:, 1]

f1_grp = f1_score(y_te_grp, y_pred_grp)
rec_grp = recall_score(y_te_grp, y_pred_grp)
prec_grp = precision_score(y_te_grp, y_pred_grp)
auc_grp = roc_auc_score(y_te_grp, y_prob_grp)
cm_grp = confusion_matrix(y_te_grp, y_pred_grp).tolist()

print(f"\nStrategy B (Domain-Grouped Split):")
print(f"  Domain Overlap: {len(grp_overlap)} domains")
print(f"  F1: {f1_grp:.4f} | Recall: {rec_grp:.4f} | Precision: {prec_grp:.4f} | ROC-AUC: {auc_grp:.4f}")
print(f"  Confusion Matrix [TN, FP, FN, TP]: {cm_grp}")

# ---------------------------------------------------------------------
# 4. SYNTHETIC UPI DATASET SEPARABILITY CHECK
# ---------------------------------------------------------------------
upi_file = "data/upi_synthetic_dataset.csv"
df_upi = pd.read_csv(upi_file)

print(f"\n--- [5] SYNTHETIC UPI DATASET SEPARABILITY CHECK ---")
print(f"UPI File: {upi_file}")
print(f"Total Rows: {len(df_upi)}")

# Check feature correlation/importance with label in synthetic data
for col in extractor.UPI_FEATURE_KEYS:
    corr = df_upi[col].corr(df_upi['label'])
    print(f"  Feature '{col:24s}' correlation with label: {corr:.4f}")

# Check single feature decision rule accuracy on synthetic UPI data
print("\nChecking single-feature perfect predictors in synthetic UPI dataset:")
for col in extractor.UPI_FEATURE_KEYS:
    # If a feature value alone cleanly separates scam vs benign
    vals_benign = df_upi[df_upi['label'] == 1][col].unique()
    vals_scam = df_upi[df_upi['label'] == 0][col].unique()
    overlap = set(vals_benign).intersection(set(vals_scam))
    if len(overlap) == 0:
        print(f"  ⚠️ Warning: Feature '{col}' completely separates benign and scam synthetic samples!")

# ---------------------------------------------------------------------
# 5. MODEL ARTIFACT & SCHEMA VERIFICATION
# ---------------------------------------------------------------------
print(f"\n--- [6] MODEL ARTIFACT VERIFICATION ---")

url_model_path = "model/qr_url_model.pkl"
upi_model_path = "model/qr_upi_model.pkl"
metadata_path = "model/model_metadata.json"

print(f"URL Model File Exists: {os.path.exists(url_model_path)}")
print(f"UPI Model File Exists: {os.path.exists(upi_model_path)}")
print(f"Metadata File Exists:  {os.path.exists(metadata_path)}")

url_model = joblib.load(url_model_path)
upi_model = joblib.load(upi_model_path)

# Predict dummy features
dummy_url_feats = extractor.extract_url_features("https://www.example.com")
df_dummy_url = pd.DataFrame([{k: dummy_url_feats[k] for k in extractor.URL_FEATURE_KEYS}])
pred_url = url_model.predict(df_dummy_url)
print(f"URL Model Predict Output on dummy vector: {pred_url}")

dummy_upi_feats = extractor.extract_upi_features({
    "payee_address": "store@okicici",
    "payee_name": "Store",
    "amount": 100.0,
    "raw_payload": "upi://pay?pa=store@okicici&pn=Store&am=100.00"
})
df_dummy_upi = pd.DataFrame([{k: dummy_upi_feats[k] for k in extractor.UPI_FEATURE_KEYS}])
pred_upi = upi_model.predict(df_dummy_upi)
print(f"UPI Model Predict Output on dummy vector: {pred_upi}")

print("\n=== PHASE 2 VALIDATION AUDIT COMPLETE ===")
