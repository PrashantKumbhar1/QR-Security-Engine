# QR Security Engine — Dataset Audit & Engineering Report

**Date**: August 9, 2026  
**Status**: Verified & Reproducible

---

## Overview

In Phase 2, we established a strict dataset strategy to maintain academic and technical credibility. We distinguish between **Real-World Public Datasets** and **Controlled Synthetic Datasets**.

---

## 1. Real-World URL Security Dataset

* **Dataset Name**: PhiUSIIL Phishing URL Dataset (UCI ML Repository Dataset ID: 967)
* **Official Source**: `https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website`
* **Repository Mirror**: `https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv`
* **License**: Creative Commons Attribution 4.0 International (CC BY 4.0)

### Audit Statistics (Full Dataset Source)
* **Total Raw Rows Downloaded**: **235,795 rows**
* **Total Raw Columns**: 56 columns (including raw `URL` string column and `label` column)
* **Class Distribution (Raw Source)**:
  * Legitimate (`label = 1`): 134,850 samples (57.2%)
  * Phishing (`label = 0`): 100,945 samples (42.8%)
* **Missing Values**: 0 null URLs, 0 null labels
* **Duplicate URLs Removed**: 425 duplicate URL records

### Processed Local Benchmark Corpus (`data/urls_dataset.csv`)
For fast, deterministic local model training and cross-validation, a balanced 5,000-sample clean evaluation corpus was extracted:
* **Total Samples**: **5,000 samples**
* **Legitimate (`label = 1`)**: 2,500 samples
* **Phishing (`label = 0`)**: 2,500 samples
* **Feature Extraction**: All 15 features of `URL_FEATURE_SCHEMA_V2` were dynamically computed from the raw `URL` column.

---

## 2. Controlled Synthetic UPI Security Dataset

Because public, labeled UPI payment scam datasets containing private VPA financial transactions are not publicly available, we built a controlled synthetic generation pipeline (`scripts/generate_upi_dataset.py`).

* **Dataset Label**: `SYNTHETIC_UPI_V1`
* **Local Storage**: `data/upi_synthetic_dataset.csv`
* **Total Samples**: **1,000 synthetic samples**
  * Benign Merchant/User QRs (`label = 1`): 500 samples
  * Scam / Anomalous QRs (`label = 0`): 500 samples

### Synthetic Generation Assumptions
1. **Benign QRs**: Generated using realistic Indian bank handles (`okicici`, `okhdfcbank`, `oksbi`, `paytm`), realistic payee names (e.g. "Coffee House", "Sharma Grocery"), and normal transaction amounts (`₹10` to `₹1500`).
2. **Scam QRs**: Generated using multi-factor scam patterns:
   * *Overpayment Scams*: High requested amounts (`₹5,000` to `₹25,000`) with urge/collect handles.
   * *Missing Payee Name*: Empty `pn` parameters.
   * *Generic Payee Names*: Generic fraud terms (`payment`, `upi`, `pay`, `merchant`, `cash`).
   * *Embedded Phishing URLs*: Parameters containing external `http://` / `https://` links.
   * *Malformed VPAs*: Excess dots or hyphens in VPA handle.

> **Disclaimer**: Synthetic UPI samples are used strictly for initial model sanity verification and are explicitly marked `is_synthetic: true` in all model metadata.
