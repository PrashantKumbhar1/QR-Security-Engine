# QR Security Engine 🛡️
### AI-Assisted QR Code Threat Detection & Risk Analysis System

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.6%2B-F7931E.svg)](https://scikit-learn.org/)
[![Test Suite](https://img.shields.io/badge/tests-48%20passed-success.svg)](https://pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An end-to-end, multi-stage cybersecurity system that inspects QR code payloads (URLs, UPI payment codes, and plain text) to detect phishing attacks, financial payment fraud, URL obfuscation, homograph spoofing, and brand impersonation.

The engine combines **Deterministic Deep Security Analyzers (20 Configurable Rules)** with **Dual Machine Learning Models (Random Forest URL Classifier & Logistic Regression UPI Classifier)** using a **Hybrid Risk Fusion Engine with Critical Floor Overrides**. Fused security assessments are delivered through a **FastAPI REST Service** and a **Web Application Dashboard**.

---

## 1. Problem Statement & Cybersecurity Context

QR codes are increasingly exploited as attack vectors in **Quishing (QR Phishing)** and **UPI Payment Scams**:
* **Quishing Attacks**: Malicious actors hide phishing URLs behind QR codes, bypassing traditional email/web security filters that only inspect plain text links.
* **UPI Payment Fraud**: Fraudulent payment QRs manipulate parameters (`pa`, `pn`, `am`) to execute overpayment scams, embedded URL redirection, or payee name impersonation.

The **QR Security Engine** provides passive, multi-layer security analysis to evaluate QR payloads *before* user navigation or financial transaction execution.

---

## 2. End-to-End System Architecture

```text
               WEB APPLICATION UI (HTML5 / Vanilla CSS3 / ES Modules)
                                       │
                                       ▼
                       REST API GATEWAY (FastAPI / uvicorn)
                                       │
                                       ▼
                           QR ANALYSIS PIPELINE
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
                 1. DECODE STAGE               2. CLASSIFY STAGE
                   (PyZbar / OpenCV)            (URL vs UPI vs TEXT)
                        │                             │
                        └──────────────┬──────────────┘
                                       │
                                       ▼
                          3. FEATURE EXTRACTION STAGE
                           (Schema V2.0 - 15 URL / 13 UPI)
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
              4A. DEEP ANALYZERS              4B. DUAL ML SCORER
           (20 Rules / TLD / Shortener)    (RandomForest / LogisticReg)
                        │                             │
                        └──────────────┬──────────────┘
                                       │
                                       ▼
                             5. RISK FUSION ENGINE
                   (Hybrid Linear + Critical Floor Override)
                                       │
                                       ▼
                           6. EXPLAINABILITY ENGINE
                      (Structured RiskIndicators & Summary)
                                       │
                                       ▼
                           7. AUDIT LOGGER & TIMELINE
                        (Structured Decision Export)
```

---

## 3. Core Technical Features

1. **Multi-Format QR Decoding**: Extracts payloads using `PyZbar` and `OpenCV` image processing.
2. **Payload Classification**: Identifies `URL`, `UPI_PAYMENT`, `TEXT`, and `UNKNOWN` formats.
3. **Deterministic Feature Extraction (Schema v2.0)**:
   * **URL Schema v2.0**: 15 features (`payload_length`, `digit_ratio`, `special_char_count`, `url_length`, `domain_length`, `path_length`, `query_param_count`, `subdomain_count`, `has_shortener`, `is_https`, `is_ip_url`, `has_at_symbol`, `suspicious_tld`, `hex_encoding_count`, `double_slash_in_path`).
   * **UPI Schema v2.0**: 13 features (`payload_length`, `digit_ratio`, `special_char_count`, `amount`, `amount_missing`, `merchant_name_missing`, `merchant_name_length`, `generic_merchant_name`, `upi_id_length`, `upi_handle_length`, `has_embedded_url`, `non_standard_param_count`, `suspicious_vpa_pattern`).
4. **Deep Security Analyzers (20 Centralized JSON Rules)**:
   * `@` Credential Spoofing, Punycode `xn--` Homograph Attacks, IP Hostnames, Shorteners (`bit.ly`, `tinyurl`), `%XX` Hex Encoding, `//` Path Slashes, High-Risk TLDs (`.top`, `.xyz`, `.zip`).
   * UPI Embedded URLs, Unusually High Amounts (>= ₹10,000), Generic Merchant Names, Missing Payee Names, Payee VPA vs Name Token Mismatches.
5. **Dual Machine Learning Models**:
   * **URL Risk Model (`qr_url_model.pkl`)**: Random Forest Classifier trained on 5,000 real-world benchmark URLs from the UCI PhiUSIIL Phishing Dataset ($F1 = 0.9960$, $ROC\text{-}AUC = 0.9986$). Tested under 0% domain overlap ($F1 = 0.9958$).
   * **UPI Risk Model (`qr_upi_model.pkl`)**: Logistic Regression Model trained on 1,000 synthetic UPI anomaly samples (`SYNTHETIC_UPI_V1`).
6. **Hybrid Risk Fusion Engine**: Fuses ML probability ($P_{\text{ML}}$) and Heuristic score ($S_{\text{heur}}$) with configurable payload weights ($\alpha_{\text{URL}} = 0.60$, $\alpha_{\text{UPI}} = 0.40$) and a `CRITICAL` floor override ($S_{\text{floor}} = 75$).
7. **FastAPI REST API**: Endpoints (`POST /scan`, `GET /health`, `GET /version`) with 5 MB file size enforcement, MIME validation, and OpenAPI UI (`/docs`).
8. **Cybersecurity Web Dashboard**: HTML5, Vanilla CSS3, and ES Modules web interface with Drag & Drop upload, webcam scanner, SVG risk gauge, signal breakdown, threat indicator cards, and execution timeline.

---

## 4. Benchmark Datasets & ML Evaluation Results

### A. Real-World URL Dataset (UCI ML ID 967 — PhiUSIIL Phishing URL Dataset)
* **Source**: UCI Machine Learning Repository (235,795 raw rows, zero exact duplicates).
* **Local Benchmark Corpus**: 5,000 clean rows (2,500 legitimate / 2,500 phishing).
* **Test Performance (1,000 Test Samples)**:
  * **Precision**: `0.9921`
  * **Recall**: `1.0000`
  * **F1-Score**: `0.9960`
  * **ROC-AUC**: `0.9986`
* **Zero Domain-Overlap Generalization Experiment**: Under `GroupShuffleSplit` with **0% domain overlap**, the URL model achieved **$F1 = 0.9958$**, proving strong generalization on unseen domain names.

### B. Controlled Synthetic UPI Dataset (`SYNTHETIC_UPI_V1`)
* **Local Corpus**: 1,000 synthetic samples (500 benign / 500 scam).
* **Test Performance**: $F1 = 1.0000$ (Explicitly documented as synthetic rule separability).

---

## 5. Installation & Setup

### Prerequisites
* Python 3.10+

### Step 1: Clone Repository
```bash
git clone https://github.com/PrashantKumbhar1/QR-Security-Engine.git
cd "QR Security Engine"
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run Automated Test Suite
```bash
pytest -v
```
*(Expected output: 48 passed, 0 failed, 0 warnings)*

### Step 4: Launch Web Dashboard & REST API
```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```
* Access Web Application: `http://localhost:8000`
* Access OpenAPI Documentation: `http://localhost:8000/docs`

---

## 6. REST API Reference

### `POST /scan`
Analyzes an uploaded QR code image file.

* **Request**: `multipart/form-data` with `file` field.
* **Example `cURL`**:
  ```bash
  curl -X POST "http://localhost:8000/scan" \
    -H "Content-Type: multipart/form-data" \
    -F "file=@tests/qr_legit_url.png"
  ```
* **Example Response (`200 OK`)**:
  ```json
  {
    "success": true,
    "scan_id": "qr_scan_9a8f7e2d14b0",
    "timestamp": "2026-08-09T16:15:00+05:30",
    "payload": "https://www.example.com",
    "payload_type": "URL",
    "ml_probability": 0.0,
    "heuristic_score": 0,
    "final_risk_score": 0,
    "risk_level": "LOW",
    "decision": "ALLOW",
    "fusion_metadata": {
      "fusion_method": "hybrid_linear_critical_floor",
      "payload_type": "URL",
      "ml_weight": 0.6,
      "heuristic_weight": 0.4,
      "floor_applied": false
    },
    "indicators": [],
    "explanation": {
      "summary": "This QR code appears safe based on current security checks.",
      "why_dangerous": [],
      "recommended_action": "You may safely proceed with this payment or link."
    }
  }
  ```

---

## 7. Security & Ethical Disclaimer

> **Disclaimer**: This system performs **passive security analysis** on QR code payloads. It does not actively crawl external URLs, execute scripts, or issue financial transactions. Benchmark ML metrics reflect performance on verified evaluation corpora and should not be construed as absolute real-world detection guarantees.

---


