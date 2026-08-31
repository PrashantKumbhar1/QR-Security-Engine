# QR Security Engine — System Architecture & Component Design

**Date**: August 9, 2026  
**Version**: 5.0  

---

## 1. End-to-End System Architecture

```text
               FRONTEND WEB UI (HTML5 / Vanilla CSS3 / ES Modules)
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

## 2. Component Directory Structure

```text
QR Security Engine/
├── api/                       # REST API Layer
│   ├── main.py                # FastAPI app initialization, middleware & static mounting
│   ├── dependencies.py        # Dependency injection container
│   ├── routes/
│   │   └── scan.py            # API routes (/scan, /health, /version)
│   └── schemas/
│       └── scan.py            # Pydantic V2 response & error schemas
├── analyzers/                 # Deep Security Analyzers
│   ├── url_analyzer.py        # 11 Deep URL Security Rules
│   └── upi_analyzer.py        # 8 Deep UPI Payment Security Rules
├── config/                    # Configurable Registries
│   ├── security_rules.json    # Centralized 20 Security Rules catalog
│   ├── tld_risk.json          # High-risk & Monitored TLD lists
│   ├── url_shorteners.json    # Known URL shortener domains
│   └── risk_fusion.json       # Hybrid Risk Fusion weights & threshold configuration
├── core/                      # Engine Pipeline Core
│   ├── qr_decoder.py          # PyZbar / OpenCV QR decoding
│   ├── payload_classifier.py  # Regex & structural payload classifier
│   ├── upi_parser.py          # UPI string parser & anomaly extractor
│   ├── feature_extractor.py   # Schema v2.0 deterministic feature extraction
│   ├── risk_engine.py         # Configurable heuristic risk engine
│   ├── ml_risk_scorer.py      # Dual ML model inference manager
│   ├── risk_fusion.py         # Hybrid Linear Fusion + Critical Floor Override engine
│   ├── explainability_engine.py # Structured indicator explainability formatter
│   ├── scam_classifier.py     # Scam category classifier
│   ├── audit_logger.py        # Structured audit trail logger
│   └── decision_engine.py     # Main 7-stage orchestrator
├── data/                      # Cleaned Benchmark Datasets
│   ├── urls_dataset.csv       # 5,000 clean real-world URLs (UCI ML ID 967)
│   └── upi_synthetic_dataset.csv # 1,000 synthetic UPI anomaly samples
├── frontend/                  # Web Application User Interface
│   ├── index.html             # Single-page dashboard template
│   ├── css/style.css          # Cybersecurity dark theme & glassmorphic design
│   └── js/
│       ├── config.js          # API base URL configuration
│       ├── api.js             # Async HTTP client
│       ├── scanner.js         # Dropzone & live camera capture
│       └── ui.js              # DOM controller, SVG risk gauge & timeline
├── model/                     # Trained ML Estimator Artifacts
│   ├── qr_url_model.pkl       # Random Forest URL Classifier (15 features)
│   ├── qr_upi_model.pkl       # Logistic Regression UPI Classifier (13 features)
│   ├── url_feature_schema.json # URL Schema v2.0 contract
│   ├── upi_feature_schema.json # UPI Schema v2.0 contract
│   ├── model_metadata.json    # Evaluation metrics & metadata
│   └── train_model.py         # Reproducible model training script
├── docs/                      # Technical Documentation
└── tests/                     # Automated Test Suite (48 tests)
```
