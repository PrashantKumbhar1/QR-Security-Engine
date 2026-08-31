# QR Security Engine — Automated Testing & Verification Report

**Date**: August 9, 2026  
**Version**: 5.0  
**Framework**: `pytest` + `fastapi.testclient.TestClient`

---

## 1. Test Suite Summary

```text
Total Test Files: 10
Total Test Cases: 48
Passed:           48
Failed:            0
Warnings:          0
Execution Time:   5.88 seconds
```

---

## 2. Test Breakdown by Component

| Test Module File | Test Count | Component Coverage | Result |
| :--- | :---: | :--- | :---: |
| [`tests/test_api.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_api.py) | 7 | REST API Endpoints (`/scan`, `/health`, `/version`, `/`, 400/413/415 errors) | PASSED |
| [`tests/test_risk_fusion.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_risk_fusion.py) | 5 | Hybrid Linear Fusion, Critical Floor Overrides, ML fallback | PASSED |
| [`tests/test_deep_analyzers.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_deep_analyzers.py) | 7 | Deep URL rules, Deep UPI rules, Score normalization, Explainability | PASSED |
| [`tests/test_dataset_and_model.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_dataset_and_model.py) | 3 | Feature Schema v2.0 contracts & dual ML models | PASSED |
| [`tests/test_decision_engine.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_decision_engine.py) | 6 | End-to-end decision orchestrator pipeline | PASSED |
| [`tests/test_decoder.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_decoder.py) | 3 | PyZbar / OpenCV QR image decoding | PASSED |
| [`tests/test_classifier.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_classifier.py) | 4 | Payload classification (URL, UPI, TEXT, UNKNOWN) | PASSED |
| [`tests/test_feature_extractor.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_feature_extractor.py) | 2 | URL 15-feature & UPI 13-feature extraction | PASSED |
| [`tests/test_risk_engine.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_risk_engine.py) | 4 | Heuristic risk engine scoring & indicator mapping | PASSED |
| [`tests/test_upi_parser.py`](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests/test_upi_parser.py) | 7 | UPI string parsing & parameter anomaly extraction | PASSED |
