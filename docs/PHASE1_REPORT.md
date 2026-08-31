# Phase 1 Stabilization Report — QR Security Engine

**Date**: August 9, 2026  
**Status**: Completed  
**Test Suite**: 26 Passed, 0 Failed, 0 Warnings

---

## 1. Problems Discovered

1. **Broken Package Initialization**: `core/__init__.py` contained duplicate sequential definitions of `QRDecisionEngine`, which overwrote the class and left essential attributes uninitialized.
2. **Disconnected ML Model**: `core/decision_engine.py` initialized `MLRiskScorer` but never invoked `predict_risk()` during pipeline execution.
3. **Inflexible UPI Parser Architecture**: `core/upi_parser.py` raised a fatal `UPIParseError` upon encountering embedded URLs in UPI payloads, halting security analysis instead of extracting the anomaly as a threat signal.
4. **Corrupted Test Image**: `tests/sample_qr.png` contained a stringified pandas Series object (`"316267 http://... Name: url, dtype: object"`) causing payload classification to fail.
5. **Fragile Feature Schema**: `core/ml_risk_scorer.py` sorted dictionary keys implicitly during inference, which could cause mismatched feature order if unexpected keys were present.
6. **Lack of Automated Unit Tests**: No `pytest` configuration or comprehensive test suite existed; manual execution failed due to path resolution errors.
7. **Deprecation Warnings**: Use of `datetime.utcnow()` triggered deprecation warnings in Python 3.13.

---

## 2. Problems Fixed

1. **Fixed Package Structure**: Refactored `core/__init__.py` to provide a single, clean `__all__` package export interface.
2. **Pipeline Integration**: Updated `core/decision_engine.py` to seamlessly execute:
   `Decode -> Classify -> Parse -> Feature Extraction -> Heuristics -> ML Scorer -> Explanation -> Audit Log`
3. **Enhanced UPI Anomaly Detection**: Refactored `core/upi_parser.py` to extract embedded URLs, missing merchant names, non-standard query parameters, and malformed amounts into structured `security_indicators` and `warnings` without crashing.
4. **Standardized Heuristic Risk Engine**: Updated `core/risk_engine.py` to calculate a normalized 0–100 `heuristic_score` and return structured `RiskIndicator` objects.
5. **Explicit ML Feature Schema**: Enforced `MODEL_FEATURES = ["amount", "merchant_name_missing", "merchant_name_length", "upi_id_length", "generic_merchant_name"]` in `core/ml_risk_scorer.py` and passed pandas DataFrames to ensure feature alignment and zero scikit-learn warnings.
6. **Clean Test Fixtures**: Generated 7 clean test QR PNG fixtures (`sample_qr.png`, `qr_legit_url.png`, `qr_upi_payment.png`, `qr_plain_text.png`, `qr_suspicious_url.png`, `qr_ip_url.png`, `qr_embedded_url_upi.png`).
7. **Comprehensive Test Suite & Pytest Config**: Added `pytest.ini` and 26 robust unit and integration tests across 7 test files.
8. **Modern Datetime Handling**: Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`.

---

## 3. Files Modified & Created

| File | Type | Description / Reason |
| :--- | :--- | :--- |
| [core/\_\_init\_\_.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/__init__.py) | Modified | Removed duplicate class definitions; set clean exports |
| [core/payload\_classifier.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/payload_classifier.py) | Modified | Added whitespace/newline normalization & unquoting |
| [core/upi\_parser.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/upi_parser.py) | Modified | Converted structural anomalies into security indicators |
| [core/feature\_extractor.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/feature_extractor.py) | Modified | Enforced deterministic feature keys & default fallbacks |
| [core/risk\_engine.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/risk_engine.py) | Modified | Added structured indicators and normalized 0–100 score |
| [core/ml\_risk\_scorer.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/ml_risk_scorer.py) | Modified | Enforced `MODEL_FEATURES` schema contract and pandas DataFrame input |
| [core/decision\_engine.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/decision_engine.py) | Modified | Integrated ML scorer, feature extraction & structured error format |
| [core/decision\_timeline.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/decision_timeline.py) | Modified | Updated to `datetime.now(timezone.utc)` |
| [core/audit\_logger.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/core/audit_logger.py) | Modified | Updated to `datetime.now(timezone.utc)` |
| [requirements.txt](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/requirements.txt) | Modified | Included pandas, scikit-learn, joblib, numpy, shap, pytest, qrcode, python-dotenv |
| [pytest.ini](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/pytest.ini) | Created | Configured `pythonpath = .` and test discovery rules |
| [tests/\*.png](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests) | Replaced | Generated 7 verified synthetic test QR images |
| [tests/test\_\*.py](file:///c:/Users/kumbh/OneDrive/Desktop/Documents/QR%20Security%20Engine/tests) | Created | Implemented 26 unit & integration tests across 7 test files |

---

## 4. Test Results Summary

```text
Total Tests:  26
Passed:       26
Failed:        0
Warnings:      0
Errors:        0
Execution Time: 4.70 seconds
```

---

## 5. Remaining Known Limitations (For Next Phases)

1. **URL Feature Extraction & Analysis Scope**: Current URL analysis is limited to basic shortener, HTTP scheme, and IP host checks. Advanced lexical analysis (entropy, subdomains, path depth, TLD risk) and reputation checks are not yet implemented.
2. **ML Model Quality**: `model/qr_risk_model.pkl` remains trained on the initial 10-row synthetic UPI sample. Retraining with a robust dataset covering both URL and UPI features is required in Phase 6.
3. **Risk Fusion Engine**: Current decision logic combines heuristics and ML using basic threshold logic. A formal mathematical Risk Fusion model (Bayesian / Sigmoid weighting) should be built in Phase 7.
4. **API & UI Layers**: Backend REST API (FastAPI) and Frontend Dashboard UI have not been created yet (scheduled for Phase 9 & Phase 10).

---

## 6. Next Recommended Phase

**Phase 2 — QR Decoding & Payload Classification Enhancement** (Expanding QR decoder robustness with OpenCV image preprocessing fallbacks and expanding payload classification edge-case handling).
