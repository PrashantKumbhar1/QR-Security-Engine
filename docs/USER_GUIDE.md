# QR Security Engine — User & Operator Guide

**Date**: August 9, 2026  
**Version**: 5.0  

---

## 1. System Requirements

* **Python**: Python 3.10+ (Tested on Python 3.13)
* **OS**: Windows, macOS, or Linux
* **Dependencies**: `fastapi`, `uvicorn`, `scikit-learn`, `pandas`, `opencv-python`, `pyzbar`, `Pillow`, `joblib`, `qrcode`

---

## 2. Quick Start & Server Execution

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Launch Web Application & API Server
```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 3: Access Application
* **Web User Interface**: Open `http://localhost:8000` in any modern web browser.
* **OpenAPI Interactive Documentation**: `http://localhost:8000/docs` or `http://localhost:8000/redoc`.

---

## 3. Web UI Operating Instructions

1. **Option A: Drag & Drop File Upload**
   * Drag any PNG, JPEG, WebP, or BMP image containing a QR code into the dotted dropzone box.
   * Or click "Browse Files" and select your QR image file.
2. **Option B: Device Camera Scanning**
   * Click "Start Camera" to activate your device's webcam.
   * Point the camera at a QR code image and click "Capture & Scan".
3. **Reviewing Security Results**
   * **Fused Risk Score (0–100)**: Animated circular gauge indicating overall security threat.
   * **Risk Level & Decision**: `LOW` (`ALLOW`), `MEDIUM` (`WARN`), `HIGH`/`CRITICAL` (`BLOCK`).
   * **Signal Breakdown**: Inspect separate bars for **ML Probability**, **Heuristic Risk Score**, and **Fused Risk Score**.
   * **Threat Indicators**: Review expandable cards for each detected rule, severity, reason, evidence string, and weight points.
   * **Execution Timeline**: Step-by-step visual trace of the 7-stage security pipeline.
   * **Recommendation**: Executive security guidance advising the user on safe next steps.
