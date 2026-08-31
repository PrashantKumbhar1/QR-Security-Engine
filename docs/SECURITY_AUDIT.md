# QR Security Engine — Defensive Security Audit Report

**Date**: August 9, 2026  
**Auditor**: Senior Cybersecurity & ML Systems Engineer  
**Status**: Verified & Hardened  

---

## 1. Audit Scope

This security audit covers the end-to-end QR Security Engine application:
* QR payload decoding (`core/qr_decoder.py`)
* Payload parsing (`core/upi_parser.py`)
* Deep Security Analyzers (`analyzers/url_analyzer.py` & `analyzers/upi_analyzer.py`)
* Machine Learning inference (`core/ml_risk_scorer.py`)
* Hybrid Risk Fusion Engine (`core/risk_fusion.py`)
* FastAPI REST Gateway (`api/main.py` & `api/routes/scan.py`)
* Single-page web dashboard (`frontend/`)

---

## 2. Security Assessment & Control Verification

### A. Input Validation & File Upload Security
* **MIME Type Validation**: The `POST /scan` endpoint inspects `file.content_type` against `{"image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp"}` and validates filename extensions.
* **File Size Limits**: Enforces a strict maximum size limit of **5 MB** (`MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024`), returning `413 Payload Too Large` to prevent Buffer Exhaustion / Denial of Service (DoS) attacks.
* **In-Memory Byte Processing**: Uploaded images are handled as binary streams in memory (`io.BytesIO`). Temporary scratch files are created in `scratch/` and removed immediately in a `finally` block.

### B. QR Payload Handling & URL Crawling Policy
* **Passive Analysis Only**: The engine strictly analyzes decoded QR text strings passively. It **does not** perform HTTP/HTTPS GET/POST requests, follow redirect chains, or execute external web scraping.
* **SSRF Prevention**: Zero outbound network requests are initiated by the server based on QR payload content, eliminating Server-Side Request Forgery (SSRF) risks.

### C. XSS Protection & DOM Insertion (Frontend)
* **Safe DOM Construction**: All decoded QR payloads, evidence strings, and rule descriptions are rendered using standard HTML escaping (`textContent` and `document.createElement()`) in `frontend/js/ui.js`.
* **No `innerHTML` Interpolation**: Untrusted user QR payloads are never assigned directly to `innerHTML`.

### D. Secret Management & Sensitive Data Logging
* **Zero Hardcoded Credentials**: No passwords, API tokens, database URIs, or private keys exist in the repository.
* **Audit Logging**: Runtime audit logging (`core/audit_logger.py`) records analysis metadata (`scan_id`, `risk_level`, `decision`, `final_risk_score`). Unnecessary storage of sensitive financial credentials is minimized.

### E. Exception & Error Handling
* **Structured Error Responses**: All exceptions are captured by FastAPI exception handlers and returned as structured JSON schemas (`ErrorResponseSchema`).
* **Stack Trace Exposure**: Production API endpoints do not expose Python stack traces or internal memory addresses to API clients.

---

## 3. Residual Risks & Security Limitations

1. **Static Passive Analysis**: Multi-hop dynamic URL shortener redirects cannot be followed without outbound HTTP requests (which would re-introduce SSRF risks).
2. **Uncalibrated UPI Synthetic ML Model**: Synthetic UPI dataset metrics ($F1 = 1.0000$) reflect rule separability; real-world UPI anomaly detection requires authoritative bank registry integration.
3. **Local Deployment Scope**: Production deployment behind a reverse proxy (e.g. Nginx with TLS termination and rate limiting) is recommended for public internet deployment.
