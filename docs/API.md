# QR Security Engine — REST API Documentation

**Date**: August 9, 2026  
**Version**: 4.0  
**Framework**: FastAPI  
**OpenAPI Interactive UI**: `/docs` (Swagger UI) or `/redoc` (ReDoc)

---

## 1. Endpoints Overview

| Method | Endpoint | Description | Request Type | Auth Required |
| :--- | :--- | :--- | :--- | :---: |
| `POST` | `/scan` | Analyzes uploaded QR code image and returns fused security assessment. | `multipart/form-data` | No |
| `GET` | `/health` | Service health check status. | None | No |
| `GET` | `/version` | API and engine version metadata. | None | No |

---

## 2. Detailed Endpoint Specifications

### A. `POST /scan` — QR Security Analysis

* **Content-Type**: `multipart/form-data`
* **Form Parameters**:
  * `file` (UploadFile): Required binary image file (`image/png`, `image/jpeg`, `image/webp`, `image/bmp`). Maximum size: **5 MB**.

#### Example `cURL` Request
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/qr_image.png"
```

#### Example `200 OK` Response
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
    "linear_score": 0.0,
    "floor_applied": false,
    "ml_probability": 0.0,
    "heuristic_score": 0
  },
  "indicators": [],
  "explanation": {
    "summary": "This QR code appears safe based on current security checks.",
    "why_dangerous": [],
    "recommended_action": "You may safely proceed with this payment or link."
  },
  "scam_category": "BENIGN"
}
```

---

## 3. Error Responses & Status Codes

All API errors return structured JSON conforming to `ErrorResponseSchema`:

| HTTP Status Code | Error Code | Description / Trigger Condition |
| :---: | :--- | :--- |
| `400 Bad Request` | `QR_DECODE_FAILED` | Uploaded image does not contain a readable QR code. |
| `413 Payload Too Large` | `PAYLOAD_TOO_LARGE` | Uploaded image size exceeds maximum 5 MB limit. |
| `415 Unsupported Media` | `UNSUPPORTED_MEDIA_TYPE` | Uploaded file format is not a supported image (`.png`, `.jpg`, `.webp`, `.bmp`). |

#### Example Error Response (`400 Bad Request`)
```json
{
  "success": false,
  "error": {
    "code": "QR_DECODE_FAILED",
    "message": "No QR code could be decoded from the image.",
    "stage": "decoder"
  }
}
```

---

## 4. Running the API Server

Start the local API development server using `uvicorn`:
```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```
Then visit `http://localhost:8000/docs` in your browser to interact with the OpenAPI UI.
