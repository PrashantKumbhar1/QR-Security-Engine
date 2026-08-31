import pytest
import os
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data


def test_version_endpoint():
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "4.0"


def test_frontend_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "QR SECURITY ENGINE" in response.text



def test_scan_endpoint_valid_qr():
    qr_path = "tests/qr_legit_url.png"
    assert os.path.exists(qr_path)

    with open(qr_path, "rb") as f:
        response = client.post(
            "/scan",
            files={"file": ("qr_legit_url.png", f, "image/png")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["payload_type"] == "URL"
    assert "scan_id" in data
    assert "final_risk_score" in data
    assert "fusion_metadata" in data
    assert data["decision"] in ["ALLOW", "WARN", "BLOCK"]


def test_scan_endpoint_invalid_unsupported_media():
    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"not an image", "text/plain")}
    )
    assert response.status_code == 415
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_scan_endpoint_oversized_file():
    # 5.1 MB fake image buffer
    large_buffer = b"0" * (5 * 1024 * 1024 + 100)
    response = client.post(
        "/scan",
        files={"file": ("large.png", large_buffer, "image/png")}
    )
    assert response.status_code == 413
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_scan_endpoint_non_qr_image():
    non_qr_path = "tests/non_qr.png"
    assert os.path.exists(non_qr_path)

    with open(non_qr_path, "rb") as f:
        response = client.post(
            "/scan",
            files={"file": ("non_qr.png", f, "image/png")}
        )

    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "QR_DECODE_FAILED"
