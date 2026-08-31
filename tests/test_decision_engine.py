import pytest
from core.decision_engine import QRDecisionEngine, DecisionAction


@pytest.fixture
def engine():
    return QRDecisionEngine()


def test_analyze_legit_url(engine):
    result = engine.analyze_qr("tests/qr_legit_url.png")
    assert result["success"] is True
    assert result["payload_type"] == "URL"
    assert result["decision"] == DecisionAction.ALLOW
    assert result["risk_level"] == "LOW"
    assert result["heuristic_score"] == 0


def test_analyze_legit_upi(engine):
    result = engine.analyze_qr("tests/qr_upi_payment.png")
    assert result["success"] is True
    assert result["payload_type"] == "UPI_PAYMENT"
    assert result["decision"] == DecisionAction.ALLOW
    assert result["risk_level"] == "LOW"


def test_analyze_suspicious_url(engine):
    result = engine.analyze_qr("tests/qr_suspicious_url.png")
    assert result["success"] is True
    assert result["payload_type"] == "URL"
    assert result["decision"] in [DecisionAction.WARN, DecisionAction.BLOCK]
    assert result["heuristic_score"] >= 30


def test_analyze_embedded_url_upi(engine):
    result = engine.analyze_qr("tests/qr_embedded_url_upi.png")
    assert result["success"] is True
    assert result["payload_type"] == "UPI_PAYMENT"
    assert result["decision"] == DecisionAction.BLOCK
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    assert result["heuristic_score"] >= 70



def test_analyze_missing_file_error(engine):
    result = engine.analyze_qr("tests/non_existent_image.png")
    assert result["success"] is False
    assert result["stage"] == "decoder"
    assert result["decision"] == DecisionAction.BLOCK
    assert "file does not exist" in result["error"].lower()
