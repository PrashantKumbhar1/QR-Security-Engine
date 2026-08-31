import pytest
from core.explainability_engine import QRExplainabilityEngine


@pytest.fixture
def explain_engine():
    return QRExplainabilityEngine()


def test_generate_explanation_low_risk(explain_engine):
    input_data = {
        "decision": "ALLOW",
        "risk_level": "LOW",
        "scam_category": "Unknown / Suspicious Pattern",
        "reasons": []
    }
    result = explain_engine.generate(input_data)
    assert result["decision"] == "ALLOW"
    assert result["risk_level"] == "LOW"
    assert "safe" in result["summary"].lower()
    assert "safely proceed" in result["recommended_action"].lower()


def test_generate_explanation_high_risk(explain_engine):
    input_data = {
        "decision": "BLOCK",
        "risk_level": "HIGH",
        "scam_category": "Overpayment Scam",
        "reasons": ["High payment amount detected", "Merchant name is missing"]
    }
    result = explain_engine.generate(input_data)
    assert result["decision"] == "BLOCK"
    assert result["risk_level"] == "HIGH"
    assert len(result["why_dangerous"]) == 2
    assert "Do not proceed" in result["recommended_action"]
