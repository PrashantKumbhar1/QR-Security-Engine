import pytest
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel


@pytest.fixture
def risk_engine():
    return QRHeuristicRiskEngine()


def test_evaluate_clean_upi(risk_engine):
    upi_data = {
        "payee_address": "officialstore@okicici",
        "payee_name": "Official Store Ltd",
        "amount": 250.0
    }
    result = risk_engine.evaluate_upi(upi_data)
    assert result.score == 0
    assert result.level() == RiskLevel.LOW
    assert len(result.indicators) == 0


def test_evaluate_suspicious_upi(risk_engine):
    upi_data = {
        "payee_address": "fast.pay.user@bank",
        "payee_name": "pay",
        "amount": 10000.0,
        "security_indicators": ["embedded_external_url"]
    }
    result = risk_engine.evaluate_upi(upi_data)
    assert result.score >= 70
    assert result.level() in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert any(ind.get("rule_id", "").lower() == "upi_embedded_external_url" or ind.get("name") == "embedded_external_url" for ind in result.indicators)


def test_evaluate_clean_url(risk_engine):
    result = risk_engine.evaluate_url("https://example.com/checkout")
    assert result.score == 0
    assert result.level() == RiskLevel.LOW


def test_evaluate_suspicious_url(risk_engine):
    result = risk_engine.evaluate_url("http://192.168.1.1/login")
    assert result.score >= 65  # IP + HTTP + Login
    assert result.level() in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

