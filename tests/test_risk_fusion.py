import pytest
from core.risk_fusion import QRRiskFusionEngine


def test_fusion_low_ml_low_heuristic():
    engine = QRRiskFusionEngine()
    res = engine.fuse("URL", ml_probability=0.05, heuristic_score=0, indicators=[])
    assert res["final_risk_score"] == 3  # (0.6 * 5) + (0.4 * 0) = 3
    assert res["risk_level"] == "LOW"
    assert res["decision"] == "ALLOW"
    assert res["fusion_metadata"]["floor_applied"] is False


def test_fusion_high_ml_high_heuristic():
    engine = QRRiskFusionEngine()
    res = engine.fuse("URL", ml_probability=0.95, heuristic_score=80, indicators=[])
    # (0.6 * 95) + (0.4 * 80) = 57 + 32 = 89
    assert res["final_risk_score"] == 89
    assert res["risk_level"] == "CRITICAL"
    assert res["decision"] == "BLOCK"


def test_fusion_high_ml_low_heuristic():
    engine = QRRiskFusionEngine()
    res = engine.fuse("URL", ml_probability=0.90, heuristic_score=10, indicators=[])
    # (0.6 * 90) + (0.4 * 10) = 54 + 4 = 58
    assert res["final_risk_score"] == 58
    assert res["risk_level"] == "HIGH"
    assert res["decision"] == "BLOCK"


def test_fusion_critical_floor_override():
    engine = QRRiskFusionEngine()
    critical_indicator = [
        {
            "rule_id": "UPI_EMBEDDED_EXTERNAL_URL",
            "severity": "CRITICAL",
            "weight": 50,
            "reason": "Embedded external URL"
        }
    ]
    # ML probability is low (0.10) and heuristic score is 50, but critical indicator enforces floor of 75
    res = engine.fuse("UPI_PAYMENT", ml_probability=0.10, heuristic_score=50, indicators=critical_indicator)
    assert res["final_risk_score"] >= 75
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert res["decision"] == "BLOCK"
    assert res["fusion_metadata"]["floor_applied"] is True


def test_fusion_no_ml_fallback():
    engine = QRRiskFusionEngine()
    res = engine.fuse("URL", ml_probability=None, heuristic_score=40, indicators=[])
    assert res["final_risk_score"] == 40
    assert res["risk_level"] == "MEDIUM"
    assert res["decision"] == "WARN"
