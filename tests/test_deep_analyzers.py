import pytest
from analyzers.url_analyzer import DeepURLAnalyzer
from analyzers.upi_analyzer import DeepUPIAnalyzer
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel
from core.explainability_engine import QRExplainabilityEngine


def test_url_analyzer_normal_and_suspicious():
    analyzer = DeepURLAnalyzer()

    # Normal URL
    clean_inds = analyzer.analyze("https://www.example.com/about")
    assert len(clean_inds) == 0

    # IP URL + HTTP + Shortener + @ symbol
    susp_inds = analyzer.analyze("http://google.com@192.168.1.1/login?ref=bit.ly")
    rule_ids = {ind["rule_id"] for ind in susp_inds}
    assert "URL_NON_SECURE_HTTP" in rule_ids
    assert "URL_USERINFO_SPOOFING" in rule_ids
    assert "URL_IP_HOST" in rule_ids
    assert "URL_SENSITIVE_KEYWORDS" in rule_ids


def test_url_analyzer_punycode_and_tld():
    analyzer = DeepURLAnalyzer()
    inds = analyzer.analyze("http://xn--80ak6aa92e.top/verify-account")
    rule_ids = {ind["rule_id"] for ind in inds}
    assert "URL_PUNYCODE_HOST" in rule_ids
    assert "URL_SUSPICIOUS_TLD" in rule_ids
    assert "URL_SENSITIVE_KEYWORDS" in rule_ids
    assert "URL_NON_SECURE_HTTP" in rule_ids


def test_url_analyzer_hex_encoding_and_double_slash():
    analyzer = DeepURLAnalyzer()
    inds = analyzer.analyze("https://example.com/path//to/%20%21%22file")
    rule_ids = {ind["rule_id"] for ind in inds}
    assert "URL_DOUBLE_SLASH_PATH" in rule_ids
    assert "URL_HEX_ENCODED_PATH" in rule_ids


def test_upi_analyzer_valid_and_suspicious():
    analyzer = DeepUPIAnalyzer()

    # Valid UPI
    clean = {
        "payee_address": "merchant@okicici",
        "payee_name": "Merchant Store",
        "amount": 250.0,
        "raw_params": {"pa": "merchant@okicici", "pn": "Merchant Store", "am": "250.00"}
    }
    assert len(analyzer.analyze(clean)) == 0

    # Embedded URL + Unusually High Amount + Generic Merchant
    suspicious = {
        "payee_address": "claim100@bank",
        "payee_name": "Payment",
        "amount": 15000.0,
        "embedded_urls": ["http://phishing.site/claim"],
        "security_indicators": ["embedded_external_url"],
        "raw_params": {"pa": "claim100@bank", "pn": "Payment", "am": "15000.00", "ref_url": "http://phishing.site"}
    }
    inds = analyzer.analyze(suspicious)
    rule_ids = {ind["rule_id"] for ind in inds}
    assert "UPI_EMBEDDED_EXTERNAL_URL" in rule_ids
    assert "UPI_UNUSUALLY_HIGH_AMOUNT" in rule_ids
    assert "UPI_GENERIC_MERCHANT_NAME" in rule_ids


def test_upi_analyzer_merchant_mismatch_and_missing_name():
    analyzer = DeepUPIAnalyzer()
    missing_name = {
        "payee_address": "store@okicici",
        "payee_name": "",
        "amount": 100.0
    }
    inds = analyzer.analyze(missing_name)
    rule_ids = {ind["rule_id"] for ind in inds}
    assert "UPI_MISSING_MERCHANT_NAME" in rule_ids


def test_risk_engine_score_normalization_and_thresholds():
    engine = QRHeuristicRiskEngine()

    # Low risk URL
    low_res = engine.evaluate_url("https://www.example.com")
    assert low_res.score == 0
    assert low_res.level() == RiskLevel.LOW

    # High / Critical risk URL
    crit_res = engine.evaluate_url("http://google.com@192.168.1.1/login?ref=bit.ly")
    assert crit_res.score >= 75
    assert crit_res.level() == RiskLevel.CRITICAL


def test_explainability_integration_structured_indicators():
    explainer = QRExplainabilityEngine()

    decision_res = {
        "decision": "BLOCK",
        "risk_level": "CRITICAL",
        "heuristic_score": 85,
        "ml_risk_probability": 0.92,
        "indicators": [
            {
                "rule_id": "URL_USERINFO_SPOOFING",
                "severity": "CRITICAL",
                "weight": 40,
                "reason": "URL contains an '@' symbol used for credential spoofing.",
                "evidence": "http://google.com@phishing.site"
            },
            {
                "rule_id": "URL_IP_HOST",
                "severity": "HIGH",
                "weight": 35,
                "reason": "URL uses an IP address instead of a domain name.",
                "evidence": "192.168.1.1"
            }
        ]
    }

    explanation = explainer.generate(decision_res)
    assert explanation["decision"] == "BLOCK"
    assert explanation["risk_level"] == "CRITICAL"
    assert len(explanation["why_dangerous"]) == 2
    assert "[CRITICAL] URL contains an '@' symbol" in explanation["why_dangerous"][0]
    assert "[HIGH] URL uses an IP address" in explanation["why_dangerous"][1]
