import pytest
import os
import json
import pandas as pd
from core.feature_extractor import QRFeatureExtractor
from core.ml_risk_scorer import MLRiskScorer


def test_feature_extractor_schemas():
    extractor = QRFeatureExtractor()

    # Check URL schema (15 features)
    url_feats = extractor.extract_url_features("https://example.com/test?id=1")
    assert len(url_feats) == 15
    assert set(url_feats.keys()) == set(extractor.URL_FEATURE_KEYS)

    # Check UPI schema (13 features)
    upi_data = {
        "payee_address": "store@okicici",
        "payee_name": "Store",
        "amount": 100.0,
        "raw_payload": "upi://pay?pa=store@okicici&pn=Store&am=100.00"
    }
    upi_feats = extractor.extract_upi_features(upi_data)
    assert len(upi_feats) == 13
    assert set(upi_feats.keys()) == set(extractor.UPI_FEATURE_KEYS)


def test_ml_risk_scorer_dual_models():
    scorer = MLRiskScorer()
    assert scorer.is_model_loaded() is True

    extractor = QRFeatureExtractor()

    # Predict URL risk
    url_feats = extractor.extract_url_features("http://bit.ly/suspicious-shortener")
    url_result = scorer.predict_url_risk(url_feats)
    assert url_result["model_used"] == "RandomForest_URL"
    assert url_result["risk_probability"] is not None
    assert url_result["prediction"] in ["safe", "suspicious"]

    # Predict UPI risk
    upi_data = {
        "payee_address": "claim100@bank",
        "payee_name": "Prize Claim",
        "amount": 0.0,
        "embedded_urls": ["http://phishing.site"]
    }
    upi_feats = extractor.extract_upi_features(upi_data)
    upi_result = scorer.predict_upi_risk(upi_feats)
    assert upi_result["model_used"] == "LogisticRegression_UPI"
    assert upi_result["risk_probability"] is not None
    assert upi_result["prediction"] in ["safe", "suspicious"]


def test_model_metadata():
    assert os.path.exists("model/model_metadata.json")
    with open("model/model_metadata.json", "r") as f:
        meta = json.load(f)

    assert "url_model" in meta
    assert "upi_model" in meta
    assert meta["url_model"]["is_synthetic"] is False
    assert meta["upi_model"]["is_synthetic"] is True
