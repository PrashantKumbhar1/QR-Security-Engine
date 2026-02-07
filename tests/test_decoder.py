from core.ml_risk_scorer import MLRiskScorer

scorer = MLRiskScorer()

features = {
    "amount": 6000,
    "merchant_name_missing": 1,
    "merchant_name_length": 0,
    "upi_id_length": 8,
    "generic_merchant_name": 0
}

print(scorer.predict_risk(features))
