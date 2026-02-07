from core.audit_logger import QRAuditLogger
from core.ml_risk_scorer import MLRiskScorer

class QRDecisionEngine:
    def __init__(self):
        self.decoder = QRDecoder()
        self.classifier = QRPayloadClassifier()
        self.upi_parser = UPIParser()
        self.risk_engine = QRHeuristicRiskEngine()
        self.explain_engine = QRExplainabilityEngine()

class QRDecisionEngine:
    def __init__(self):
        ...
        self.feature_extractor = QRFeatureExtractor()
        self.ml_scorer = MLRiskScorer()
        self.audit_logger = QRAuditLogger()
        self.scam_classifier = QRScamClassifier()


        if self.ml_scorer.is_model_loaded():
            self.ml_xai = MLExplainabilityEngine(
                self.ml_scorer.model,
                feature_names=list(
                    sorted(self.feature_extractor.extract_upi_features({
                        "payee_address": "",
                        "payee_name": "",
                        "amount": 0
                    }).keys())
                )
            )
        else:
            self.ml_xai = None
