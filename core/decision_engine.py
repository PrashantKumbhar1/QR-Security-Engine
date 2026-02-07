from core.qr_decoder import QRDecoder, QRDecodeError
from core.payload_classifier import QRPayloadClassifier, PayloadType
from core.upi_parser import UPIParser, UPIParseError
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel
from core.explainability_engine import QRExplainabilityEngine
from core.feature_extractor import QRFeatureExtractor
from core.ml_risk_scorer import MLRiskScorer
from core.ml_xai import MLExplainabilityEngine
from core.audit_logger import QRAuditLogger
from core.scam_classifier import QRScamClassifier


class DecisionAction:
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class QRDecisionEngine:
    def __init__(self):
        self.decoder = QRDecoder()
        self.classifier = QRPayloadClassifier()
        self.upi_parser = UPIParser()
        self.risk_engine = QRHeuristicRiskEngine()
        self.explain_engine = QRExplainabilityEngine()

        # ML components
        self.feature_extractor = QRFeatureExtractor()
        self.ml_scorer = MLRiskScorer()
        self.audit_logger = QRAuditLogger()
        self.scam_classifier = QRScamClassifier()


        # SHAP XAI (only if model exists)
        if self.ml_scorer.is_model_loaded():
            sample_features = self.feature_extractor.extract_upi_features({
                "payee_address": "",
                "payee_name": "",
                "amount": 0
            })
            self.ml_xai = MLExplainabilityEngine(
                self.ml_scorer.model,
                feature_names=list(sample_features.keys())
            )
        else:
            self.ml_xai = None

    def analyze_qr(self, image_path: str) -> dict:
        try:
            payload = self.decoder.decode_qr(image_path)
        except QRDecodeError as e:
            return self._block_decision("QR decoding failed", str(e))

        payload_type = self.classifier.classify(payload)

        response = {
            "payload_type": payload_type,
            "decision": DecisionAction.ALLOW,
            "risk_level": RiskLevel.LOW.value,
            "reasons": [],
            "details": {}
        }

        # ---------- UPI FLOW ----------
        if payload_type == PayloadType.UPI:
            try:
                upi_data = self.upi_parser.parse(payload)
                risk = self.risk_engine.evaluate_upi(upi_data)

                response["risk_level"] = risk.level().value
                response["reasons"] = list(risk.reasons)
                response["details"] = upi_data

                if risk.level() == RiskLevel.HIGH:
                    response["decision"] = DecisionAction.BLOCK

                elif risk.level() == RiskLevel.MEDIUM:
                    # ML second opinion
                    features = self.feature_extractor.extract_upi_features(upi_data)
                    ml_result = self.ml_scorer.predict_risk(features)

                    response["details"]["ml_used"] = ml_result["model_used"]
                    response["details"]["ml_risk_probability"] = ml_result["risk_probability"]

                    if ml_result["model_used"] and ml_result["risk_probability"] is not None:
                        if ml_result["risk_probability"] >= 0.7:
                            response["decision"] = DecisionAction.BLOCK
                            response["reasons"].append(
                                "ML model identified high scam probability"
                            )
                        elif ml_result["risk_probability"] >= 0.4:
                            response["decision"] = DecisionAction.WARN
                            response["reasons"].append(
                                "ML model identified moderate scam probability"
                            )
                        else:
                            response["decision"] = DecisionAction.ALLOW

                        # SHAP explainability
                        if self.ml_xai:
                            shap_exp = self.ml_xai.explain(features)
                            response["details"]["ml_explanation"] = shap_exp

                            top_feature = max(
                                shap_exp, key=lambda k: abs(shap_exp[k])
                            )
                            response["reasons"].append(
                                f"ML analysis found '{top_feature}' as a major risk contributor"
                            )
                    else:
                        response["decision"] = DecisionAction.WARN

            except UPIParseError as e:
                return self._block_decision(
                    "Invalid or unsafe UPI QR",
                    str(e)
                )

        # ---------- URL FLOW ----------
        elif payload_type == PayloadType.URL:
            risk = self.risk_engine.evaluate_url(payload)

            response["risk_level"] = risk.level().value
            response["reasons"] = list(risk.reasons)
            response["details"] = {"url": payload}

            if risk.level() != RiskLevel.LOW:
                response["decision"] = DecisionAction.WARN

        # ---------- UNKNOWN ----------
        else:
            response["decision"] = DecisionAction.WARN
            response["risk_level"] = RiskLevel.MEDIUM.value
            response["reasons"].append("Unknown or unsupported QR payload")

        # 🔐 ALWAYS return explainable output
        # Scam category classification
        scam_category = self.scam_classifier.classify(
            payload_type=response.get("payload_type"),
            reasons=response.get("reasons", []),
            details=response.get("details", {})
        )

        response["scam_category"] = scam_category.value

        final_result = self.explain_engine.generate(response)
        self.audit_logger.log(final_result)
        return final_result


    def _block_decision(self, title: str, reason: str) -> dict:
        base_response = {
            "decision": DecisionAction.BLOCK,
            "risk_level": RiskLevel.HIGH.value,
            "reasons": [title, reason]
        }
        final_result = self.explain_engine.generate(base_response)
        self.audit_logger.log(final_result)
        return final_result

