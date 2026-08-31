from core.qr_decoder import QRDecoder, QRDecodeError
from core.payload_classifier import QRPayloadClassifier, PayloadType
from core.upi_parser import UPIParser, UPIParseError
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel
from core.explainability_engine import QRExplainabilityEngine
from core.feature_extractor import QRFeatureExtractor
from core.ml_risk_scorer import MLRiskScorer
from core.risk_fusion import QRRiskFusionEngine
from core.scam_classifier import QRScamClassifier
from core.audit_logger import QRAuditLogger
from core.decision_timeline import DecisionTimeline


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

        # ML and Feature components
        self.feature_extractor = QRFeatureExtractor()
        self.ml_scorer = MLRiskScorer()
        self.fusion_engine = QRRiskFusionEngine()

        # Intelligence layers
        self.scam_classifier = QRScamClassifier()
        self.audit_logger = QRAuditLogger()

    def analyze_qr(self, image_path: str) -> dict:
        """
        End-to-end QR security analysis pipeline:
        Decode -> Classify -> Parse -> Feature Extraction -> Heuristics -> ML Scorer -> Risk Fusion -> Explanation -> Final Result
        """
        timeline = DecisionTimeline()
        timeline.add_step(
            stage="SCAN",
            description="QR code scanned by user"
        )

        # 1. DECODE STAGE
        try:
            payload = self.decoder.decode_qr(image_path)
            timeline.add_step(
                stage="DECODE",
                description="QR code decoded successfully"
            )
        except QRDecodeError as e:
            timeline.add_step(
                stage="DECODE",
                description="QR decoding failed",
                outcome=str(e)
            )
            return self._format_error_response(
                stage="decoder",
                error=str(e),
                timeline=timeline
            )

        # 2. CLASSIFY STAGE
        payload_type = self.classifier.classify(payload)
        timeline.add_step(
            stage="CLASSIFY",
            description=f"QR classified as {payload_type}"
        )

        response = {
            "success": True,
            "payload": payload,
            "payload_type": payload_type,
            "decision": DecisionAction.ALLOW,
            "risk_level": RiskLevel.LOW.value,
            "heuristic_score": 0,
            "ml_risk_probability": None,
            "final_risk_score": 0,
            "fusion_metadata": {},
            "indicators": [],
            "reasons": [],
            "details": {}
        }

        # 3. PARSE & ANALYZE STAGE
        if payload_type == PayloadType.UPI:
            try:
                upi_data = self.upi_parser.parse(payload)
                risk_result = self.risk_engine.evaluate_upi(upi_data)
                features = self.feature_extractor.extract_upi_features(upi_data)

                response["heuristic_score"] = risk_result.score
                response["reasons"] = list(risk_result.reasons)
                response["indicators"] = [ind if isinstance(ind, dict) else ind.to_dict() for ind in risk_result.indicators]
                response["details"] = {
                    "upi_data": upi_data,
                    "features": features
                }

                timeline.add_step(
                    stage="RISK_ANALYSIS",
                    description="Heuristic UPI risk analysis completed",
                    outcome=f"Heuristic score: {risk_result.score}"
                )

                # ML Inference Step for UPI
                if self.ml_scorer.is_model_loaded():
                    ml_eval = self.ml_scorer.predict_upi_risk(features)
                    if ml_eval.get("model_used") and ml_eval.get("risk_probability") is not None:
                        prob = ml_eval["risk_probability"]
                        response["ml_risk_probability"] = prob
                        timeline.add_step(
                            stage="ML_INFERENCE",
                            description="ML model risk prediction evaluated",
                            outcome=f"Scam probability: {prob}"
                        )

            except UPIParseError as e:
                timeline.add_step(
                    stage="PARSE",
                    description="UPI parsing failed",
                    outcome=str(e)
                )
                return self._format_error_response(
                    stage="upi_parser",
                    error=str(e),
                    timeline=timeline
                )

        elif payload_type == PayloadType.URL:
            risk_result = self.risk_engine.evaluate_url(payload)
            features = self.feature_extractor.extract_url_features(payload)

            response["heuristic_score"] = risk_result.score
            response["reasons"] = list(risk_result.reasons)
            response["indicators"] = [ind if isinstance(ind, dict) else ind.to_dict() for ind in risk_result.indicators]
            response["details"] = {
                "url": payload,
                "features": features
            }

            timeline.add_step(
                stage="RISK_ANALYSIS",
                description="URL risk analysis completed",
                outcome=f"Heuristic score: {risk_result.score}"
            )

            # ML Inference Step for URL
            if self.ml_scorer.is_model_loaded():
                ml_eval = self.ml_scorer.predict_url_risk(features)
                if ml_eval.get("model_used") and ml_eval.get("risk_probability") is not None:
                    prob = ml_eval["risk_probability"]
                    response["ml_risk_probability"] = prob
                    timeline.add_step(
                        stage="ML_INFERENCE",
                        description="ML URL model risk prediction evaluated",
                        outcome=f"Phishing probability: {prob}"
                    )

        elif payload_type == PayloadType.TEXT:
            response["details"] = {"text": payload}
            timeline.add_step(
                stage="RISK_ANALYSIS",
                description="Plain text payload verified safe",
                outcome="Risk level: LOW"
            )

        else:
            response["heuristic_score"] = 35
            response["reasons"].append("Unknown or unsupported QR payload")
            timeline.add_step(
                stage="RISK_ANALYSIS",
                description="Unknown QR payload pattern detected",
                outcome="Risk level: MEDIUM"
            )

        # 4. RISK FUSION STAGE
        fusion_result = self.fusion_engine.fuse(
            payload_type=payload_type,
            ml_probability=response.get("ml_risk_probability"),
            heuristic_score=response.get("heuristic_score", 0),
            indicators=response.get("indicators", [])
        )

        response["final_risk_score"] = fusion_result["final_risk_score"]
        response["risk_level"] = fusion_result["risk_level"]
        response["decision"] = fusion_result["decision"]
        response["fusion_metadata"] = fusion_result["fusion_metadata"]

        timeline.add_step(
            stage="RISK_FUSION",
            description="ML and Heuristic scores mathematically fused",
            outcome=f"Final Risk Score: {response['final_risk_score']}/100, Level: {response['risk_level']}"
        )

        # 5. SCAM CLASSIFICATION STAGE
        scam_category = self.scam_classifier.classify(
            payload_type=response.get("payload_type"),
            reasons=response.get("reasons", []),
            details=response.get("details", {})
        )
        response["scam_category"] = scam_category.value

        timeline.add_step(
            stage="SCAM_CLASSIFICATION",
            description="Scam category determined",
            outcome=scam_category.value
        )

        timeline.add_step(
            stage="DECISION",
            description="Final decision applied",
            outcome=response["decision"]
        )

        response["decision_timeline"] = timeline.export()

        # 6. EXPLANATION & AUDIT STAGE
        final_result = self.explain_engine.generate(response)
        final_result["success"] = True
        final_result["payload"] = payload
        final_result["payload_type"] = payload_type
        final_result["heuristic_score"] = response["heuristic_score"]
        final_result["ml_risk_probability"] = response["ml_risk_probability"]
        final_result["final_risk_score"] = response["final_risk_score"]
        final_result["fusion_metadata"] = response["fusion_metadata"]
        final_result["indicators"] = response["indicators"]

        self.audit_logger.log(final_result)
        return final_result


    def _format_error_response(self, stage: str, error: str, timeline: DecisionTimeline) -> dict:
        timeline.add_step(
            stage="DECISION",
            description="QR processing halted due to critical error",
            outcome=f"{stage}: {error}"
        )

        base_response = {
            "success": False,
            "stage": stage,
            "error": error,
            "decision": DecisionAction.BLOCK,
            "risk_level": RiskLevel.HIGH.value,
            "reasons": [f"Failure in {stage}", error],
            "decision_timeline": timeline.export()
        }

        final_result = self.explain_engine.generate(base_response)
        final_result["success"] = False
        final_result["stage"] = stage
        final_result["error"] = error
        final_result["heuristic_score"] = 100
        final_result["indicators"] = []

        self.audit_logger.log(final_result)
        return final_result

