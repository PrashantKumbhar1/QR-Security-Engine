from core.qr_decoder import QRDecoder, QRDecodeError
from core.payload_classifier import QRPayloadClassifier, PayloadType
from core.upi_parser import UPIParser, UPIParseError
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel
from core.explainability_engine import QRExplainabilityEngine
from core.feature_extractor import QRFeatureExtractor
from core.ml_risk_scorer import MLRiskScorer
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

        # Optional ML components
        self.feature_extractor = QRFeatureExtractor()
        self.ml_scorer = MLRiskScorer()

        # Intelligence layers
        self.scam_classifier = QRScamClassifier()
        self.audit_logger = QRAuditLogger()

    def analyze_qr(self, image_path: str) -> dict:
        """
        End-to-end QR security analysis with decision replay timeline
        """

        timeline = DecisionTimeline()
        timeline.add_step(
            stage="SCAN",
            description="QR code scanned by user"
        )

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
            return self._block_decision("QR decoding failed", str(e), timeline)

        payload_type = self.classifier.classify(payload)
        timeline.add_step(
            stage="CLASSIFY",
            description=f"QR classified as {payload_type}"
        )

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

                timeline.add_step(
                    stage="RISK_ANALYSIS",
                    description="Heuristic UPI risk analysis completed",
                    outcome=f"Risk level: {response['risk_level']}"
                )

                if risk.level() == RiskLevel.HIGH:
                    response["decision"] = DecisionAction.BLOCK

                elif risk.level() == RiskLevel.MEDIUM:
                    response["decision"] = DecisionAction.WARN

            except UPIParseError as e:
                timeline.add_step(
                    stage="PARSE",
                    description="UPI parsing failed",
                    outcome=str(e)
                )
                return self._block_decision(
                    "Invalid or unsafe UPI QR",
                    str(e),
                    timeline
                )

        # ---------- URL FLOW ----------
        elif payload_type == PayloadType.URL:
            risk = self.risk_engine.evaluate_url(payload)

            response["risk_level"] = risk.level().value
            response["reasons"] = list(risk.reasons)
            response["details"] = {"url": payload}

            timeline.add_step(
                stage="RISK_ANALYSIS",
                description="URL risk analysis completed",
                outcome=f"Risk level: {response['risk_level']}"
            )

            if risk.level() != RiskLevel.LOW:
                response["decision"] = DecisionAction.WARN

        # ---------- UNKNOWN ----------
        else:
            response["decision"] = DecisionAction.WARN
            response["risk_level"] = RiskLevel.MEDIUM.value
            response["reasons"].append("Unknown or unsupported QR payload")

            timeline.add_step(
                stage="RISK_ANALYSIS",
                description="Unknown QR payload pattern detected",
                outcome="Risk level: MEDIUM"
            )

        # ---------- SCAM CATEGORY ----------
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

        final_result = self.explain_engine.generate(response)
        self.audit_logger.log(final_result)
        return final_result

    def _block_decision(self, title: str, reason: str, timeline: DecisionTimeline) -> dict:
        timeline.add_step(
            stage="DECISION",
            description="QR blocked due to critical error",
            outcome=title
        )

        base_response = {
            "decision": DecisionAction.BLOCK,
            "risk_level": RiskLevel.HIGH.value,
            "reasons": [title, reason],
            "decision_timeline": timeline.export()
        }

        final_result = self.explain_engine.generate(base_response)
        self.audit_logger.log(final_result)
        return final_result
