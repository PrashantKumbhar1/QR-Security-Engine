from core.qr_decoder import QRDecoder, QRDecodeError
from core.payload_classifier import QRPayloadClassifier, PayloadType
from core.upi_parser import UPIParser, UPIParseError
from core.risk_engine import QRHeuristicRiskEngine, RiskLevel
from core.explainability_engine import QRExplainabilityEngine

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

    def analyze_qr(self, image_path: str) -> dict:
        """
        End-to-end QR security analysis.

        Returns:
            dict: decision, risk_level, reasons, metadata
        """

        try:
            payload = self.decoder.decode_qr(image_path)
        except QRDecodeError as e:
            return self._block_decision("QR decoding failed", str(e))

        payload_type = self.classifier.classify(payload)

        # Default response structure
        response = {
            "payload_type": payload_type,
            "decision": DecisionAction.ALLOW,
            "risk_level": RiskLevel.LOW.value,
            "reasons": [],
            "details": {}
        }

        # ---- UPI FLOW ----
        if payload_type == PayloadType.UPI:
            try:
                upi_data = self.upi_parser.parse(payload)
                risk = self.risk_engine.evaluate_upi(upi_data)

                response["risk_level"] = risk.level().value
                response["reasons"] = risk.reasons
                response["details"] = upi_data

                if risk.level() == RiskLevel.HIGH:
                    response["decision"] = DecisionAction.BLOCK
                elif risk.level() == RiskLevel.MEDIUM:
                    response["decision"] = DecisionAction.WARN

            except UPIParseError as e:
                return self._block_decision(
                    "Invalid or unsafe UPI QR",
                    str(e)
                )

        # ---- URL FLOW ----
        elif payload_type == PayloadType.URL:
            risk = self.risk_engine.evaluate_url(payload)

            response["risk_level"] = risk.level().value
            response["reasons"] = risk.reasons
            response["details"] = {"url": payload}

            if risk.level() != RiskLevel.LOW:
                response["decision"] = DecisionAction.WARN

        # ---- OTHER / UNKNOWN ----
        else:
            response["decision"] = DecisionAction.WARN
            response["risk_level"] = RiskLevel.MEDIUM.value
            response["reasons"].append("Unknown or unsupported QR payload")

        return response

    def _block_decision(self, title: str, reason: str) -> dict:
        base_response = {
            "decision": DecisionAction.BLOCK,
            "risk_level": RiskLevel.HIGH.value,
            "reasons": [title, reason]
        }
        return self.explain_engine.generate(base_response)
