class QRExplainabilityEngine:
    """
    Builds human-readable explanations for QR security decisions
    """

    def generate(self, decision_result: dict) -> dict:
        """
        Converts decision output into an explainable security story

        Args:
            decision_result (dict): Output from QRDecisionEngine

        Returns:
            dict: explainability output
        """

        decision = decision_result.get("decision")
        risk_level = decision_result.get("risk_level")
        reasons = decision_result.get("reasons", [])

        return {
            "decision": decision,
            "risk_level": risk_level,
            "summary": self._summary(risk_level),
            "why_dangerous": self._why_dangerous(reasons),
            "recommended_action": self._recommended_action(decision)
        }

    def _summary(self, risk_level: str) -> str:
        summaries = {
            "LOW": "This QR code appears safe based on current security checks.",
            "MEDIUM": "This QR code shows warning signs and should be reviewed carefully.",
            "HIGH": "This QR code shows strong indicators of a payment scam."
        }
        return summaries.get(risk_level, "QR risk level could not be determined.")

    def _why_dangerous(self, reasons: list) -> list:
        explanation_map = {
            "High payment amount detected":
                "The payment amount requested is unusually high, which is commonly seen in QR payment scams.",

            "Merchant name is missing":
                "The QR does not specify a merchant name. Legitimate businesses usually provide clear identification.",

            "Generic merchant name detected":
                "The merchant name used is very generic, a pattern often observed in fraudulent QR codes.",

            "URL shortener detected":
                "The QR contains a shortened link, which can hide the actual destination and increase scam risk.",

            "Non-secure HTTP URL":
                "The QR points to a non-secure website, which increases the risk of redirection or phishing attacks.",

            "Unknown or unsupported QR payload":
                "The QR uses an unusual format that cannot be safely verified."
        }

        explanations = []
        for reason in reasons:
            explanations.append(
                explanation_map.get(
                    reason,
                    f"This QR triggered a security warning: {reason}."
                )
            )

        return explanations

    def _recommended_action(self, decision: str) -> str:
        if decision == "BLOCK":
            return "Do not proceed with the payment. This QR is likely unsafe."
        if decision == "WARN":
            return "Proceed only if you trust the source of this QR code."
        return "You may safely proceed with this payment."
