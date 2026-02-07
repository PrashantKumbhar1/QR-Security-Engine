from enum import Enum


class ScamCategory(Enum):
    REDIRECTION = "Redirection Scam"
    FAKE_MERCHANT = "Fake Merchant Scam"
    OVERPAYMENT = "Overpayment Scam"
    UNKNOWN = "Unknown / Suspicious Pattern"


class QRScamClassifier:
    """
    Classifies the type of scam based on detected risk signals
    """

    def classify(self, payload_type, reasons: list, details: dict) -> ScamCategory:

        # URL-based redirection scams
        if payload_type == "URL":
            if "URL shortener detected" in reasons:
                return ScamCategory.REDIRECTION

        # Fake merchant scams
        if "Merchant name is missing" in reasons or \
           "Generic merchant name detected" in reasons:
            return ScamCategory.FAKE_MERCHANT

        # Overpayment / urgency scams
        if "High payment amount detected" in reasons:
            return ScamCategory.OVERPAYMENT

        return ScamCategory.UNKNOWN
