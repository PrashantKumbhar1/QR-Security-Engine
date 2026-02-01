from enum import Enum


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskResult:
    def __init__(self):
        self.score = 0
        self.reasons = []

    def add_risk(self, points: int, reason: str):
        self.score += points
        self.reasons.append(reason)

    def level(self) -> RiskLevel:
        if self.score >= 70:
            return RiskLevel.HIGH
        elif self.score >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


class QRHeuristicRiskEngine:
    def evaluate_upi(self, upi_data: dict) -> RiskResult:
        """
        Applies heuristic rules to UPI payment data
        """
        result = RiskResult()

        pa = upi_data.get("payee_address", "")
        pn = upi_data.get("payee_name", "")
        amount = upi_data.get("amount")

        # Rule 1: Missing or empty merchant name
        if not pn:
            result.add_risk(15, "Merchant name is missing")

        # Rule 2: Suspicious UPI ID patterns
        if pa.count(".") > 2 or "-" in pa:
            result.add_risk(10, "Unusual UPI ID format")

        # Rule 3: High amount without user intent
        if amount and amount >= 5000:
            result.add_risk(25, "High payment amount detected")

        # Rule 4: Generic merchant names (common in scams)
        if pn.lower() in ["payment", "upi", "pay", "merchant"]:
            result.add_risk(20, "Generic merchant name detected")

        return result

    def evaluate_url(self, url: str) -> RiskResult:
        """
        Applies heuristic rules to URL-based QR codes
        """
        result = RiskResult()

        # Rule 1: URL shorteners
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        if any(s in url for s in shorteners):
            result.add_risk(30, "URL shortener detected")

        # Rule 2: IP-based URLs
        if "://" in url and url.split("://")[1].split("/")[0].replace(".", "").isdigit():
            result.add_risk(40, "IP-based URL detected")

        # Rule 3: Non-HTTPS
        if url.startswith("http://"):
            result.add_risk(20, "Non-secure HTTP URL")

        return result
