import re
from urllib.parse import urlparse


class PayloadType:
    UPI = "UPI_PAYMENT"
    URL = "URL"
    TEXT = "PLAIN_TEXT"
    UNKNOWN = "UNKNOWN"


class QRPayloadClassifier:
    def classify(self, payload: str) -> str:
        """
        Classifies QR payload into known types.

        Args:
            payload (str): Decoded QR payload

        Returns:
            str: PayloadType
        """

        if not payload or not isinstance(payload, str):
            return PayloadType.UNKNOWN

        payload = payload.strip()

        # UPI payment intent
        if payload.lower().startswith("upi://pay"):
            return PayloadType.UPI

        # URL detection
        parsed = urlparse(payload)
        if parsed.scheme in ["http", "https"] and parsed.netloc:
            return PayloadType.URL

        # Plain readable text (no URL / no scheme)
        if re.match(r"^[a-zA-Z0-9\s\-_,.]+$", payload):
            return PayloadType.TEXT

        return PayloadType.UNKNOWN
