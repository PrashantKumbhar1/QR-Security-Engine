import re
from urllib.parse import urlparse, unquote


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
            str: PayloadType constant
        """
        if not payload or not isinstance(payload, str):
            return PayloadType.UNKNOWN

        # Normalize whitespace and newlines for classification
        cleaned = payload.strip()

        if not cleaned:
            return PayloadType.UNKNOWN

        # UPI payment intent detection (case insensitive)
        if cleaned.lower().startswith("upi://pay"):
            return PayloadType.UPI

        # URL detection (http, https, or domain string like youtube.com or www.youtube.com)
        unquoted = unquote(cleaned)
        parse_target = cleaned if cleaned.lower().startswith(("http://", "https://", "ftp://")) else "https://" + cleaned
        parsed = urlparse(parse_target)
        if parsed.netloc and "." in parsed.netloc and not any(c in cleaned for c in ["\n", "\r"]):
            return PayloadType.URL

        # Fallback URL parsing for unquoted string
        parsed_unquoted = urlparse(unquoted if unquoted.lower().startswith(("http://", "https://")) else "https://" + unquoted)
        if parsed_unquoted.netloc and "." in parsed_unquoted.netloc and not any(c in unquoted for c in ["\n", "\r"]):
            return PayloadType.URL


        # Plain readable text detection (alphanumeric, whitespace, standard punctuation)
        if re.match(r"^[\w\s\-_,.:;!?@#$%&*()/+=\[\]{}'\"<>-]+$", cleaned, re.UNICODE):
            return PayloadType.TEXT

        return PayloadType.UNKNOWN

