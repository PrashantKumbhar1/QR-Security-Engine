from urllib.parse import urlparse
import re


class QRFeatureExtractor:
    """
    Extracts ML-ready numerical features from QR payload data
    """

    # ---------- PUBLIC API ----------

    def extract_upi_features(self, upi_data: dict) -> dict:
        """
        Extracts features from parsed UPI payload
        """
        features = {}

        payee_name = upi_data.get("payee_name", "")
        payee_address = upi_data.get("payee_address", "")
        amount = upi_data.get("amount") or 0

        features["amount"] = float(amount)
        features["merchant_name_missing"] = 1 if not payee_name else 0
        features["merchant_name_length"] = len(payee_name)
        features["upi_id_length"] = len(payee_address)
        features["generic_merchant_name"] = self._is_generic_name(payee_name)

        return features

    def extract_url_features(self, url: str) -> dict:
        """
        Extracts features from URL-based QR payloads
        """
        features = {}

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        features["url_length"] = len(url)
        features["has_shortener"] = self._is_shortened_url(domain)
        features["is_https"] = 1 if parsed.scheme == "https" else 0
        features["is_ip_url"] = self._is_ip_based(domain)

        return features

    # ---------- INTERNAL HELPERS ----------

    def _is_generic_name(self, name: str) -> int:
        generic_names = ["payment", "upi", "pay", "merchant", "store"]
        return 1 if name.lower().strip() in generic_names else 0

    def _is_shortened_url(self, domain: str) -> int:
        shorteners = [
            "bit.ly", "tinyurl.com", "t.co",
            "goo.gl", "ow.ly", "is.gd"
        ]
        return 1 if domain in shorteners else 0

    def _is_ip_based(self, domain: str) -> int:
        return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
