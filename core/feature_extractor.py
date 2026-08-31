from urllib.parse import urlparse, parse_qs
import re
import string


class QRFeatureExtractor:
    """
    Extracts ML-ready numerical features from QR payload data with deterministic, versioned schemas (Schema v2.0).
    """

    SCHEMA_VERSION = "2.0"

    COMMON_FEATURE_KEYS = [
        "payload_length",
        "digit_ratio",
        "special_char_count",
    ]

    URL_FEATURE_KEYS = COMMON_FEATURE_KEYS + [
        "url_length",
        "domain_length",
        "path_length",
        "query_param_count",
        "subdomain_count",
        "has_shortener",
        "is_https",
        "is_ip_url",
        "has_at_symbol",
        "suspicious_tld",
        "hex_encoding_count",
        "double_slash_in_path",
    ]

    UPI_FEATURE_KEYS = COMMON_FEATURE_KEYS + [
        "amount",
        "amount_missing",
        "merchant_name_missing",
        "merchant_name_length",
        "generic_merchant_name",
        "upi_id_length",
        "upi_handle_length",
        "has_embedded_url",
        "non_standard_param_count",
        "suspicious_vpa_pattern",
    ]

    # High-risk top-level domains frequently observed in phishing
    SUSPICIOUS_TLDS = {
        "top", "xyz", "zip", "work", "click", "cc", "tk", "ml", "ga", "gq",
        "fit", "surf", "casa", "country", "kim", "science", "gdn"
    }

    # Standard UPI query parameters
    STANDARD_UPI_PARAMS = {"pa", "pn", "mc", "tid", "tr", "tn", "am", "cu", "url", "mode", "sign"}

    # Generic merchant names common in QR scams
    GENERIC_NAMES = {"payment", "upi", "pay", "merchant", "store", "cash", "account", "transfer", "help"}

    # Known URL shortening services
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bit.do", "mcaf.ee", "su.pr", "cutt.ly", "rb.gy"
    }

    # ---------- COMMON FEATURES ----------

    def extract_common_features(self, payload: str) -> dict:
        """
        Extracts 3 common payload features.
        """
        if not payload or not isinstance(payload, str):
            return {
                "payload_length": 0,
                "digit_ratio": 0.0,
                "special_char_count": 0,
            }

        length = len(payload)
        digits = sum(c.isdigit() for c in payload)
        specials = sum(c in "!@#$%^&*+=<>?/\\|~`" for c in payload)

        return {
            "payload_length": length,
            "digit_ratio": round(digits / length, 4) if length > 0 else 0.0,
            "special_char_count": specials,
        }

    # ---------- URL FEATURES ----------

    def extract_url_features(self, url: str) -> dict:
        """
        Extracts 15 URL security features (URL_FEATURE_SCHEMA_V2).
        """
        if not url or not isinstance(url, str):
            url = ""

        cleaned = url.strip()
        common = self.extract_common_features(cleaned)

        # Normalize target URL for parsing if scheme is missing
        if not cleaned.lower().startswith(("http://", "https://", "ftp://")):
            parse_target = "https://" + cleaned
            scheme_present = False
        else:
            parse_target = cleaned
            scheme_present = True

        parsed = urlparse(parse_target)

        domain = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
        path = parsed.path
        query = parsed.query
        params = parse_qs(query)

        # Subdomain count calculation
        domain_parts = [p for p in domain.split(".") if p]
        subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0

        # TLD check
        tld = domain_parts[-1] if domain_parts else ""
        suspicious_tld = 1 if tld in self.SUSPICIOUS_TLDS else 0

        # Hex encoding count (%XX)
        hex_count = len(re.findall(r"%[0-9a-fA-F]{2}", cleaned))

        return {
            **common,
            "url_length": len(cleaned),
            "domain_length": len(domain),
            "path_length": len(path),
            "query_param_count": len(params),
            "subdomain_count": subdomain_count,
            "has_shortener": 1 if domain in self.URL_SHORTENERS else 0,
            "is_https": 1 if (parsed.scheme.lower() == "https" or not scheme_present) else 0,
            "is_ip_url": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0,
            "has_at_symbol": 1 if "@" in cleaned else 0,
            "suspicious_tld": suspicious_tld,
            "hex_encoding_count": hex_count,
            "double_slash_in_path": 1 if "//" in path else 0,
        }


    # ---------- UPI FEATURES ----------

    def extract_upi_features(self, upi_data: dict) -> dict:
        """
        Extracts 13 UPI security features (UPI_FEATURE_SCHEMA_V2).
        """
        if not isinstance(upi_data, dict):
            upi_data = {}

        raw_payload = upi_data.get("raw_payload", "")
        if not raw_payload and "payee_address" in upi_data:
            pa = upi_data.get("payee_address", "")
            pn = upi_data.get("payee_name", "")
            am = upi_data.get("amount", "")
            raw_payload = f"upi://pay?pa={pa}&pn={pn}&am={am}"

        common = self.extract_common_features(str(raw_payload))

        payee_name = str(upi_data.get("payee_name") or "").strip()
        payee_address = str(upi_data.get("payee_address") or "").strip()

        # Handle splitting VPA address@bank
        vpa_parts = payee_address.split("@")
        handle_length = len(vpa_parts[1]) if len(vpa_parts) > 1 else 0

        # Amount checking
        raw_amount = upi_data.get("amount")
        amount_missing = 1 if raw_amount is None or raw_amount == "" else 0
        try:
            amount_val = float(raw_amount or 0.0)
        except (ValueError, TypeError):
            amount_val = 0.0

        # Embedded URL check
        embedded_urls = upi_data.get("embedded_urls", [])
        security_indicators = upi_data.get("security_indicators", [])
        has_embedded_url = 1 if (embedded_urls or "embedded_external_url" in security_indicators) else 0

        # Non-standard parameters check
        raw_params = upi_data.get("raw_params", {})
        non_standard_count = len(set(raw_params.keys()) - self.STANDARD_UPI_PARAMS) if isinstance(raw_params, dict) else 0

        # Suspicious VPA pattern
        suspicious_vpa = 1 if (payee_address.count(".") > 2 or "-" in payee_address) else 0

        return {
            **common,
            "amount": amount_val,
            "amount_missing": amount_missing,
            "merchant_name_missing": 1 if not payee_name else 0,
            "merchant_name_length": len(payee_name),
            "generic_merchant_name": 1 if payee_name.lower() in self.GENERIC_NAMES else 0,
            "upi_id_length": len(payee_address),
            "upi_handle_length": handle_length,
            "has_embedded_url": has_embedded_url,
            "non_standard_param_count": non_standard_count,
            "suspicious_vpa_pattern": suspicious_vpa,
        }


