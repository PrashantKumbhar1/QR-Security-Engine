from urllib.parse import urlparse, parse_qs
import re


class UPIParseError(Exception):
    """Raised when UPI payload is fundamentally malformed or invalid"""
    pass


class UPIParser:
    REQUIRED_FIELDS = ["pa"]
    STANDARD_UPI_PARAMS = {"pa", "pn", "mc", "tid", "tr", "tn", "am", "cu", "url", "mode", "sign"}

    def parse(self, payload: str) -> dict:
        """
        Parses and validates a UPI payment QR payload.

        Args:
            payload (str): QR payload string

        Returns:
            dict: Parsed UPI data with security indicators and warnings

        Raises:
            UPIParseError: If scheme is not upi or required payee address (pa) is missing.
        """
        if not payload or not isinstance(payload, str):
            raise UPIParseError("Payload is empty or invalid type")

        cleaned = payload.strip()
        parsed = urlparse(cleaned)

        if parsed.scheme.lower() != "upi":
            raise UPIParseError("Invalid UPI scheme: expected 'upi://'")

        if parsed.netloc.lower() != "pay":
            raise UPIParseError(f"Invalid UPI action: expected 'pay', got '{parsed.netloc}'")

        params = parse_qs(parsed.query)
        warnings = []
        security_indicators = []
        embedded_urls = []

        # Validate required fields
        for field in self.REQUIRED_FIELDS:
            if field not in params or not params[field][0].strip():
                raise UPIParseError(f"Missing required UPI field: '{field}'")

        pa = params["pa"][0].strip()

        # Basic UPI ID validation
        if not self._is_valid_upi_id(pa):
            warnings.append(f"Unusual or malformed UPI ID format: '{pa}'")
            security_indicators.append("malformed_upi_id")

        # Payee Name check
        payee_name = params.get("pn", [""])[0].strip()
        if not payee_name:
            warnings.append("Merchant name (pn) is missing")
            security_indicators.append("missing_merchant_name")

        # Amount validation
        amount = None
        raw_amount = params.get("am", [None])[0]
        if raw_amount is not None:
            try:
                amount = float(raw_amount)
                if amount <= 0:
                    warnings.append(f"Invalid non-positive payment amount: {raw_amount}")
                    security_indicators.append("invalid_amount")
            except (ValueError, TypeError):
                warnings.append(f"Amount is not a valid number: '{raw_amount}'")
                security_indicators.append("malformed_amount")
                amount = 0.0

        # Embedded URL detection across all query parameters (suspicious scam vector)
        for key, values in params.items():
            for val in values:
                if "http://" in val.lower() or "https://" in val.lower():
                    embedded_urls.append(val)
                    warnings.append(f"Embedded URL detected in parameter '{key}': '{val}'")
                    if "embedded_external_url" not in security_indicators:
                        security_indicators.append("embedded_external_url")

        # Non-standard / Unknown parameter check
        unknown_params = set(params.keys()) - self.STANDARD_UPI_PARAMS
        if unknown_params:
            warnings.append(f"Non-standard parameters detected: {list(unknown_params)}")
            security_indicators.append("non_standard_parameters")

        return {
            "valid": True,
            "payee_address": pa,
            "payee_name": payee_name,
            "amount": amount,
            "currency": params.get("cu", ["INR"])[0],
            "raw_params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            "warnings": warnings,
            "security_indicators": security_indicators,
            "embedded_urls": embedded_urls
        }

    def _is_valid_upi_id(self, upi_id: str) -> bool:
        """
        Validates standard UPI ID format (handle@bank)
        """
        return bool(re.match(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$", upi_id))

