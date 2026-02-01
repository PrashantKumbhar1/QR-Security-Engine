from urllib.parse import urlparse, parse_qs
import re


class UPIParseError(Exception):
    """Raised when UPI payload is invalid or unsafe"""
    pass


class UPIParser:
    REQUIRED_FIELDS = ["pa"]

    def parse(self, payload: str) -> dict:
        """
        Parses and validates a UPI payment QR payload.

        Args:
            payload (str): QR payload string

        Returns:
            dict: Parsed and validated UPI data

        Raises:
            UPIParseError
        """

        parsed = urlparse(payload)

        if parsed.scheme != "upi":
            raise UPIParseError("Invalid UPI scheme")

        if parsed.netloc != "pay":
            raise UPIParseError("Invalid UPI action")

        params = parse_qs(parsed.query)

        # Validate required fields
        for field in self.REQUIRED_FIELDS:
            if field not in params or not params[field][0].strip():
                raise UPIParseError(f"Missing required UPI field: {field}")

        pa = params["pa"][0].strip()

        # Basic UPI ID validation
        if not self._is_valid_upi_id(pa):
            raise UPIParseError("Invalid UPI ID format")

        # Detect embedded URLs (very common scam trick)
        for key, values in params.items():
            for value in values:
                if "http://" in value or "https://" in value:
                    raise UPIParseError("Suspicious URL found inside UPI payload")

        amount = params.get("am", [None])[0]
        if amount:
            try:
                amount = float(amount)
                if amount <= 0:
                    raise UPIParseError("Invalid payment amount")
            except ValueError:
                raise UPIParseError("Amount is not a valid number")

        return {
            "payee_address": pa,
            "payee_name": params.get("pn", [""])[0],
            "amount": amount,
            "currency": params.get("cu", ["INR"])[0],
            "raw_params": params
        }

    def _is_valid_upi_id(self, upi_id: str) -> bool:
        """
        Validates basic UPI ID format (name@bank)
        """
        return bool(re.match(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$", upi_id))
