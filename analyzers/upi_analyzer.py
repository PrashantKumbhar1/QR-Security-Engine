import json
import os
import re


class DeepUPIAnalyzer:
    """
    Modular Deep UPI Security Analyzer.
    Evaluates VPA structure, payee consistency, amount rules, embedded URLs, and query parameters.
    """

    GENERIC_NAMES = {"payment", "upi", "pay", "merchant", "store", "cash", "account", "transfer", "help", "billing"}
    STANDARD_PARAMS = {"pa", "pn", "mc", "tid", "tr", "tn", "am", "cu", "url", "mode", "sign"}
    TEMPORARY_HANDLES = {"temp", "fake", "verify", "claim", "win", "test", "scam"}

    def __init__(self, rules_config_path: str = "config/security_rules.json"):
        self.rules_map = self._load_json_config(rules_config_path, "rules")

    def analyze(self, upi_data: dict) -> list:
        """
        Analyzes parsed UPI data and returns a list of detected RiskIndicator dictionaries.
        """
        indicators = []
        if not isinstance(upi_data, dict):
            return indicators

        pa = str(upi_data.get("payee_address") or "").strip()
        pn = str(upi_data.get("payee_name") or "").strip()
        raw_amount = upi_data.get("amount")
        security_indicators = upi_data.get("security_indicators", [])
        embedded_urls = upi_data.get("embedded_urls", [])

        # 1. UPI_EMBEDDED_EXTERNAL_URL (CRITICAL)
        if embedded_urls or "embedded_external_url" in security_indicators:
            evidence_url = embedded_urls[0] if embedded_urls else "http(s):// parameter"
            self._add_indicator(
                indicators, "UPI_EMBEDDED_EXTERNAL_URL",
                reason="UPI payment payload contains an embedded external URL parameter.",
                evidence=evidence_url
            )

        # 2. UPI_UNUSUALLY_HIGH_AMOUNT (>= 10,000)
        try:
            amount_val = float(raw_amount or 0.0)
        except (ValueError, TypeError):
            amount_val = 0.0

        if amount_val >= 10000:
            self._add_indicator(
                indicators, "UPI_UNUSUALLY_HIGH_AMOUNT",
                reason=f"UPI payment requests an unusually high amount (₹{amount_val:,.2f}).",
                evidence=f"₹{amount_val:,.2f}"
            )
        elif amount_val >= 5000:
            self._add_indicator(
                indicators, "UPI_HIGH_AMOUNT",
                reason=f"UPI payment requests a high amount (₹{amount_val:,.2f}).",
                evidence=f"₹{amount_val:,.2f}"
            )

        # 3. UPI_GENERIC_MERCHANT_NAME
        if pn.lower() in self.GENERIC_NAMES:
            self._add_indicator(
                indicators, "UPI_GENERIC_MERCHANT_NAME",
                reason=f"UPI payee name '{pn}' is a generic term frequently used in QR scams.",
                evidence=pn
            )

        # 4. UPI_MISSING_MERCHANT_NAME
        if not pn:
            self._add_indicator(
                indicators, "UPI_MISSING_MERCHANT_NAME",
                reason="UPI merchant/payee name (pn) is missing from payment QR payload.",
                evidence="pn parameter missing"
            )

        # 5. UPI_UNUSUAL_VPA_FORMAT
        if pa.count(".") > 2 or "-" in pa or "malformed_upi_id" in security_indicators:
            self._add_indicator(
                indicators, "UPI_UNUSUAL_VPA_FORMAT",
                reason=f"UPI VPA address '{pa}' contains an unusual format with excess dots or hyphens.",
                evidence=pa
            )

        # 6. UPI_SUSPICIOUS_HANDLE
        vpa_parts = pa.split("@")
        handle = vpa_parts[1].lower() if len(vpa_parts) > 1 else ""
        if any(temp in handle for temp in self.TEMPORARY_HANDLES):
            self._add_indicator(
                indicators, "UPI_SUSPICIOUS_HANDLE",
                reason=f"UPI VPA bank handle '@{handle}' appears temporary or suspicious.",
                evidence=f"@{handle}"
            )

        # 7. UPI_MERCHANT_NAME_MISMATCH (Merchant Consistency Check)
        if pn and len(vpa_parts) > 0:
            vpa_user = vpa_parts[0].lower()
            pn_words = set(re.findall(r"\w+", pn.lower()))
            # If payee name is a specific business name (>= 4 chars) but shares zero letter tokens with VPA user handle
            if len(pn) >= 4 and pn.lower() not in self.GENERIC_NAMES and not any(w in vpa_user for w in pn_words):
                self._add_indicator(
                    indicators, "UPI_MERCHANT_NAME_MISMATCH",
                    reason=f"Payee name '{pn}' shows structural inconsistency with VPA user handle '{vpa_user}'.",
                    evidence=f"pn='{pn}' vs pa='{pa}'"
                )

        # 8. UPI_NON_STANDARD_PARAMS
        raw_params = upi_data.get("raw_params", {})
        if isinstance(raw_params, dict):
            non_standard = set(raw_params.keys()) - self.STANDARD_PARAMS
            if non_standard:
                self._add_indicator(
                    indicators, "UPI_NON_STANDARD_PARAMS",
                    reason=f"UPI payload contains non-standard parameters: {', '.join(non_standard)}.",
                    evidence=", ".join(non_standard)
                )

        return indicators

    def _add_indicator(self, indicators: list, rule_id: str, reason: str, evidence: str):
        rule_meta = self.rules_map.get(rule_id, {})
        if rule_meta.get("enabled", True) is False:
            return

        indicators.append({
            "rule_id": rule_id,
            "category": rule_meta.get("category", "UPI_SECURITY"),
            "severity": rule_meta.get("severity", "MEDIUM"),
            "weight": rule_meta.get("weight", 15),
            "detected": True,
            "reason": reason,
            "evidence": str(evidence)
        })

    def _load_json_config(self, path: str, key: str = None) -> dict:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if key and key in data:
                        return {item["rule_id"]: item for item in data[key]}
                    return data
            except Exception:
                pass
        return {}
