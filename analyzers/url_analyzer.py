import json
import os
import re
from urllib.parse import urlparse, parse_qs


class DeepURLAnalyzer:
    """
    Modular Deep URL Security Analyzer.
    Evaluates URL structure, hostname, obfuscation, path, and protocol indicators.
    """

    SENSITIVE_KEYWORDS = {
        "login", "signin", "verify", "verification", "account", "banking", "bank",
        "update", "security", "credential", "password", "wallet", "paypal", "secure",
        "confirm", "authenticate", "billing", "service-update"
    }

    def __init__(self, rules_config_path: str = "config/security_rules.json",
                 tld_config_path: str = "config/tld_risk.json",
                 shortener_config_path: str = "config/url_shorteners.json"):
        self.rules_map = self._load_json_config(rules_config_path, "rules")
        self.tld_config = self._load_json_config(tld_config_path)
        self.shortener_config = self._load_json_config(shortener_config_path)

        self.high_risk_tlds = set(self.tld_config.get("high_risk_tlds", [
            "top", "xyz", "zip", "work", "click", "cc", "tk", "ml", "ga", "gq"
        ]))
        self.shorteners = set(self.shortener_config.get("shortener_domains", [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"
        ]))

    def analyze(self, url: str) -> list:
        """
        Analyzes a URL string and returns a list of detected RiskIndicator dictionaries.
        """
        indicators = []
        if not url or not isinstance(url, str):
            return indicators

        cleaned = url.strip()
        url_lower = cleaned.lower()
        parsed = urlparse(cleaned)
        domain = (parsed.hostname or parsed.netloc.split(":")[0]).lower()

        path = parsed.path
        query = parsed.query

        # 1. URL_USERINFO_SPOOFING (@ symbol)
        if "@" in cleaned:
            self._add_indicator(
                indicators, "URL_USERINFO_SPOOFING",
                reason="URL contains an '@' symbol used for credential spoofing.",
                evidence=cleaned
            )

        # 2. URL_PUNYCODE_HOST (xn--)
        if "xn--" in domain:
            self._add_indicator(
                indicators, "URL_PUNYCODE_HOST",
                reason="Hostname uses Punycode (xn--) indicating potential homograph attack.",
                evidence=domain
            )

        # 3. URL_IP_HOST (IP address)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            self._add_indicator(
                indicators, "URL_IP_HOST",
                reason="URL uses an IP address instead of a domain name.",
                evidence=domain
            )

        # 4. URL_SHORTENER_DETECTED
        if domain in self.shorteners or any(s in url_lower for s in ["bit.ly/", "tinyurl.com/", "t.co/"]):
            self._add_indicator(
                indicators, "URL_SHORTENER_DETECTED",
                reason="URL uses a known link shortening service hiding actual destination.",
                evidence=domain
            )

        # 5. URL_DOUBLE_SLASH_PATH
        if "//" in path:
            self._add_indicator(
                indicators, "URL_DOUBLE_SLASH_PATH",
                reason="URL path contains double slashes (//) used for redirection tricks.",
                evidence=path
            )

        # 6. URL_SUSPICIOUS_TLD
        domain_parts = [p for p in domain.split(".") if p]
        tld = domain_parts[-1] if domain_parts else ""
        if tld in self.high_risk_tlds:
            self._add_indicator(
                indicators, "URL_SUSPICIOUS_TLD",
                reason=f"URL uses high-risk top-level domain '.{tld}'.",
                evidence=f".{tld}"
            )

        # 7. URL_SENSITIVE_KEYWORDS
        found_keywords = [kw for kw in self.SENSITIVE_KEYWORDS if kw in path.lower() or kw in query.lower()]
        if found_keywords:
            self._add_indicator(
                indicators, "URL_SENSITIVE_KEYWORDS",
                reason=f"URL contains sensitive security keywords: {', '.join(found_keywords)}.",
                evidence=", ".join(found_keywords)
            )

        # 8. URL_NON_SECURE_HTTP
        if parsed.scheme.lower() == "http":
            self._add_indicator(
                indicators, "URL_NON_SECURE_HTTP",
                reason="URL uses non-secure HTTP protocol instead of HTTPS.",
                evidence="http://"
            )

        # 9. URL_HEX_ENCODED_PATH
        hex_matches = re.findall(r"%[0-9a-fA-F]{2}", path)
        if len(hex_matches) >= 2:
            self._add_indicator(
                indicators, "URL_HEX_ENCODED_PATH",
                reason="URL path contains percent-encoded hex characters.",
                evidence=f"Count: {len(hex_matches)}"
            )

        # 10. URL_EXCESSIVE_SUBDOMAINS
        subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0
        if subdomain_count >= 3:
            self._add_indicator(
                indicators, "URL_EXCESSIVE_SUBDOMAINS",
                reason=f"Hostname contains {subdomain_count} subdomain levels.",
                evidence=domain
            )

        # 11. URL_EXCESSIVE_LENGTH
        if len(cleaned) > 75:
            self._add_indicator(
                indicators, "URL_EXCESSIVE_LENGTH",
                reason=f"URL length ({len(cleaned)} chars) exceeds standard length threshold.",
                evidence=f"Length: {len(cleaned)}"
            )

        return indicators

    def _add_indicator(self, indicators: list, rule_id: str, reason: str, evidence: str):
        rule_meta = self.rules_map.get(rule_id, {})
        if rule_meta.get("enabled", True) is False:
            return

        indicators.append({
            "rule_id": rule_id,
            "category": rule_meta.get("category", "URL_SECURITY"),
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
