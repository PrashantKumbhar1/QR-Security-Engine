from enum import Enum
import json
import os
from analyzers.url_analyzer import DeepURLAnalyzer
from analyzers.upi_analyzer import DeepUPIAnalyzer


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskIndicator:
    def __init__(self, rule_id: str, category: str, severity: str, weight: int, reason: str, evidence: str = ""):
        self.rule_id = rule_id
        self.category = category
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.weight = weight
        self.reason = reason
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "weight": self.weight,
            "detected": True,
            "reason": self.reason,
            "evidence": self.evidence,

            # Legacy fields for backward compatibility with Phase 1 tests
            "name": self.rule_id.lower(),
            "score": self.weight,
        }


class RiskResult:
    def __init__(self):
        self.score = 0
        self.reasons = []
        self.indicators = []

    def add_indicator_dict(self, ind_dict: dict):
        weight = ind_dict.get("weight", 15)
        reason = ind_dict.get("reason", "")
        self.score = min(100, self.score + weight)
        self.reasons.append(reason)
        self.indicators.append(ind_dict)

    def add_risk(self, points: int, reason: str, name: str = None, severity: str = "MEDIUM"):
        self.score = min(100, self.score + points)
        self.reasons.append(reason)
        rule_id = name.upper() if name else reason.upper().replace(" ", "_")
        ind = RiskIndicator(
            rule_id=rule_id,
            category="SECURITY_INDICATOR",
            severity=severity,
            weight=points,
            reason=reason
        ).to_dict()
        self.indicators.append(ind)

    def level(self) -> RiskLevel:
        if self.score >= 75:
            return RiskLevel.CRITICAL
        elif self.score >= 50:
            return RiskLevel.HIGH
        elif self.score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def to_dict(self) -> dict:
        return {
            "heuristic_score": self.score,
            "risk_level": self.level().value,
            "reasons": self.reasons,
            "indicators": self.indicators
        }


class QRHeuristicRiskEngine:
    """
    Configurable Heuristic Risk Engine utilizing Deep URL & UPI Analyzers.
    """

    def __init__(self, rules_config_path: str = "config/security_rules.json"):
        self.url_analyzer = DeepURLAnalyzer(rules_config_path=rules_config_path)
        self.upi_analyzer = DeepUPIAnalyzer(rules_config_path=rules_config_path)

    def evaluate_upi(self, upi_data: dict) -> RiskResult:
        """
        Applies deep heuristic security rules to parsed UPI payment data.
        """
        result = RiskResult()
        raw_indicators = self.upi_analyzer.analyze(upi_data)

        for ind in raw_indicators:
            result.add_indicator_dict(ind)

        return result

    def evaluate_url(self, url: str) -> RiskResult:
        """
        Applies deep heuristic security rules to URL-based QR codes.
        """
        result = RiskResult()
        raw_indicators = self.url_analyzer.analyze(url)

        for ind in raw_indicators:
            result.add_indicator_dict(ind)

        return result


