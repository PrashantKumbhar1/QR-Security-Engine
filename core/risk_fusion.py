import json
import os


class QRRiskFusionEngine:
    """
    Risk Fusion Engine: Mathematically combines ML Risk Probability (0.0–1.0)
    and Heuristic Risk Score (0–100) into a single Final Risk Score (0–100)
    using Hybrid Linear Fusion with Critical Floor Overrides.
    """

    def __init__(self, config_path: str = "config/risk_fusion.json"):
        self.config_path = config_path
        self.config = self._load_config()

    def fuse(self, payload_type: str, ml_probability: float, heuristic_score: int, indicators: list) -> dict:
        """
        Fuses ML probability and Heuristic score based on payload type and detected indicators.

        Args:
            payload_type (str): "URL", "UPI_PAYMENT", "TEXT", etc.
            ml_probability (float or None): ML model probability (0.0 to 1.0)
            heuristic_score (int): Normalized heuristic score (0 to 100)
            indicators (list): List of detected RiskIndicator dictionaries

        Returns:
            dict: Structured fusion result containing final_risk_score, risk_level, decision, and metadata.
        """
        p_type_key = "url" if payload_type == "URL" else ("upi" if "UPI" in payload_type else "default")
        weights = self.config.get(p_type_key, {"ml_weight": 0.50, "heuristic_weight": 0.50})

        w_ml = weights.get("ml_weight", 0.50)
        w_heur = weights.get("heuristic_weight", 0.50)

        # 1. Linear Fusion Computation
        if ml_probability is not None:
            ml_score_scale = float(ml_probability) * 100.0
            linear_score = (w_ml * ml_score_scale) + (w_heur * float(heuristic_score))
        else:
            # Fallback to heuristic score if ML is unavailable
            linear_score = float(heuristic_score)
            w_ml = 0.0
            w_heur = 1.0

        # 2. Critical Rule Floor Override Check
        critical_floor = self.config.get("critical_floor_score", 75)
        has_critical_indicator = any(
            isinstance(ind, dict) and ind.get("severity") == "CRITICAL" for ind in indicators
        )

        floor_applied = False
        if has_critical_indicator:
            floor_score = float(critical_floor)
            if floor_score > linear_score:
                final_score = floor_score
                floor_applied = True
            else:
                final_score = linear_score
        else:
            final_score = linear_score

        # Bound final score between 0 and 100
        final_risk_score = min(100, max(0, int(round(final_score))))

        # 3. Final Risk Level Mapping
        risk_level = self._map_risk_level(final_risk_score)

        # 4. Final Decision Mapping
        decision = self._map_decision(risk_level)

        return {
            "final_risk_score": final_risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "fusion_metadata": {
                "fusion_method": self.config.get("fusion_method", "hybrid_linear_critical_floor"),
                "payload_type": payload_type,
                "ml_weight": round(w_ml, 2),
                "heuristic_weight": round(w_heur, 2),
                "linear_score": round(linear_score, 2),
                "floor_applied": floor_applied,
                "ml_probability": ml_probability,
                "heuristic_score": heuristic_score
            }
        }

    def _map_risk_level(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        return "LOW"

    def _map_decision(self, risk_level: str) -> str:
        if risk_level in ["HIGH", "CRITICAL"]:
            return "BLOCK"
        elif risk_level == "MEDIUM":
            return "WARN"
        return "ALLOW"

    def _load_config(self) -> dict:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "fusion_method": "hybrid_linear_critical_floor",
            "url": {"ml_weight": 0.60, "heuristic_weight": 0.40},
            "upi": {"ml_weight": 0.40, "heuristic_weight": 0.60},
            "default": {"ml_weight": 0.50, "heuristic_weight": 0.50},
            "critical_floor_score": 75
        }
