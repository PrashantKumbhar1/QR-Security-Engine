from functools import lru_cache
from core.decision_engine import QRDecisionEngine


@lru_cache()
def get_decision_engine() -> QRDecisionEngine:
    """
    Dependency provider for singleton QRDecisionEngine instance.
    """
    return QRDecisionEngine()
