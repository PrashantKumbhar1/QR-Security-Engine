from datetime import datetime


class DecisionTimeline:
    """
    Records step-by-step security decisions for replay and investigation
    """

    def __init__(self):
        self.steps = []

    def add_step(self, stage: str, description: str, outcome: str = None):
        self.steps.append({
            "timestamp": datetime.utcnow().isoformat(),
            "stage": stage,
            "description": description,
            "outcome": outcome
        })

    def export(self) -> list:
        return self.steps
