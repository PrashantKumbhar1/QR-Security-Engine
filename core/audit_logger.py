import json
from datetime import datetime
from pathlib import Path


class QRAuditLogger:
    """
    Records security decisions for traceability and compliance
    """

    def __init__(self, log_file: str = "logs/qr_audit.log"):
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, decision_result: dict):
        """
        Append a security decision to the audit log
        """

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "decision": decision_result.get("decision"),
            "risk_level": decision_result.get("risk_level"),
            "summary": decision_result.get("summary"),
            "reasons": decision_result.get("why_dangerous", []),
        }

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
