from core.decision_engine import QRDecisionEngine

engine = QRDecisionEngine()

result = engine.analyze_qr("tests/sample_qr.png")
print(result)
