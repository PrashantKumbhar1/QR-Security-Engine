from core.decision_engine import QRDecisionEngine

def run_test():
    engine = QRDecisionEngine()
    result = engine.analyze_qr("tests/sample_qr.png")

    print("=== QR SECURITY ANALYSIS RESULT ===")
    for k, v in result.items():
        print(f"{k}: {v}")

    print("\n--- DECISION TIMELINE ---")
    for step in result.get("decision_timeline", []):
        print(step)



if __name__ == "__main__":
    run_test()
