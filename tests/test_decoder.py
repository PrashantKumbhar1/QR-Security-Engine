from core.decision_engine import QRDecisionEngine

def run_test():
    engine = QRDecisionEngine()
    result = engine.analyze_qr("tests/sample_qr.png")

    print("=== QR SECURITY ANALYSIS RESULT ===")
    for key, value in result.items():
        print(f"{key}: {value}")

    assert "decision" in result
    assert "risk_level" in result

    print("\n[TEST PASSED] Decision and explainability generated successfully.")


if __name__ == "__main__":
    run_test()
