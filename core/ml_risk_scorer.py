import joblib
import os


class MLRiskScorer:
    """
    Loads a trained ML model and performs risk inference
    """

    def __init__(self, model_path: str = "model/qr_risk_model.pkl"):
        self.model = None
        self.model_path = model_path

        if os.path.exists(model_path):
            self.model = joblib.load(model_path)

    def is_model_loaded(self) -> bool:
        return self.model is not None

    def predict_risk(self, features: dict) -> dict:
        """
        Predicts scam probability using ML model

        Args:
            features (dict): ML feature vector

        Returns:
            dict: risk_probability and raw score
        """

        if not self.model:
            return {
                "risk_probability": None,
                "model_used": False
            }

        # Keep feature order consistent
        feature_values = [features[key] for key in sorted(features.keys())]

        probability = self.model.predict_proba([feature_values])[0][1]

        return {
            "risk_probability": round(float(probability), 3),
            "model_used": True
        }
