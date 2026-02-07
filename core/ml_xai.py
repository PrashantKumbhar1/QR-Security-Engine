import shap
import numpy as np


class MLExplainabilityEngine:
    """
    Generates SHAP-based explanations for ML risk predictions
    """

    def __init__(self, model, feature_names: list):
        self.model = model
        self.feature_names = feature_names
        self.explainer = shap.TreeExplainer(model)

    def explain(self, feature_dict: dict) -> dict:
        """
        Returns top contributing features for ML decision
        """

        # Ensure consistent feature order
        feature_vector = np.array(
            [feature_dict[name] for name in self.feature_names]
        ).reshape(1, -1)

        shap_values = self.explainer.shap_values(feature_vector)

        # Binary classification: index 1 = scam class
        contributions = shap_values[1][0]

        explanation = {}

        for name, value in zip(self.feature_names, contributions):
            explanation[name] = round(float(value), 3)

        return explanation
