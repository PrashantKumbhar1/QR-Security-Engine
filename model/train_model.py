import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


def load_data():
    """
    Generates a small synthetic dataset for QR scam detection
    """
    data = [
        # amount, merchant_missing, merchant_len, upi_len, generic_name, label
        [6000, 1, 0, 8, 0, 1],   # scam-like
        [5000, 1, 0, 10, 1, 1],
        [8000, 1, 0, 12, 0, 1],
        [200, 0, 10, 8, 0, 0],  # benign
        [150, 0, 12, 9, 0, 0],
        [300, 0, 8, 10, 0, 0],
        [4000, 1, 0, 8, 0, 1],
        [100, 0, 15, 7, 0, 0],
        [7000, 1, 0, 9, 1, 1],
        [250, 0, 11, 8, 0, 0],
    ]

    columns = [
        "amount",
        "merchant_name_missing",
        "merchant_name_length",
        "upi_id_length",
        "generic_merchant_name",
        "label"
    ]

    return pd.DataFrame(data, columns=columns)


def train():
    df = load_data()

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X_train, y_train)

    print("=== MODEL EVALUATION ===")
    print(classification_report(y_test, model.predict(X_test)))

    joblib.dump(model, "model/qr_risk_model.pkl")
    print("Model saved as model/qr_risk_model.pkl")


if __name__ == "__main__":
    train()
