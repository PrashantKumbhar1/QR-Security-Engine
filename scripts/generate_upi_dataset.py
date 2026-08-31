import random
import os
import pandas as pd
from core.feature_extractor import QRFeatureExtractor

print("=== MILESTONE 2C: GENERATING CONTROLLED SYNTHETIC UPI DATASET ===")
random.seed(42)

extractor = QRFeatureExtractor()
rows = []

# Benign merchants / users (500 samples)
legit_banks = ["okicici", "okhdfcbank", "oksbi", "paytm", "apl", "ybl", "icici", "axisbank"]
legit_names = ["Coffee House", "Sharma Grocery", "City Electronics", "Metro Station Kiosk", "Rahul Verma", "Priya Patel", "Book World", "Fresh Fruits"]

for i in range(500):
    handle = random.choice(legit_banks)
    user_part = f"user{i+100}" if random.random() > 0.6 else random.choice(["store", "shop", "pay", "billing"]) + str(i+10)
    vpa = f"{user_part}@{handle}"
    name = random.choice(legit_names)
    amount = round(random.uniform(10, 1500), 2) if random.random() > 0.2 else None
    
    upi_data = {
        "payee_address": vpa,
        "payee_name": name,
        "amount": amount,
        "raw_payload": f"upi://pay?pa={vpa}&pn={name}&am={amount if amount else ''}&cu=INR",
        "embedded_urls": [],
        "security_indicators": []
    }
    
    features = extractor.extract_upi_features(upi_data)
    features["dataset_source"] = "SYNTHETIC_UPI_V1"
    features["label"] = 1  # Benign
    rows.append(features)

# Scam / anomalous transactions (500 samples)
scam_banks = ["scambank", "fake", "temp", "verify", "claim", "win"]
scam_names = ["", "payment", "upi", "pay", "merchant", "store", "cash", "account"]

for i in range(500):
    scam_type = random.choice(["overpayment", "missing_name", "generic_name", "embedded_url", "malformed_vpa"])
    
    if scam_type == "overpayment":
        vpa = f"collect{i}@okicici"
        name = "FastPay"
        amount = round(random.uniform(5000, 25000), 2)
        urls = []
        indicators = []
    elif scam_type == "missing_name":
        vpa = f"pay.{i}.ref@bank"
        name = ""
        amount = round(random.uniform(100, 2000), 2)
        urls = []
        indicators = ["missing_merchant_name"]
    elif scam_type == "generic_name":
        vpa = f"support.{i}@upi"
        name = random.choice(scam_names)
        amount = round(random.uniform(500, 5000), 2)
        urls = []
        indicators = []
    elif scam_type == "embedded_url":
        vpa = f"claim{i}@bank"
        name = "Prize Claim"
        amount = 0.0
        urls = ["http://phishing-claim.site/verify"]
        indicators = ["embedded_external_url"]
    else:  # malformed_vpa
        vpa = f"user.ref.id.{i}-sub@fakebank"
        name = "Support"
        amount = round(random.uniform(500, 8000), 2)
        urls = []
        indicators = ["malformed_upi_id"]

    raw = f"upi://pay?pa={vpa}&pn={name}&am={amount}&cu=INR"
    if urls:
        raw += f"&url={urls[0]}"

    upi_data = {
        "payee_address": vpa,
        "payee_name": name,
        "amount": amount,
        "raw_payload": raw,
        "embedded_urls": urls,
        "security_indicators": indicators
    }

    features = extractor.extract_upi_features(upi_data)
    features["dataset_source"] = "SYNTHETIC_UPI_V1"
    features["label"] = 0  # Scam / Malicious
    rows.append(features)

df_upi = pd.DataFrame(rows)
os.makedirs("data", exist_ok=True)
df_upi.to_csv("data/upi_synthetic_dataset.csv", index=False)

print(f"Generated 'data/upi_synthetic_dataset.csv':")
print(f"  - Total Synthetic Samples: {len(df_upi)}")
print(f"  - Benign (1): {(df_upi['label'] == 1).sum()}")
print(f"  - Scam (0):   {(df_upi['label'] == 0).sum()}")
print(f"  - Dataset Source Label: 'SYNTHETIC_UPI_V1'")
print("=== MILESTONE 2C COMPLETE ===")
