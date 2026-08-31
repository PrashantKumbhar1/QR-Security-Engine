import requests
import pandas as pd
import io
import os

print("=== MILESTONE 2A: AUDITING PUBLIC PHISHING URL DATASET ===")

url = "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv"
headers = {'User-Agent': 'Mozilla/5.0'}

print(f"Fetching dataset from source: {url}")
res = requests.get(url, headers=headers, timeout=30)
res.raise_for_status()

content = res.content.decode('utf-8-sig', errors='ignore')
df_full = pd.read_csv(io.StringIO(content))

print("\n--- DATASET METADATA & SUMMARY ---")
print(f"Dataset Name: PhiUSIIL Phishing URL Dataset (UCI ML ID: 967 / GitHub Benchmark Mirror)")
print(f"Official Source URL: {url}")
print(f"Total Rows Downloaded: {len(df_full)}")
print(f"Total Columns: {len(df_full.columns)}")
print(f"Raw URL Column Present: {'URL' in df_full.columns} (Column name: 'URL')")
print(f"Label Column Present: {'label' in df_full.columns} (Column name: 'label')")

# Inspect labels
label_counts = df_full['label'].value_counts().to_dict()
print(f"\nRaw Class Distribution (label column): {label_counts}")
print(f"  - Legitimate (label=1): {label_counts.get(1, 0)}")
print(f"  - Phishing (label=0):   {label_counts.get(0, 0)}")

# Check missing values
missing_urls = df_full['URL'].isnull().sum()
missing_labels = df_full['label'].isnull().sum()
print(f"\nMissing Values:")
print(f"  - Null URLs:   {missing_urls}")
print(f"  - Null Labels: {missing_labels}")

# Check exact duplicate URLs
duplicate_urls = df_full.duplicated(subset=['URL']).sum()
print(f"  - Duplicate Raw URLs: {duplicate_urls}")

# Save a clean 5,000-sample balanced subset (2,500 benign, 2,500 phishing) for local reproducibility & fast training
os.makedirs("data", exist_ok=True)
df_clean = df_full[['URL', 'label']].dropna().drop_duplicates(subset=['URL'])
df_benign = df_clean[df_clean['label'] == 1].sample(n=2500, random_state=42)
df_phish = df_clean[df_clean['label'] == 0].sample(n=2500, random_state=42)
df_balanced = pd.concat([df_benign, df_phish]).sample(frac=1.0, random_state=42).reset_index(drop=True)

df_balanced.to_csv("data/urls_dataset.csv", index=False)
print(f"\nSaved clean balanced evaluation dataset to 'data/urls_dataset.csv':")
print(f"  - Total Samples: {len(df_balanced)}")
print(f"  - Legitimate (1): {(df_balanced['label'] == 1).sum()}")
print(f"  - Phishing (0):   {(df_balanced['label'] == 0).sum()}")

print("\n=== MILESTONE 2A AUDIT COMPLETE ===")
