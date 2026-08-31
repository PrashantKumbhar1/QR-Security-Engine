# QR Security Engine — Deep UPI Security Analyzer Specification

**Date**: August 9, 2026  
**Module**: `analyzers/upi_analyzer.py`  
**Config**: `config/security_rules.json`

---

## 1. Overview

The Deep UPI Security Analyzer (`analyzers/upi_analyzer.py`) inspects Indian Unified Payments Interface (`upi://pay`) QR payloads for payment fraud, merchant spoofing, amount anomalies, and embedded external phishing links.

---

## 2. Security Rules & Indicators

### A. Embedded Payload Rules
* **`UPI_EMBEDDED_EXTERNAL_URL`** (`CRITICAL`, 50 pts): Triggers if an external `http://` or `https://` link is embedded inside query parameters (redirect scam).

### B. Payment Amount Rules
* **`UPI_UNUSUALLY_HIGH_AMOUNT`** (`HIGH`, 30 pts): Triggers if requested amount >= ₹10,000.
* **`UPI_HIGH_AMOUNT`** (`HIGH`, 25 pts): Triggers if requested amount >= ₹5,000.

### C. Merchant Identification & Consistency Rules
* **`UPI_GENERIC_MERCHANT_NAME`** (`MEDIUM`, 20 pts): Triggers if payee name is a generic scam keyword (`payment`, `upi`, `pay`, `merchant`, `store`, `cash`, `account`, `transfer`, `help`).
* **`UPI_MISSING_MERCHANT_NAME`** (`MEDIUM`, 15 pts): Triggers if payee name (`pn`) parameter is missing or empty.
* **`UPI_MERCHANT_NAME_MISMATCH`** (`MEDIUM`, 15 pts): Consistency check evaluating structural token match between payee name (`pn`) and VPA user handle (`pa`).

### D. VPA Address Rules
* **`UPI_UNUSUAL_VPA_FORMAT`** (`MEDIUM`, 15 pts): Triggers if VPA contains excess dots (`>2`) or hyphens.
* **`UPI_SUSPICIOUS_HANDLE`** (`MEDIUM`, 15 pts): Triggers if bank handle after `@` uses a temporary or suspicious domain.
* **`UPI_NON_STANDARD_PARAMS`** (`LOW`, 10 pts): Triggers if payload contains non-standard query parameters.

---

## 3. Merchant Consistency Safeguards

1. **No Absolute Identity Claims**: The engine evaluates structural token overlap between VPA handle and payee name. It does not claim authoritative merchant identity without a verified bank registry API.
2. **Unfamiliar VPAs**: Unfamiliar VPAs are not labeled fraudulent; indicators require explicit structural anomalies or generic fraud patterns.
