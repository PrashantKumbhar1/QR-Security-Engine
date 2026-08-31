# QR Security Engine — Risk Scoring & Threshold Methodology

**Date**: August 9, 2026  
**Version**: 3.0  
**Module**: `core/risk_engine.py`

---

## 1. Overview

The QR Security Engine calculates a deterministic, normalized **0–100 Heuristic Risk Score** based on weighted security indicators evaluated by the Deep URL Analyzer (`analyzers/url_analyzer.py`) and Deep UPI Analyzer (`analyzers/upi_analyzer.py`).

---

## 2. Mathematical Scoring Pipeline

```text
Raw Rule Detection (rule_id, severity, weight)
                       ↓
Summation: Raw Score = Σ weight_i for all detected rules
                       ↓
Score Normalization: Heuristic Score = min(100, Raw Score)
                       ↓
Threshold Mapping → Risk Level (LOW, MEDIUM, HIGH, CRITICAL)
```

### Mathematical Formula
$$\text{Raw Score} = \sum_{i \in \text{Detected}} w_i$$
$$\text{Heuristic Risk Score} = \min\left(100, \sum_{i \in \text{Detected}} w_i\right)$$

Where $w_i$ represents the rule weight defined in `config/security_rules.json`.

---

## 3. Severity Weighting Matrix

Rules are grouped into four standardized severity tiers based on defensive security impact:

| Severity Tier | Weight Range | Defensive Meaning |
| :--- | :---: | :--- |
| **`LOW`** | 5 – 10 points | Informational signal or minor structural anomaly. |
| **`MEDIUM`** | 15 – 20 points | Noticeable security warning indicator; warrants user caution. |
| **`HIGH`** | 25 – 35 points | Strong threat indicator; high probability of malicious intent. |
| **`CRITICAL`** | 40 – 50 points | Severe malicious threat (e.g. Punycode spoofing, embedded external phishing URL in payment QR). |

---

## 4. Configurable Risk Thresholds

| Score Range | Risk Level | Action Decision | User Guidance |
| :--- | :---: | :---: | :--- |
| **`0 – 24`** | **`LOW`** | `ALLOW` | Safe payload based on current security checks. |
| **`25 – 49`** | **`MEDIUM`** | `WARN` | Warning signs present; user caution advised before proceeding. |
| **`50 – 74`** | **`HIGH`** | `BLOCK` | Strong threat indicators detected; block by default. |
| **`75 – 100`** | **`CRITICAL`** | `BLOCK` | Severe malicious threat detected; strict block. |

---

## 5. Separation of Heuristic & ML Scores

In Phase 3, **Heuristic Risk Score** (`0–100`) and **ML Risk Probability** (`0.0–1.0`) are calculated and reported as **independent risk vectors**:

* `heuristic_score`: Deterministic rule-based score (`0–100`).
* `ml_risk_probability`: Statistical ML model prediction probability (`0.0–1.0`).

> **Note**: Risk Fusion combining ML and Heuristic scores into a single unified score will be implemented in **Phase 4**.
