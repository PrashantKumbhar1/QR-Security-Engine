# QR Security Engine — Risk Fusion Engine Specification

**Date**: August 9, 2026  
**Version**: 4.0  
**Module**: `core/risk_fusion.py`  
**Configuration**: `config/risk_fusion.json`

---

## 1. Executive Summary

The Risk Fusion Engine (`core/risk_fusion.py`) mathematically synthesizes statistical Machine Learning risk predictions ($P_{\text{ML}} \in [0.0, 1.0]$) and normalized Heuristic security scores ($S_{\text{heur}} \in [0, 100]$) into a single, coherent **Final Risk Score** ($S_{\text{final}} \in [0, 100]$).

It implements **Method 3: Hybrid Linear Fusion with Critical Floor Overrides**, combining mathematical weighting with defensive security guarantees.

---

## 2. Mathematical Fusion Model

### Step 1: Linear Fusion Computation
For a given payload type (URL or UPI), the linear fusion score $S_{\text{linear}}$ is calculated as:

$$S_{\text{linear}} = \alpha \cdot (100 \cdot P_{\text{ML}}) + (1 - \alpha) \cdot S_{\text{heur}}$$

Where:
* $P_{\text{ML}}$ is the ML model prediction probability ($0.0 \le P_{\text{ML}} \le 1.0$).
* $S_{\text{heur}}$ is the normalized heuristic score ($0 \le S_{\text{heur}} \le 100$).
* $\alpha$ is the payload-specific ML weight defined in `config/risk_fusion.json`.

If ML inference is unavailable ($P_{\text{ML}} = \text{None}$), the engine safely falls back to $S_{\text{linear}} = S_{\text{heur}}$.

---

### Step 2: Critical Floor Override Check
To ensure severe, deterministic threats (such as credential harvesting `@` symbols or embedded phishing links in payment QR codes) cannot be improperly downgraded by a statistical ML model, an explicit security floor is enforced:

$$S_{\text{floor}} = \begin{cases} 75 & \text{if any detected indicator has } \text{severity} = \text{"CRITICAL"} \\ 0 & \text{otherwise} \end{cases}$$

$$S_{\text{fused}} = \max\left(S_{\text{linear}}, S_{\text{floor}}\right)$$

---

### Step 3: Bounding & Integer Rounding
$$\text{Final Risk Score} = \min\left(100, \max\left(0, \text{round}(S_{\text{fused}})\right)\right)$$

---

## 3. Configurable Payload Weightings

The weights $\alpha$ and $(1 - \alpha)$ are configured in `config/risk_fusion.json`:

| Payload Type | ML Weight ($\alpha$) | Heuristic Weight ($1 - \alpha$) | Justification |
| :--- | :---: | :---: | :--- |
| **URL Payload** | **0.60** (60%) | **0.40** (40%) | Trained on 5,000 real-world URLs from UCI PhiUSIIL benchmark ($F1 = 0.9958$). Statistical ML generalizes strongly on lexical features. |
| **UPI Payload** | **0.40** (40%) | **0.60** (60%) | Trained on synthetic data (`SYNTHETIC_UPI_V1`). Deterministic structural heuristic rules carry higher authority in financial payment transactions. |
| **Default / Text** | **0.50** (50%) | **0.50** (50%) | Balanced fallback weighting for unclassified payloads. |

---

## 4. Final Risk Levels & Decision Policy

The fused `final_risk_score` is mapped to standardized risk levels and decision actions:

| Fused Score Range | Risk Level | Action Decision | User Security Guidance |
| :--- | :---: | :---: | :--- |
| **`0 – 24`** | **`LOW`** | `ALLOW` | You may safely proceed with this payment or link. |
| **`25 – 49`** | **`MEDIUM`** | `WARN` | Proceed only if you trust the source of this QR code. |
| **`50 – 74`** | **`HIGH`** | `BLOCK` | Do not proceed with the payment or link. This QR is likely unsafe. |
| **`75 – 100`** | **`CRITICAL`** | `BLOCK` | Do not proceed. Severe malicious threat detected. |

---

## 5. Output Schema & Naming Integrity

* **`ml_probability`**: Raw ML probability (`0.0–1.0`)
* **`heuristic_score`**: Raw heuristic score (`0–100`)
* **`final_risk_score`**: Fused risk score (`0–100`)
* **`fusion_metadata`**: Object containing `fusion_method`, `ml_weight`, `heuristic_weight`, `linear_score`, and `floor_applied`.

> **Probability Naming Policy**: The fused output is explicitly named **`final_risk_score`**, not "fraud probability", because fusing heuristics with probabilities yields a composite security index rather than a calibrated statistical probability.
