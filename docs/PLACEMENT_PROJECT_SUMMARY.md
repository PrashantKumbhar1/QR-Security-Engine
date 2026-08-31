# QR Security Engine — Placement Project Summary & Interview Guide

**Date**: August 9, 2026  
**Version**: 5.0  

---

## 1. Project Overview

* **Project Title**: QR Security Engine — AI-Assisted QR Code Threat Detection & Risk Analysis System
* **One-Line Description**: An end-to-end multi-stage cybersecurity system that inspects QR code payloads (URLs, UPI payment codes, and plain text) for phishing attacks, financial payment fraud, URL obfuscation, and brand impersonation.
* **Problem Statement**: QR codes are increasingly exploited for Quishing (QR Phishing) and UPI payment fraud because traditional security filters scan text links rather than embedded QR images. The QR Security Engine provides multi-stage passive security analysis before user navigation or financial execution.

---

## 2. Technical Architecture & Component Breakdown

```text
QR IMAGE ──► QR DECODER ──► CLASSIFIER ──► FEATURE EXTRACTOR ──► ANALYZERS & DUAL ML ──► RISK FUSION ──► EXPLAINABILITY ──► FASTAPI ──► WEB UI
```

* **Core Engine**: PyZbar & OpenCV QR decoding, regex payload classification (URL, UPI, TEXT), Schema v2.0 deterministic feature extraction (15 URL / 13 UPI features).
* **Deep Security Analyzers**: 20 JSON-configured security rules covering `@` credential spoofing, Punycode `xn--` homograph attacks, IP hostnames, known shorteners (`bit.ly`, `tinyurl`), `%XX` hex encoding, `//` path slashes, high-risk TLDs (`.top`, `.xyz`), UPI embedded URLs, and merchant name mismatches.
* **Dual Machine Learning Models**:
  * **URL Model (`qr_url_model.pkl`)**: Random Forest Classifier trained on 5,000 real-world benchmark URLs from UCI Dataset ID 967 ($F1 = 0.9960$, $ROC\text{-}AUC = 0.9986$). Tested under 0% domain overlap ($F1 = 0.9958$).
  * **UPI Model (`qr_upi_model.pkl`)**: Logistic Regression Model trained on 1,000 synthetic UPI anomaly samples (`SYNTHETIC_UPI_V1`).
* **Hybrid Risk Fusion Engine**: Fuses ML probability ($P_{\text{ML}}$) and Heuristic score ($S_{\text{heur}}$) with payload-specific weights ($\alpha_{\text{URL}} = 0.60$, $\alpha_{\text{UPI}} = 0.40$) and a 75-point `CRITICAL` floor override.
* **FastAPI Backend Service**: REST API (`POST /scan`, `GET /health`, `GET /version`) with 5 MB file size limits, MIME validation, and OpenAPI documentation.
* **Web Dashboard**: HTML5, Vanilla CSS3, and Vanilla JS ES modules frontend featuring Drag & Drop upload, live camera QR scanner, SVG risk gauge, signal breakdown, threat indicator cards, 7-stage timeline, and executive security recommendations.

---

## 3. Actual Verified Metrics

* **Automated Tests**: **48 Passed / 0 Failed / 0 Warnings**
* **URL Model Test Metrics (1,000 Test Samples)**: Precision `0.9921`, Recall `1.0000`, F1 `0.9960`, ROC-AUC `0.9986`.
* **Zero Domain-Overlap URL F1-Score**: `0.9958`
* **Average API Response Time**: **~55 ms**

---

## 4. Interview Preparation Guide

### 60-Second Elevator Pitch
> *"QR codes are increasingly exploited for Quishing (QR Phishing) and UPI payment fraud because traditional security filters only scan text links. I built the **QR Security Engine**, an AI-assisted threat analysis system that passively inspects QR code payloads before navigation or payment execution. It classifies payloads into URLs or UPI codes, extracts deterministic features, and evaluates them through 20 deep security rules—like `@` credential spoofing, Punycode homograph attacks, and embedded phishing links. It feeds these features into specialized ML models—a Random Forest URL classifier trained on 5,000 real-world benchmark URLs and a UPI Logistic Regression model. Finally, my Hybrid Risk Fusion Engine combines ML probabilities and heuristic scores with a critical security floor override to generate a fused 0–100 risk score, complete with structured explanations. The system is delivered via FastAPI and a dark cybersecurity web dashboard, backed by 48 passing automated tests."*

### 2-Minute Technical Deep Dive
> *"When designing the QR Security Engine, my primary architectural goal was to combine statistical machine learning generalization with deterministic defensive security guarantees.
>
> 1. **Pipeline Architecture**: The engine receives a QR image via FastAPI, decodes it using OpenCV/PyZbar, and classifies the payload into URL, UPI Payment, or Text.
> 2. **Feature Extraction**: I established Schema v2.0 contracts—extracting 15 structural URL features (such as subdomain depth, percent-encoded hex sequences, and IP host flags) and 13 UPI features (such as amount anomalies, merchant name missingness, and VPA vs payee name token mismatches).
> 3. **Dual ML Models & Validation**: For URLs, I trained a Random Forest Classifier on 5,000 balanced raw URLs from the UCI PhiUSIIL dataset. To ensure the $F1 = 0.9960$ score wasn't inflated by domain memorization, I ran a zero-domain-overlap validation gate using `GroupShuffleSplit`, which confirmed an $F1 = 0.9958$ on completely unseen domains.
> 4. **Deep Security Analyzers**: I built modular analyzers evaluating 20 JSON-configured security rules, incorporating configurable high-risk TLD registries and known URL shorteners.
> 5. **Hybrid Risk Fusion Engine**: Rather than naively averaging scores or mislabeling fused scores as 'probabilities', I implemented a hybrid linear model: $S_{\text{linear}} = \alpha \cdot (100 \cdot P_{\text{ML}}) + (1 - \alpha) \cdot S_{\text{heur}}$, using $\alpha_{\text{URL}} = 0.60$ and $\alpha_{\text{UPI}} = 0.40$. Crucially, if any `CRITICAL` indicator is detected—like a credential spoofing `@` symbol or an embedded phishing link—an explicit security floor ($S_{\text{floor}} = 75$) overrides the linear score to guarantee a `BLOCK` decision.
> 6. **FastAPI & UI**: The backend exposes REST endpoints (`POST /scan`, `GET /health`, `GET /version`) enforcing MIME checks and 5 MB limits, while serving a responsive glassmorphic dashboard in HTML5/CSS3/Vanilla JS."*

---

## 5. Top 10 Technical Interview Questions & Answers

#### Q1: Why did you build separate ML models for URL and UPI payloads instead of one combined model?
> **Answer**: URL phishing and UPI payment fraud rely on fundamentally different feature spaces. URL threats depend on domain structure, TLD risk, path encoding, and protocol schemes (15 features), whereas UPI threats depend on payment amounts, payee address structure, merchant consistency, and embedded parameter links (13 features). Forcing both into a single sparse vector would dilute decision boundaries and degrade model explainability.

#### Q2: How did you prevent domain memorization / data leakage during ML model evaluation?
> **Answer**: I conducted a Phase 2 Validation Gate. In addition to standard 80/20 stratified splitting, I evaluated the URL Random Forest model using `GroupShuffleSplit` by registered domain. This ensured 0% overlap of domain names between training and test sets. The model achieved $F1 = 0.9958$ on zero-overlap domains (vs $F1 = 0.9960$ on stratified split), proving it learned structural lexical patterns rather than memorizing domain strings.

#### Q3: Why didn't you label the final fused score as a "fraud probability"?
> **Answer**: Probability has a strict mathematical definition representing the likelihood of an outcome under a calibrated distribution. Fusing a statistical model probability with a rule-based heuristic score creates a composite security risk index ($0–100$), not a calibrated statistical probability. Calling it a 'probability' would be mathematically misleading. Therefore, I explicitly named it `final_risk_score`.

#### Q4: What is the Critical Floor Override in your Risk Fusion Engine?
> **Answer**: In cybersecurity, high-severity deterministic indicators (like an `@` credential spoofing symbol or an embedded phishing URL in a payment code) represent definitive attack vectors. If an ML model predicts a low probability due to a novel domain pattern, a simple linear average might falsely downgrade a critical threat. The Critical Floor Override guarantees that if any `CRITICAL` rule triggers, the final risk score cannot drop below `75` (`HIGH`/`BLOCK`), ensuring bulletproof defensive posture.

#### Q5: Why did you use Vanilla JavaScript instead of React or Next.js for the frontend?
> **Answer**: The backend is the single source of security truth in this architecture. Introducing a heavy client-side framework like React or Next.js would add unnecessary build complexity and bundle overhead for what is a clean presentation and visualization layer. Vanilla JS with ES modules allowed me to build a lightweight, fast, zero-dependency dashboard served directly by FastAPI.

#### Q6: How do you handle XSS and security when rendering untrusted QR payloads in the UI?
> **Answer**: Decoded QR payloads can contain arbitrary malicious strings, including JavaScript injection payloads (`<script>alert(1)</script>`). The frontend strictly uses `textContent` and programmatic DOM node creation (`document.createElement()`) rather than setting `innerHTML` directly on untrusted API response fields.

#### Q7: How does your UPI analyzer perform merchant consistency checks without an authoritative banking API?
> **Answer**: The analyzer extracts token sets from the payee name (`pn`) and the VPA handle user string (`pa`). If the payee name is a specific business name (e.g. "Official Electronics Store Ltd") but shares zero letter tokens with the VPA handle (e.g. `fast.cash.claim@bank`), it flags a `UPI_MERCHANT_NAME_MISMATCH` indicator. It does not claim absolute identity verification, but highlights structural inconsistency as a warning signal.

#### Q8: What security controls are enforced on the `POST /scan` file upload endpoint?
> **Answer**: The API validates MIME types (`image/png`, `jpeg`, `webp`, `bmp`), checks file extensions, enforces a 5 MB file size limit to prevent buffer exhaustion DoS attacks, processes image bytes safely in memory via `io.BytesIO`, cleans up temporary scratch files immediately, and formats all exceptions into structured JSON error schemas without exposing stack traces.

#### Q9: Why is passive security analysis preferred over active URL crawling in a QR engine?
> **Answer**: Actively fetching untrusted URLs from scanned QR codes exposes the security server to Server-Side Request Forgery (SSRF), IP tracking, drive-by malware payloads, and premature triggering of one-time phishing tokens. Passive analysis evaluates the structural indicators safely without contacting the attacker's infrastructure.

#### Q10: How are security rules configured and managed in the engine?
> **Answer**: All 20 security rules are defined in a centralized `config/security_rules.json` registry with unique rule IDs, categories, severities, weights, descriptions, and enabled flags. Separate configuration files manage TLD risk classifications (`config/tld_risk.json`), URL shortener domains (`config/url_shorteners.json`), and risk fusion weights (`config/risk_fusion.json`), allowing security operators to update rules without touching core codebase logic.

---

## 6. Engineering Challenges & Limitations

* **Biggest Challenge**: Balancing ML statistical generalization with deterministic security guarantees, solved by implementing the Hybrid Linear Fusion with Critical Floor Override model.
* **Primary Limitation**: Passive analysis evaluates static structural features; dynamic multi-hop URL redirects require threat intelligence API integration (documented under Future Scope).
