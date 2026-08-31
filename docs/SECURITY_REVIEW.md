# QR Security Engine — Security Review & Threat Modeling

**Date**: August 9, 2026  
**Version**: 5.0  

---

## 1. Defensive Security Posture & Threat Vectors Mitigated

| Threat Vector | Mitigation Mechanism | Engine Defense Layer |
| :--- | :--- | :--- |
| **Credential Harvesting / `@` Spoofing** | Detects `@` symbol in URL netloc; assigns `CRITICAL` severity (+40 pts) and enforces minimum score floor of 75 (`BLOCK`). | `analyzers/url_analyzer.py` & `core/risk_fusion.py` |
| **IDN Homograph Attack (Punycode)** | Detects `xn--` domain prefixes used to imitate trusted brand domains; assigns `HIGH` severity (+30 pts). | `analyzers/url_analyzer.py` |
| **Embedded Phishing URL in UPI QR** | Detects `http://` or `https://` inside query parameters of `upi://` payload; assigns `CRITICAL` severity (+50 pts) and enforces floor of 75 (`BLOCK`). | `analyzers/upi_analyzer.py` & `core/risk_fusion.py` |
| **IP-Based Host Destinations** | Detects raw IPv4 hostnames; assigns `HIGH` severity (+35 pts). | `analyzers/url_analyzer.py` |
| **Obfuscated Path Hex Encoded & `//` Redirection** | Detects `%XX` hex encoding and double slashes in path; assigns `MEDIUM`/`HIGH` severity (+15 to +25 pts). | `analyzers/url_analyzer.py` |
| **URL Shortener Destination Hiding** | Checks domain against `config/url_shorteners.json`; assigns `HIGH` severity (+30 pts). | `analyzers/url_analyzer.py` |
| **High-Risk TLD Phishing** | Checks domain TLD against `config/tld_risk.json`; assigns `MEDIUM` severity (+20 pts). | `analyzers/url_analyzer.py` |
| **Merchant Name Spoofing & Missing Payee** | Checks payee name against generic fraud terms and evaluates VPA vs Payee Name token mismatch. | `analyzers/upi_analyzer.py` |

---

## 2. Application & API Input Security Controls

1. **Passive Security Inspection Only**: The engine inspects decoded URL strings without issuing outbound HTTP/HTTPS GET/POST requests or actively crawling external sites. This prevents SSRF (Server-Side Request Forgery) and drive-by malware execution.
2. **Strict File Upload Validation**:
   * MIME Type Validation: Enforces `image/png`, `image/jpeg`, `image/webp`, `image/bmp`.
   * File Size Limits: Enforces maximum size limit of **5 MB**.
3. **XSS Prevention in Web UI**: Render decoded QR payloads, evidence strings, and reasons using `textContent` and standard DOM node creation to avoid DOM-based Cross-Site Scripting.
4. **Safe Temporary File Lifecycle**: Uploaded image bytes are processed safely in workspace scratch storage and deleted immediately upon analysis completion.
5. **No Expose of Stack Traces**: All API exceptions are caught by FastAPI exception handlers and formatted into structured JSON error schemas.

---

## 3. Known Limitations & Future Enhancements

1. **Static Passive Analysis**: Dynamic HTTP redirect chains (e.g. multi-hop URL shortener resolution) require passive threat intelligence lookup APIs (queued for future integration).
2. **Synthetic UPI Training Limitations**: Synthetic UPI training data provides linear boundary separability (`F1: 1.0000`); real-world payment anomaly detection requires partnership with authoritative banking fraud registries.
