# QR Security Engine — Deep URL Security Analyzer Specification

**Date**: August 9, 2026  
**Module**: `analyzers/url_analyzer.py`  
**Configs**: `config/security_rules.json`, `config/tld_risk.json`, `config/url_shorteners.json`

---

## 1. Overview

The Deep URL Security Analyzer (`analyzers/url_analyzer.py`) performs multi-layer inspection across URL structure, hostname, obfuscation, path, query parameters, and protocol schemes.

---

## 2. Analysis Layers & Rules

### A. URL Structure Layer
* **`URL_USERINFO_SPOOFING`** (`CRITICAL`, 40 pts): Detects `@` credential spoofing symbols in netloc (e.g. `http://google.com@phishing.site`).
* **`URL_EXCESSIVE_LENGTH`** (`LOW`, 10 pts): Triggers if total URL length exceeds 75 characters.

### B. Hostname Layer
* **`URL_PUNYCODE_HOST`** (`HIGH`, 30 pts): Detects `xn--` IDN homograph attack prefixes in hostname.
* **`URL_IP_HOST`** (`HIGH`, 35 pts): Detects raw IPv4 address hostnames.
* **`URL_SHORTENER_DETECTED`** (`HIGH`, 30 pts): Detects domains matching `config/url_shorteners.json`.
* **`URL_SUSPICIOUS_TLD`** (`MEDIUM`, 20 pts): Detects TLDs matching high-risk list in `config/tld_risk.json` (`.top`, `.xyz`, `.zip`, `.click`, `.cc`, `.tk`, etc.).
* **`URL_EXCESSIVE_SUBDOMAINS`** (`MEDIUM`, 15 pts): Triggers if subdomain depth >= 3.

### C. Obfuscation Layer
* **`URL_DOUBLE_SLASH_PATH`** (`HIGH`, 25 pts): Detects `//` inside path string (URL redirection trick).
* **`URL_HEX_ENCODED_PATH`** (`MEDIUM`, 15 pts): Detects percent-encoded `%XX` sequences in path.

### D. Path & Query Layer
* **`URL_SENSITIVE_KEYWORDS`** (`MEDIUM`, 20 pts): Detects security keywords (`login`, `signin`, `verify`, `account`, `banking`, `paypal`, `wallet`, `credential`) in path/query.

### E. Protocol Layer
* **`URL_NON_SECURE_HTTP`** (`MEDIUM`, 20 pts): Detects `http://` scheme.

---

## 3. False Positive Considerations & Safeguards

1. **HTTP ≠ Automatic Maliciousness**: HTTP triggers a `MEDIUM` indicator (20 pts), allowing clean HTTP URLs to stay at `LOW` risk level (`20 < 25`).
2. **Shorteners ≠ Automatic Maliciousness**: URL shorteners trigger a `HIGH` indicator (30 pts), placing the URL at `MEDIUM` risk (`WARN`), prompting caution without an absolute block.
3. **Multi-Signal Combination**: High or Critical decisions (`BLOCK`) require multiple compounding indicators (e.g. IP host + HTTP + sensitive keyword).
