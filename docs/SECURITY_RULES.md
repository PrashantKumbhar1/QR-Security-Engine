# QR Security Engine — Security Rules Catalog

**Date**: August 9, 2026  
**Registry File**: `config/security_rules.json`

---

## Centralized Rules Catalog (20 Rules)

| Rule ID | Category | Severity | Weight | Enabled | Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `URL_USERINFO_SPOOFING` | `URL_STRUCTURE` | `CRITICAL` | 40 | Yes | URL contains an '@' symbol used for credential spoofing. |
| `URL_PUNYCODE_HOST` | `URL_HOSTNAME` | `HIGH` | 30 | Yes | Hostname uses Punycode (xn--) indicating potential homograph attack. |
| `URL_IP_HOST` | `URL_HOSTNAME` | `HIGH` | 35 | Yes | URL uses an IP address instead of a domain name. |
| `URL_SHORTENER_DETECTED` | `URL_HOSTNAME` | `HIGH` | 30 | Yes | URL uses a known link shortening service hiding actual destination. |
| `URL_DOUBLE_SLASH_PATH` | `URL_OBFUSCATION` | `HIGH` | 25 | Yes | URL path contains double slashes (//) used for redirection tricks. |
| `URL_SUSPICIOUS_TLD` | `URL_HOSTNAME` | `MEDIUM` | 20 | Yes | URL uses a top-level domain frequently associated with phishing. |
| `URL_SENSITIVE_KEYWORDS` | `URL_PATH_QUERY` | `MEDIUM` | 20 | Yes | URL path or query contains sensitive security/login keywords. |
| `URL_NON_SECURE_HTTP` | `URL_PROTOCOL` | `MEDIUM` | 20 | Yes | URL uses non-secure HTTP protocol instead of HTTPS. |
| `URL_HEX_ENCODED_PATH` | `URL_OBFUSCATION` | `MEDIUM` | 15 | Yes | URL path contains percent-encoded hex characters. |
| `URL_EXCESSIVE_SUBDOMAINS` | `URL_HOSTNAME` | `MEDIUM` | 15 | Yes | Hostname contains an excessive number of subdomain levels (>=3). |
| `URL_EXCESSIVE_LENGTH` | `URL_STRUCTURE` | `LOW` | 10 | Yes | URL length exceeds 75 characters. |
| `UPI_EMBEDDED_EXTERNAL_URL` | `UPI_PAYLOAD` | `CRITICAL` | 50 | Yes | UPI payment payload contains an embedded external HTTP(S) URL. |
| `UPI_UNUSUALLY_HIGH_AMOUNT` | `UPI_AMOUNT` | `HIGH` | 30 | Yes | UPI payment requests an unusually high amount (>= ₹10,000). |
| `UPI_HIGH_AMOUNT` | `UPI_AMOUNT` | `HIGH` | 25 | Yes | UPI payment requests a high amount (>= ₹5,000). |
| `UPI_GENERIC_MERCHANT_NAME` | `UPI_MERCHANT` | `MEDIUM` | 20 | Yes | UPI merchant name is a generic scam keyword. |
| `UPI_MISSING_MERCHANT_NAME` | `UPI_MERCHANT` | `MEDIUM` | 15 | Yes | UPI merchant name parameter is missing or empty. |
| `UPI_UNUSUAL_VPA_FORMAT` | `UPI_PAYEE` | `MEDIUM` | 15 | Yes | UPI VPA address contains an unusual format with excess dots or hyphens. |
| `UPI_MERCHANT_NAME_MISMATCH` | `UPI_MERCHANT` | `MEDIUM` | 15 | Yes | Payee VPA handle and payee name show structural inconsistency. |
| `UPI_SUSPICIOUS_HANDLE` | `UPI_PAYEE` | `MEDIUM` | 15 | Yes | UPI handle uses a non-standard or temporary domain name. |
| `UPI_NON_STANDARD_PARAMS` | `UPI_PAYLOAD` | `LOW` | 10 | Yes | UPI payload contains non-standard query parameters. |
