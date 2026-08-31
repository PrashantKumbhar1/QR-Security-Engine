# QR Security Engine — Feature Schema Specification (v2.0)

**Version**: 2.0  
**Status**: Active  
**Module**: `core/feature_extractor.py`

---

## Overview

The QR Security Engine uses a deterministic, versioned feature extraction architecture (`SCHEMA_VERSION = "2.0"`). Feature vectors are split into two domain-specific schemas:

* **`URL_FEATURE_SCHEMA_V2`**: 15 features (3 Common + 12 URL-specific)
* **`UPI_FEATURE_SCHEMA_V2`**: 13 features (3 Common + 10 UPI-specific)

---

## 1. Common Payload Features (3 Features)

| Feature Name | Type | Value Range | Description |
| :--- | :---: | :---: | :--- |
| `payload_length` | `int` | `[0, ∞)` | Character length of the decoded raw payload. |
| `digit_ratio` | `float` | `[0.0, 1.0]` | Ratio of numeric digits to total string length. |
| `special_char_count` | `int` | `[0, ∞)` | Count of special characters (`!@#$%^&*+=<>?/\|~``). |

---

## 2. URL Feature Schema (`URL_FEATURE_SCHEMA_V2` — 15 Features)

| Feature Name | Type | Value Range | Description |
| :--- | :---: | :---: | :--- |
| `payload_length` | `int` | `[0, ∞)` | (Common) Total string length. |
| `digit_ratio` | `float` | `[0.0, 1.0]` | (Common) Digit density in string. |
| `special_char_count` | `int` | `[0, ∞)` | (Common) Count of special symbols. |
| `url_length` | `int` | `[0, ∞)` | Total character length of URL. |
| `domain_length` | `int` | `[0, ∞)` | Character length of netloc hostname. |
| `path_length` | `int` | `[0, ∞)` | Character length of URL path. |
| `query_param_count` | `int` | `[0, ∞)` | Number of key-value query parameters. |
| `subdomain_count` | `int` | `[0, ∞)` | Number of subdomains preceding main domain. |
| `has_shortener` | `int` | `0` or `1` | `1` if domain matches known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.). |
| `is_https` | `int` | `0` or `1` | `1` if URL scheme is HTTPS. |
| `is_ip_url` | `int` | `0` or `1` | `1` if hostname is an IPv4 address. |
| `has_at_symbol` | `int` | `0` or `1` | `1` if `@` exists in URL (credential spoofing). |
| `suspicious_tld` | `int` | `0` or `1` | `1` if TLD matches high-risk TLD list (`.top`, `.xyz`, `.zip`, `.work`, `.click`, `.cc`, `.tk`, `.ml`, `.ga`, `.gq`). |
| `hex_encoding_count` | `int` | `[0, ∞)` | Count of `%XX` percent-encoded sequences. |
| `double_slash_in_path` | `int` | `0` or `1` | `1` if `//` appears inside URL path. |

---

## 3. UPI Feature Schema (`UPI_FEATURE_SCHEMA_V2` — 13 Features)

| Feature Name | Type | Value Range | Description |
| :--- | :---: | :---: | :--- |
| `payload_length` | `int` | `[0, ∞)` | (Common) Total string length. |
| `digit_ratio` | `float` | `[0.0, 1.0]` | (Common) Digit density in string. |
| `special_char_count` | `int` | `[0, ∞)` | (Common) Count of special symbols. |
| `amount` | `float` | `[0.0, ∞)` | Requested payment amount in INR. |
| `amount_missing` | `int` | `0` or `1` | `1` if amount parameter (`am`) is omitted. |
| `merchant_name_missing` | `int` | `0` or `1` | `1` if payee name (`pn`) is empty. |
| `merchant_name_length` | `int` | `[0, ∞)` | Character length of payee name. |
| `generic_merchant_name` | `int` | `0` or `1` | `1` if payee name is a generic term (`payment`, `upi`, `pay`, `merchant`, `store`, `cash`, `account`). |
| `upi_id_length` | `int` | `[0, ∞)` | Character length of VPA address (`pa`). |
| `upi_handle_length` | `int` | `[0, ∞)` | Character length of bank handle after `@`. |
| `has_embedded_url` | `int` | `0` or `1` | `1` if embedded `http(s)://` URL exists in any parameter. |
| `non_standard_param_count` | `int` | `[0, ∞)` | Count of non-standard UPI query parameters. |
| `suspicious_vpa_pattern` | `int` | `0` or `1` | `1` if VPA contains excess dots (`>2`) or hyphens. |
