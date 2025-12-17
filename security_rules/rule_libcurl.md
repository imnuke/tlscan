# libcurl SSL/TLS Security Rules

This document defines library-specific security rules for libcurl-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2 | MUST | Protocol Version Enforcement |
| R5 | M5 | SHOULD | Cipher Suite Selection |
| R6 | S1 | SHOULD | Certificate Revocation Checking |
| R7 | O1 | MAY | Certificate Pinning |

**Note**: Entropy/RNG (S3) is not applicable to libcurl as it relies on the underlying SSL backend (OpenSSL, NSS, etc.).

## Binary Analysis Reference

**CRITICAL**: When analyzing compiled binaries, `curl_easy_setopt()` calls show numeric option codes instead of symbolic names.

### Security-Critical Options (MUST check)

| Option Name | Code | Default | Secure Value | Insecure Value |
|-------------|------|---------|--------------|----------------|
| `CURLOPT_SSL_VERIFYPEER` | 64 | 1 | 1 | 0 |
| `CURLOPT_SSL_VERIFYHOST` | 81 | 2 | 2 | 0, 1 |
| `CURLOPT_SSLVERSION` | 32 | 0 | ≥6 | <6 (version-dependent) |

### Other SSL-Related Options

| Option Name | Code | Description |
|-------------|------|-------------|
| `CURLOPT_CAINFO` | 10065 | CA certificate file path |
| `CURLOPT_CAPATH` | 10097 | CA certificate directory |
| `CURLOPT_SSL_OPTIONS` | 216 | SSL behavior flags |
| `CURLOPT_SSL_CIPHER_LIST` | 10083 | Allowed cipher suites |
| `CURLOPT_PINNEDPUBLICKEY` | 10230 | Certificate pinning |
| `CURLOPT_URL` | 10002 | Target URL |

### Common Non-SSL Options (for disambiguation)

| Option Name | Code | Description |
|-------------|------|-------------|
| `CURLOPT_VERBOSE` | 41 | Debug output |
| `CURLOPT_POST` | 47 | Enable POST |
| `CURLOPT_POSTFIELDS` | 10015 | POST data |

## Version Detection Hints

| Pattern | Indicates |
|---------|-----------|
| `curl_easy_option_by_id()` | libcurl 7.73.0+ |
| `CURL_SSLVERSION_TLSv1_3` (value 7) | libcurl 7.52.0+ |
| `CURLOPT_DOH_SSL_VERIFYHOST` | libcurl 7.76.0+ |

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm HTTPS is used for connections, not HTTP or plaintext.

**Implementation**:
- Check URL scheme: must be `https://` not `http://`
- Verify `curl_easy_perform()` is called (not just setup)
- Look for conditional protocol usage or HTTP fallback

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `curl_easy_init` | Create curl handle |
| `curl_easy_setopt` | Configure options |
| `curl_easy_perform` | Execute request |
| `curl_multi_perform` | Execute multi-handle request |

**Detection Patterns**:
- URL patterns: presence of `https://` vs `http://` in strings
- Option 10002 (`CURLOPT_URL`): URL being set
- Conditional protocol: `url = (use_ssl ? "https" : "http") + "://..."`
- Port-based: different handling for port 443 vs 80

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | PASS | TLS connection |
| URL starts with `http://` | FAIL | Plaintext connection |
| URL scheme from variable | CONDITIONAL | Trace variable |
| Fallback to HTTP on error | FAIL | Downgrade possible |
| No URL found | UNDETERMINED | Cannot determine |

---

## R2: Certificate Chain Verification

**Meta-Rule(s)**: M3  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated against trusted CA store.

**Implementation**:
- `CURLOPT_SSL_VERIFYPEER` (code 64): Enable certificate verification
- `CURLOPT_CAINFO` (code 10065): Specify CA certificate file
- `CURLOPT_CAPATH` (code 10097): Specify CA certificate directory
- Default: **ENABLED** (value 1) - secure by default

**Binary Analysis**:
| Option | Code | Values |
|--------|------|--------|
| `CURLOPT_SSL_VERIFYPEER` | 64 | 0=disabled (FAIL), 1=enabled (PASS) |
| `CURLOPT_CAINFO` | 10065 | Path to CA bundle file |
| `CURLOPT_CAPATH` | 10097 | Path to CA directory |

**Default Behavior**:
| libcurl Version | Default | Security |
|-----------------|---------|----------|
| All versions | 1 (enabled) | SECURE |

**Detection Patterns**:
- `curl_easy_setopt(handle, 64, 0)` → FAIL (verification disabled)
- `curl_easy_setopt(handle, 64, 1)` → PASS (verification enabled)
- No call to option 64 → PASS (uses secure default)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYPEER` set to 1 | PASS | Verification enabled |
| `CURLOPT_SSL_VERIFYPEER` not set | PASS | Default is 1 (enabled) |
| `CURLOPT_SSL_VERIFYPEER` set to 0 | FAIL | Verification disabled |
| `curl_easy_setopt(h, 64, var)` | CONDITIONAL | Trace variable |
| `CURLOPT_CAINFO`/`CAPATH` not set | CONDITIONAL | May use system CA store |

---

## R3: Hostname Verification

**Meta-Rule(s)**: M4  |  **Priority**: MUST

**What to Verify**: Certificate's identity matches the target hostname.

**Implementation**:
- `CURLOPT_SSL_VERIFYHOST` (code 81): Enable hostname verification
- Default: **2** (strict hostname check) - secure by default
- Value 0: Disabled (INSECURE)
- Value 1: Deprecated, treated differently by version

**Binary Analysis**:
| Option | Code | Values |
|--------|------|--------|
| `CURLOPT_SSL_VERIFYHOST` | 81 | 0=disabled, 1=deprecated, 2=enabled |

**Default Behavior (Version-Dependent)**:
| libcurl Version | Default | Security |
|-----------------|---------|----------|
| All versions | 2 | SECURE |

**Value 1 Behavior History**:
| Version | Behavior |
|---------|----------|
| ≤ 7.28.0 | Debug option (unreliable) |
| 7.28.1 - 7.65.3 | Returns error |
| ≥ 7.66.0 | Treated same as 2 |

**Detection Patterns**:
- `curl_easy_setopt(handle, 81, 0)` → FAIL (hostname verification disabled)
- `curl_easy_setopt(handle, 81, 1)` → FAIL (unreliable/deprecated)
- `curl_easy_setopt(handle, 81, 2)` → PASS (verification enabled)
- No call to option 81 → PASS (default is 2)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYHOST` set to 2 | PASS | Strict hostname check |
| `CURLOPT_SSL_VERIFYHOST` not set | PASS | Default is 2 |
| `CURLOPT_SSL_VERIFYHOST` set to 0 | FAIL | Hostname check disabled |
| `CURLOPT_SSL_VERIFYHOST` set to 1 | FAIL | Deprecated/unreliable |
| `curl_easy_setopt(h, 81, var)` | CONDITIONAL | Trace variable |

**Cross-Rule Note**: Hostname verification (R3) is only meaningful if certificate verification (R2) is also enabled. Document in evidence if R2 fails.

---

## R4: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is negotiated; older versions are blocked.

**Implementation**:
- `CURLOPT_SSLVERSION` (code 32): Set minimum SSL/TLS version
- Default: 0 (`CURL_SSLVERSION_DEFAULT`) - relies on SSL backend
- Must set to ≥6 (`CURL_SSLVERSION_TLSv1_2`) for security

**Binary Analysis**:
| Option | Code | Values |
|--------|------|--------|
| `CURLOPT_SSLVERSION` | 32 | See version table below |

| Value | Constant | Version | Security |
|-------|----------|---------|----------|
| 0 | `CURL_SSLVERSION_DEFAULT` | Backend default | Version-dependent |
| 1 | `CURL_SSLVERSION_TLSv1` | TLS 1.0+ | INSECURE |
| 2 | `CURL_SSLVERSION_SSLv2` | SSL 2.0 | INSECURE (refused since 7.77.0) |
| 3 | `CURL_SSLVERSION_SSLv3` | SSL 3.0 | INSECURE (refused since 7.77.0) |
| 4 | `CURL_SSLVERSION_TLSv1_0` | TLS 1.0 | INSECURE |
| 5 | `CURL_SSLVERSION_TLSv1_1` | TLS 1.1 | INSECURE |
| 6 | `CURL_SSLVERSION_TLSv1_2` | TLS 1.2 | SECURE |
| 7 | `CURL_SSLVERSION_TLSv1_3` | TLS 1.3 | SECURE |

**Default Behavior (Version-Dependent)**:
| libcurl Version | Default Min | Security |
|-----------------|-------------|----------|
| < 7.39.0 | SSL 3.0 allowed | INSECURE |
| 7.39.0 - 8.15.x | TLS 1.0 | INSECURE |
| ≥ 8.16.0 | TLS 1.2 | SECURE |

**Detection Patterns**:
- `curl_easy_setopt(handle, 32, 6)` → PASS (TLS 1.2 minimum)
- `curl_easy_setopt(handle, 32, 7)` → PASS (TLS 1.3 minimum)
- `curl_easy_setopt(handle, 32, value < 6)` → FAIL (allows insecure versions)
- No call to option 32 → CONDITIONAL (depends on libcurl version)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSLVERSION` ≥ 6 | PASS | TLS 1.2+ enforced |
| `CURLOPT_SSLVERSION` < 6 and > 0 | FAIL | Allows insecure protocols |
| `CURLOPT_SSLVERSION` = 0 or not set | CONDITIONAL | Depends on libcurl version |
| `curl_easy_setopt(h, 32, var)` | CONDITIONAL | Trace variable |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: SHOULD

**What to Verify**: Strong cipher suites are configured, weak ciphers excluded.

**Implementation**:
- `CURLOPT_SSL_CIPHER_LIST` (code 10083): Cipher string for TLS 1.2 and below
- `CURLOPT_TLS13_CIPHERS` (code 10276): Cipher suites for TLS 1.3
- Format depends on SSL backend (OpenSSL, NSS, etc.)

**Binary Analysis**:
| Option | Code | Purpose |
|--------|------|---------|
| `CURLOPT_SSL_CIPHER_LIST` | 10083 | TLS 1.2 ciphers |
| `CURLOPT_TLS13_CIPHERS` | 10276 | TLS 1.3 ciphers |
| `CURLOPT_PROXY_SSL_CIPHER_LIST` | 10259 | Proxy ciphers |

**Detection Patterns**:
- Cipher string containing `NULL`, `EXPORT`, `RC4`, `DES` → FAIL
- Cipher string with `HIGH:!aNULL:!eNULL:!EXPORT` → PASS
- No cipher restriction → CONDITIONAL (uses backend default)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string configured | PASS | Weak ciphers excluded |
| Weak ciphers in string | FAIL | Insecure ciphers allowed |
| No cipher configuration | CONDITIONAL | Uses SSL backend default |
| Cipher string from variable | CONDITIONAL | Trace variable |

---

## R6: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked.

**Implementation**:
- `CURLOPT_SSL_OPTIONS` (code 216) with `CURLSSLOPT_REVOKE_BEST_EFFORT`
- Revocation checking support varies by SSL backend
- OCSP stapling support is backend-dependent

**Binary Analysis**:
| Option | Code | Values |
|--------|------|--------|
| `CURLOPT_SSL_OPTIONS` | 216 | Bitmask of SSL options |

| Flag | Value | Purpose |
|------|-------|---------|
| `CURLSSLOPT_REVOKE_BEST_EFFORT` | 32 | Check CRL if available |
| `CURLSSLOPT_NO_REVOKE` | 2 | Disable revocation check (Windows) |

**Detection Patterns**:
- `CURLSSLOPT_REVOKE_BEST_EFFORT` flag set → PASS
- `CURLSSLOPT_NO_REVOKE` flag set → FAIL
- No revocation configuration → UNDETERMINED

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Revocation checking enabled | PASS | CRL/OCSP check performed |
| `CURLSSLOPT_NO_REVOKE` used | FAIL | Revocation check disabled |
| No configuration | UNDETERMINED | SHOULD requirement |

---

## R7: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented.

**Implementation**:
- `CURLOPT_PINNEDPUBLICKEY` (code 10230): SHA256 hash of public key
- Format: `"sha256//base64-encoded-hash"` or path to public key file
- Multiple pins separated by semicolons

**Binary Analysis**:
| Option | Code | Format |
|--------|------|--------|
| `CURLOPT_PINNEDPUBLICKEY` | 10230 | `sha256//hash` or file path |

**Detection Patterns**:
- `curl_easy_setopt(h, 10230, "sha256//...")` → PASS (pinning enabled)
- Option 10230 not used → UNDETERMINED (optional feature)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_PINNEDPUBLICKEY` set | PASS | Pinning enabled |
| Pinning not configured | UNDETERMINED | Optional feature |
| Pin value from variable | CONDITIONAL | Trace pin source |

---

## Result Determination Summary

### When to use each result:

| Scenario | Result | Example |
|----------|--------|---------|
| Option explicitly set to secure value | PASS | `curl_easy_setopt(curl, 81, 2)` |
| Option NOT set, default is secure | PASS | `CURLOPT_SSL_VERIFYHOST` not called |
| Option explicitly set to insecure value | FAIL | `curl_easy_setopt(curl, 64, 0)` |
| Option NOT set, default is version-dependent | CONDITIONAL | `CURLOPT_SSLVERSION` not set |
| Option set to runtime variable | CONDITIONAL | `curl_easy_setopt(curl, 64, config_value)` |
| Cannot find relevant code | UNDETERMINED | No `curl_easy_setopt` calls found |
