# libcurl SSL/TLS Security Rules

This document defines library-specific security rules for libcurl-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2 | MUST | Protocol Version Enforcement |
| R5 | M5 | MUST | Cipher Suite Selection |
| R6 | S1 | SHOULD | Certificate Revocation Checking |
| R7 | S2 | SHOULD | Cryptographic Strength (Backend-Dependent) |
| R8 | O1 | MAY | Certificate Pinning |

**Notes**:
- Entropy/RNG (S3) is not applicable to libcurl: there are no libcurl options to configure entropy, and RNG initialization is entirely internal to the SSL backend with nothing observable at the libcurl layer. In contrast, R7 (S2) is analyzable because backend version determines cryptographic strength defaults (e.g., OpenSSL 3.0+ enforces SHA-256+, RSA 2048+).
- R7 (S2) is backend-dependent - libcurl relies on the SSL backend for cryptographic strength enforcement.

## ⚠️ CRITICAL: Applicability Check

**This ruleset applies ONLY to binaries that implement TLS clients using libcurl.**

### Required Functions for Applicability

A binary MUST call at least one of these to be applicable:
- `curl_easy_perform()` - Execute single transfer
- `curl_multi_perform()` - Execute multi-handle transfer

### Non-Applicable: Utility-Only Usage

If a binary only imports these functions WITHOUT `curl_easy_perform`/`curl_multi_perform`:

| Function | Purpose | TLS Relevance |
|----------|---------|---------------|
| `curl_easy_init` | Create handle | Setup only |
| `curl_easy_cleanup` | Destroy handle | Cleanup only |
| `curl_easy_escape` | URL-encode string | Utility only |
| `curl_easy_unescape` | URL-decode string | Utility only |
| `curl_free` | Free memory | Utility only |
| `curl_easy_strerror` | Error message | Utility only |

**→ Set `applicable=false` with reason: "Binary uses libcurl utility functions only (no curl_easy_perform or curl_multi_perform)"**

### Binary Analysis Flow

1. **FIRST**: Check for `curl_easy_perform` or `curl_multi_perform` imports/calls
   - Use `list_functions_filter(filter="curl_easy_perform")` or `list_imports`
   - Search strings: `list_strings_filter(filter="curl_easy_perform")`

2. **If NOT found**:
   - Set `applicable=false`
   - Reason: "Binary uses libcurl utility functions only"

3. **If found**:
   - Continue with rule analysis (R1-R8)

### Delegated TLS Clients

If the binary imports functions that handle TLS internally (e.g., `Send_Mail_Direct`, `NotificationOauth::*`), but doesn't call `curl_easy_perform` itself:
- The TLS implementation is in the **library** defining those functions
- This binary is NOT the TLS client → NOT APPLICABLE
- The library should be analyzed separately

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

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | SATISFIED | TLS connection |
| URL starts with `http://` | UNSATISFIED | Plaintext connection |
| URL scheme from variable | CONDITIONAL | Trace variable |
| Fallback to HTTP on error | UNSATISFIED | Downgrade possible |
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
| `CURLOPT_SSL_VERIFYPEER` | 64 | 0=disabled (UNSATISFIED), 1=enabled (SATISFIED) |
| `CURLOPT_CAINFO` | 10065 | Path to CA bundle file |
| `CURLOPT_CAPATH` | 10097 | Path to CA directory |

**Default Behavior**:
| libcurl Version | Default | Security |
|-----------------|---------|----------|
| All versions | 1 (enabled) | SECURE |

**Detection Patterns**:
- `curl_easy_setopt(handle, 64, 0)` → UNSATISFIED (verification disabled)
- `curl_easy_setopt(handle, 64, 1)` → SATISFIED (verification enabled)
- No call to option 64 → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYPEER` set to 1 | SATISFIED | Verification enabled |
| `CURLOPT_SSL_VERIFYPEER` not set | DEFAULT | Not explicitly configured |
| `CURLOPT_SSL_VERIFYPEER` set to 0 | UNSATISFIED | Verification disabled |
| `curl_easy_setopt(h, 64, var)` | CONDITIONAL | Trace variable |

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
- `curl_easy_setopt(handle, 81, 0)` → UNSATISFIED (hostname verification disabled)
- `curl_easy_setopt(handle, 81, 1)` → UNSATISFIED (unreliable/deprecated)
- `curl_easy_setopt(handle, 81, 2)` → SATISFIED (verification enabled)
- No call to option 81 → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYHOST` set to 2 | SATISFIED | Strict hostname check |
| `CURLOPT_SSL_VERIFYHOST` not set | DEFAULT | Not explicitly configured |
| `CURLOPT_SSL_VERIFYHOST` set to 0 | UNSATISFIED | Hostname check disabled |
| `CURLOPT_SSL_VERIFYHOST` set to 1 | UNSATISFIED | Deprecated/unreliable |
| `curl_easy_setopt(h, 81, var)` | CONDITIONAL | Trace variable |

**Security Note**: CURLOPT_SSL_VERIFYHOST operates independently of CURLOPT_SSL_VERIFYPEER per libcurl documentation. Evaluate R3 based solely on VERIFYHOST setting. If R2 fails, note the combined security impact in evidence but do NOT change R3's result.

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

**libcurl Version Defaults (when CURLOPT_SSLVERSION=0 or not set)**:
| libcurl Version | Default Min | Security |
|-----------------|-------------|----------|
| < 7.39.0 | SSL 3.0 allowed | INSECURE |
| 7.39.0 - 8.15.x | TLS 1.0 | INSECURE |
| ≥ 8.16.0 | TLS 1.2 | SECURE |

**Backend Minimum (HARD FLOOR - applies regardless of libcurl version)**:
| Backend | Version Range | Library Default | With Config |
|---------|---------------|-----------------|-------------|
| OpenSSL | 3.0+ | TLS 1.2 | Use MinProtocol from openssl.cnf |
| OpenSSL | 1.1.1+ | TLS 1.0 | Use MinProtocol from openssl.cnf |
| OpenSSL | 1.0.x | TLS 1.0 | Use MinProtocol from openssl.cnf |
| GnuTLS | 3.6+ | TLS 1.2 | Use priority from gnutls config |
| GnuTLS | < 3.6 | TLS 1.0 | Use priority from gnutls config |
| mbedTLS | 2.x+ | TLS 1.2 | Compile-time only |
| wolfSSL | 4.x+ | TLS 1.2 | Compile-time only |

**IMPORTANT**: The backend's minimum is a hard floor that libcurl cannot go below.
If the backend config (e.g., openssl.cnf) sets MinProtocol=TLSv1.2, the backend
will refuse connections below TLS 1.2 even if libcurl's default would allow TLS 1.0.

**Detection Patterns**:
- `curl_easy_setopt(handle, 32, 6)` → SATISFIED (TLS 1.2 minimum)
- `curl_easy_setopt(handle, 32, 7)` → SATISFIED (TLS 1.3 minimum)
- `curl_easy_setopt(handle, 32, 1-5)` → UNSATISFIED (insecure version explicitly set)
- No call to option 32 → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSLVERSION` ≥ 6 | SATISFIED | TLS 1.2+ enforced |
| `CURLOPT_SSLVERSION` 1-5 | UNSATISFIED | Insecure version explicitly set |
| `CURLOPT_SSLVERSION` not set | DEFAULT | Not explicitly configured |
| `curl_easy_setopt(h, 32, var)` | CONDITIONAL | Trace variable |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: MUST

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

**Backend Cipher Suite Defaults (when no cipher configuration)**:
| Backend | Version | Default Config | Security |
|---------|---------|----------------|----------|
| OpenSSL | 3.0+ | TLS_AES_* + ECDHE preferred | SECURE |
| OpenSSL | 1.1.1+ | DEFAULT:!aNULL:!eNULL (ECDHE) | SECURE |
| OpenSSL | 1.0.x | DEFAULT (may include weak) | INSECURE |
| GnuTLS | 3.6+ | NORMAL priority | SECURE |
| mbedTLS | 2.x+ | Secure defaults | SECURE |
| wolfSSL | 4.x+ | Secure defaults | SECURE |

**Detection Patterns**:
- Cipher string containing `NULL`, `EXPORT`, `RC4`, `DES` → UNSATISFIED
- Cipher string with `HIGH:!aNULL:!eNULL:!EXPORT` → SATISFIED
- No cipher config → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string configured | SATISFIED | Weak ciphers excluded |
| Weak ciphers in string | UNSATISFIED | Insecure ciphers allowed |
| No cipher config | DEFAULT | Not explicitly configured |
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

**Backend Revocation Defaults (when no revocation configuration)**:
| Backend | Default Behavior | Verdict |
|---------|-----------------|---------|
| OpenSSL | DISABLED (no CRL/OCSP) | CONDITIONAL |
| GnuTLS | DISABLED | CONDITIONAL |
| mbedTLS | DISABLED | CONDITIONAL |
| Schannel (Windows) | CRL enabled | SATISFIED |
| SecureTransport (macOS) | May use system OCSP | CONDITIONAL |
| wolfSSL | DISABLED | CONDITIONAL |

**Detection Patterns**:
- `CURLSSLOPT_REVOKE_BEST_EFFORT` flag set → SATISFIED
- `CURLSSLOPT_NO_REVOKE` flag set → UNSATISFIED (explicitly disabled)
- No revocation config → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Revocation checking enabled | SATISFIED | CRL/OCSP check performed |
| `CURLSSLOPT_NO_REVOKE` used | UNSATISFIED | Revocation checking explicitly disabled |
| No revocation config | DEFAULT | Not explicitly configured |

---

## R7: Cryptographic Strength (Backend-Dependent)

**Meta-Rule(s)**: S2  |  **Priority**: SHOULD

**What to Verify**: Certificates use strong signature algorithms (SHA-256+) and adequate key sizes (RSA 2048+).

**Implementation**:
- libcurl relies on the underlying SSL backend for cryptographic strength enforcement
- Check the backend version to determine default security level
- libcurl has no direct option to configure cryptographic strength requirements

**Backend Cryptographic Strength Defaults**:
| Backend | Version | Default Security Level | Verdict |
|---------|---------|----------------------|---------|
| OpenSSL | 3.0+ | Level 2 (SHA-256+, RSA 2048+) | SATISFIED |
| OpenSSL | 1.1.x | Level 1 (SHA-1 allowed, RSA 1024+) | UNSATISFIED |
| OpenSSL | 1.0.x | Level 0 (weak algorithms allowed) | UNSATISFIED |
| GnuTLS | 3.6+ | NORMAL priority (secure defaults) | SATISFIED |
| GnuTLS | < 3.6 | May allow weak algorithms | UNSATISFIED |
| mbedTLS | 2.x+ | Compile-time configured | CONDITIONAL |
| wolfSSL | 4.x+ | Secure defaults | SATISFIED |

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No configuration | DEFAULT | Not explicitly configured (backend-dependent) |

**Note**: libcurl has no direct option to configure cryptographic strength. This is entirely
backend-dependent with no code-level configuration possible, so result is always DEFAULT.

---

## R8: Certificate Pinning

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
- `curl_easy_setopt(h, 10230, "sha256//...")` → SATISFIED (pinning enabled)
- Option 10230 not used → UNSATISFIED (pinning not implemented)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_PINNEDPUBLICKEY` set | SATISFIED | Pinning enabled |
| Pinning not configured | UNSATISFIED | Pinning not implemented |
| Pin value from variable | CONDITIONAL | Trace pin source |

---

## Result Determination Summary

### When to use each result:

| Scenario | Result | Example |
|----------|--------|---------|
| Option explicitly set to secure value | SATISFIED | `curl_easy_setopt(curl, 81, 2)` |
| Option explicitly set to insecure value | UNSATISFIED | `curl_easy_setopt(curl, 64, 0)` |
| Option set to runtime variable | CONDITIONAL | `curl_easy_setopt(curl, 64, config_value)` |
| Option NOT configured | DEFAULT | `CURLOPT_SSL_VERIFYHOST` not called |
| Cannot find relevant code at all | UNDETERMINED | No `curl_easy_setopt` calls found |

**IMPORTANT**: Use DEFAULT (not SATISFIED) when an option is not explicitly configured,
even if the library has secure defaults. The agent should NOT infer results based on
knowledge of library default behavior.
