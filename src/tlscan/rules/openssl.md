# OpenSSL SSL/TLS Security Rules

This document defines library-specific security rules for OpenSSL-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |


## ⚠️ CRITICAL: Applicability Check

**This ruleset applies ONLY to binaries that implement TLS clients using OpenSSL.**

### Required Functions for Applicability

A binary MUST call at least one of these to be applicable:
- `SSL_connect()` - Client TLS handshake
- `SSL_do_handshake()` - Generic handshake (client or server)
- `bufferevent_socket_connect` - Buffer event handshake

### Non-Applicable: Setup-Only Usage

If a binary only imports these functions WITHOUT handshake calls:

| Function | Purpose | TLS Relevance |
|----------|---------|---------------|
| `SSL_CTX_new` | Create context | Setup only |
| `SSL_new` | Create session | Setup only |
| `SSL_free` | Free session | Cleanup only |
| `SSL_CTX_free` | Free context | Cleanup only |
| `SSL_library_init` | Initialize library | Setup only |
| `SSL_load_error_strings` | Load error messages | Utility only |

**→ Set `applicable=false` with reason: "Binary uses OpenSSL setup/utility functions only"**

### Binary Analysis Flow

1. **FIRST**: Check for `SSL_connect` or `SSL_do_handshake` or `bufferevent_socket_connect` imports/calls
2. **If NOT found**: Set `applicable=false`
3. **If found**: Continue with rule analysis (R1-R9)

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm that SSL/TLS is actually used for connections, not just linked.

**Implementation**:
- `SSL_connect()`: Initiates client TLS handshake - MUST be called for client connections
- `SSL_new()` + `SSL_CTX_new()`: Context and session creation - required before handshake
- Default behavior: No TLS unless explicitly initialized and connected

**Binary Analysis**:
| Function | Purpose | Required for TLS |
|----------|---------|------------------|
| `SSL_CTX_new` | Create SSL context | Yes |
| `SSL_new` | Create SSL session | Yes |
| `SSL_set_fd` / `SSL_set_bio` | Attach socket | Yes |
| `SSL_connect` | Client handshake | Yes (client) |
| `SSL_write` / `SSL_read` | Data transfer | Yes (after handshake) |

**Detection Patterns**:
- Functions: `SSL_connect`, `SSL_new`, `SSL_CTX_new`, `SSL_write`, `SSL_read`
- Conditional patterns:
  - `if (use_ssl)` or `if (config.enable_tls)` before SSL calls
  - `if (strncmp(url, "https://", 8) == 0)` for protocol detection
  - Port checks: `if (port == 443)` determining SSL usage
  - STARTTLS: "STARTTLS" string followed by `SSL_connect()`
- Vulnerability indicators:
  - SSL functions linked but never called in dataflow
  - Unconditional `connect()` + `send()`/`recv()` without SSL wrapper
  - SSL initialization inside disabled code branches
  - Error recovery that falls back to plaintext connection
  - Opportunistic STARTTLS without enforcement

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `SSL_connect()` always called | SATISFIED | TLS connection established |
| SSL functions not found/linked | UNSATISFIED | No TLS implementation |
| `connect()` without SSL wrapper | UNSATISFIED | Plaintext connection |
| SSL usage depends on config/env | CONDITIONAL | Trace variable to determine |
| STARTTLS with fallback to plaintext | UNSATISFIED | Downgrade attack possible |
| STARTTLS with mandatory enforcement | CONDITIONAL | Depends on server response handling |

---

## R2: Certificate Chain Verification

**Meta-Rule(s)**: M3  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated against trusted CA store.

**Implementation**:
- `SSL_CTX_set_verify()` / `SSL_set_verify()`: Set verification mode
- Default mode: `SSL_VERIFY_NONE` (0x00) - **INSECURE** - does NOT verify certificates
- Required mode: `SSL_VERIFY_PEER` (0x01) - verifies certificate chain
- Custom callback: If provided, MUST check `preverify_ok` parameter and return 0 on error

**Binary Analysis**:
| Function/Constant | Value | Security |
|-------------------|-------|----------|
| `SSL_VERIFY_NONE` | 0x00 | INSECURE (unless manual verification) |
| `SSL_VERIFY_PEER` | 0x01 | SECURE - verify peer cert |
| `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` | 0x02 | Additional flag (server mode) |
| `SSL_VERIFY_CLIENT_ONCE` | 0x04 | Additional flag (server mode) |

**Default Behavior (Version-Dependent)**:
| Version | Default Mode | Security |
|---------|--------------|----------|
| All versions | `SSL_VERIFY_NONE` (0x00) | INSECURE |

### Alternative Verification Pattern (SSL_VERIFY_NONE with Manual Check)

When `SSL_VERIFY_NONE` is used, verification can still be secure if **ALL** of the following are implemented after `SSL_connect()`:

1. **`SSL_get_peer_certificate()`** MUST be called and checked for non-NULL
2. **`SSL_get_verify_result()`** MUST be called and checked for `X509_V_OK`

**CRITICAL BUG**: `SSL_get_verify_result()` returns `X509_V_OK` even when no certificate was provided by the peer. Therefore, `SSL_get_peer_certificate()` MUST be called **first** to verify a certificate exists.

**Correct Manual Verification Pattern**:
```c
// After SSL_connect() succeeds:
X509 *cert = SSL_get_peer_certificate(ssl);
if (cert == NULL) {
    // FAIL - no certificate provided
    return error;
}
long result = SSL_get_verify_result(ssl);
if (result != X509_V_OK) {
    // FAIL - certificate verification failed
    X509_free(cert);
    return error;
}
X509_free(cert);
// PASS - certificate valid
```

**Incorrect Manual Verification (Vulnerability)**:
```c
// WRONG: Only checks result, not certificate presence
long result = SSL_get_verify_result(ssl);
if (result != X509_V_OK) { ... }  // Returns X509_V_OK even without cert!
```

### Custom Callback Requirements (SSL_CTX_set_verify)

If a custom verification callback is provided to `SSL_CTX_set_verify()`:

**CRITICAL**: When a custom callback is detected, you MUST:
1. **Decompile the callback function** to analyze its implementation
2. **Check the control flow** for error handling patterns
3. **Identify any error suppression** that bypasses security checks

**Callback Signature**:
```c
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
```
- `preverify_ok`: 1 if OpenSSL verification passed, 0 if it failed
- Return value: 1 to continue handshake, 0 to abort

**Secure Callback Requirements**:
1. MUST check `preverify_ok` parameter
2. MUST return 0 when `preverify_ok` is 0 (propagate verification failure)
3. MUST NOT suppress critical errors without security justification
4. MAY return 1 for non-critical errors only with documented policy reason

**Insecure Patterns - UNSATISFIED**:
```c
// UNSATISFIED: Returns 1 unconditionally (bypasses all verification)
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    return 1;  // DANGER: Accepts ANY certificate!
}

// UNSATISFIED: Ignores preverify_ok entirely
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // Does custom logic without checking preverify_ok
    return my_custom_check(ctx);  // preverify_ok ignored!
}

// UNSATISFIED: Suppresses critical errors
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_CERT_HAS_EXPIRED ||
        err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
        return 1;  // DANGER: Suppresses critical security errors!
    }
    return preverify_ok;
}
```

**Secure Pattern - SATISFIED**:
```c
// SATISFIED: Properly propagates preverify_ok
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        log_error("Certificate verification failed: %s",
                  X509_verify_cert_error_string(err));
        return 0;  // Propagate failure
    }
    return 1;  // Verification passed
}
```

**Critical Errors That Should NEVER Be Suppressed**:
| Error Code | Constant | Impact if Suppressed |
|------------|----------|---------------------|
| 2 | `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT` | Accepts incomplete chains |
| 7 | `X509_V_ERR_CERT_SIGNATURE_FAILURE` | Accepts forged certificates |
| 9 | `X509_V_ERR_CERT_NOT_YET_VALID` | Accepts future-dated certs |
| 10 | `X509_V_ERR_CERT_HAS_EXPIRED` | Accepts expired certificates |
| 18 | `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` | Accepts self-signed leaf |
| 19 | `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN` | Accepts untrusted CA |
| 20 | `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | Accepts unknown issuer |
| 23 | `X509_V_ERR_CERT_REVOKED` | Accepts revoked certificates |

**Analysis Instructions**:
When you detect `SSL_CTX_set_verify(ctx, mode, callback)` with a non-NULL callback:
1. Decompile the callback function
2. Check if callback ever returns 1 when `preverify_ok` (first parameter) is 0
3. Check if callback uses `X509_STORE_CTX_get_error()` to selectively ignore errors
4. If any critical error (see table above) is suppressed → result is **UNSATISFIED**
5. If callback always returns 1 regardless of preverify_ok → result is **UNSATISFIED**

### SSL_CTX_set_cert_verify_callback (Complete Override)

`SSL_CTX_set_cert_verify_callback()` sets a callback that **completely replaces** OpenSSL's built-in verification. Unlike `SSL_CTX_set_verify()` callbacks which receive `preverify_ok`, this callback receives no indication of prior verification - it must perform ALL verification itself.

**Critical Difference**:
| API | Callback Signature | Verification |
|-----|-------------------|--------------|
| `SSL_CTX_set_verify` | `callback(int preverify_ok, X509_STORE_CTX *ctx)` | OpenSSL verifies first |
| `SSL_CTX_set_cert_verify_callback` | `callback(X509_STORE_CTX *ctx, void *arg)` | Callback does ALL verification |

**Secure Callback Requirements**:
1. MUST call `X509_verify_cert()` to verify the certificate chain
2. MUST check the return value of `X509_verify_cert()` (1 = success, <=0 = failure)
3. MUST return 0 on verification failure
4. MAY implement additional checks (e.g., pinning) AFTER successful chain verification

**Insecure Patterns**:
```c
// UNSATISFIED: Calls X509_verify_cert() but ignores return value
int callback(X509_STORE_CTX *ctx, void *arg) {
    X509_verify_cert(ctx);  // Return value ignored!
    return my_pinning_check(ctx);  // Only pinning is enforced
}

// UNSATISFIED: Never calls X509_verify_cert()
int callback(X509_STORE_CTX *ctx, void *arg) {
    return my_custom_check(ctx);  // No chain verification
}

// UNSATISFIED: Returns 1 unconditionally
int callback(X509_STORE_CTX *ctx, void *arg) {
    return 1;  // Bypasses all verification
}
```

**Secure Pattern**:
```c
// SATISFIED: Verifies chain AND checks result before custom logic
int callback(X509_STORE_CTX *ctx, void *arg) {
    int ret = X509_verify_cert(ctx);
    if (ret <= 0) {
        return 0;  // Chain verification failed
    }
    // Additional checks (e.g., pinning) only after chain is verified
    return my_pinning_check(ctx);
}
```

**Important**: The callback parameters (`X509_STORE_CTX *ctx`, `void *arg`) are always provided by OpenSSL during the handshake. These are NOT conditions that require dataflow analysis. The security determination is based solely on:
1. Whether `X509_verify_cert()` is called
2. Whether its return value is checked and used to determine the callback's return value
3. If the return value is ignored, result is **UNSATISFIED** (not CONDITIONAL)

**Detection Patterns**:
- Functions: `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_get_verify_result`, `SSL_get_peer_certificate`
- Complete override: `SSL_CTX_set_cert_verify_callback`, `X509_verify_cert`
- Callback analysis: `X509_STORE_CTX_get_error`, `X509_verify_cert_error_string`
- Constants: `SSL_VERIFY_PEER`, `SSL_VERIFY_NONE`, `X509_V_OK`, `X509_V_ERR_*`
- CA loading: `SSL_CTX_load_verify_locations`, `SSL_CTX_set_default_verify_paths`

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` | SATISFIED | Verification enabled |
| `SSL_set_verify(ssl, SSL_VERIFY_PEER, callback)` with proper callback | SATISFIED | Verification with custom logic |
| `SSL_VERIFY_NONE` + `SSL_get_peer_certificate()` + `SSL_get_verify_result()` | SATISFIED | Manual verification (both checks) |
| `SSL_VERIFY_NONE` + only `SSL_get_verify_result()` | UNSATISFIED | Missing peer certificate check (bug) |
| `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)` without manual check | UNSATISFIED | Verification disabled |
| `SSL_CTX_set_verify` not called | UNSATISFIED | Default is `SSL_VERIFY_NONE` |
| Verification mode from runtime variable | CONDITIONAL | Trace variable |
| `SSL_CTX_set_verify` callback always returns 1 | UNSATISFIED | Bypasses all verification |
| `SSL_CTX_set_verify` callback ignores `preverify_ok` | UNSATISFIED | Ignores OpenSSL's verification |
| `SSL_CTX_set_verify` callback suppresses critical errors | UNSATISFIED | Critical errors bypassed |
| `SSL_CTX_set_verify` callback properly propagates `preverify_ok` | SATISFIED | Verification enforced |
| No CA certificates loaded | UNSATISFIED | Chain cannot be verified |
| `SSL_CTX_set_cert_verify_callback` with proper `X509_verify_cert()` check | SATISFIED | Chain verified before custom logic |
| `SSL_CTX_set_cert_verify_callback` ignoring `X509_verify_cert()` result | UNSATISFIED | Chain verification bypassed |
| `SSL_CTX_set_cert_verify_callback` not calling `X509_verify_cert()` | UNSATISFIED | No chain verification |

---

## R3: Hostname Verification

**Meta-Rule(s)**: M4  |  **Priority**: MUST

**What to Verify**: Certificate's Subject Alternative Name (SAN) matches the intended server hostname.

**Implementation**:
- `SSL_set1_host()` (OpenSSL 1.1.0+): Sets expected hostname, enables automatic verification
- `X509_check_host()` (OpenSSL 1.0.2+): Manual hostname verification after handshake
- `SSL_set_hostflags()`: Configure matching flags (e.g., `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`)
- Default behavior: **NO** automatic hostname verification - must be explicitly enabled

**Binary Analysis**:
| Function | Version | Behavior |
|----------|---------|----------|
| `SSL_set1_host` | 1.1.0+ | Automatic verification during handshake |
| `SSL_add1_host` | 1.1.0+ | Add additional hostnames to check |
| `X509_check_host` | 1.0.2+ | Manual verification (post-handshake) |
| `X509_VERIFY_PARAM_set1_host` | 1.0.2+ | Alternative API for hostname setting |
| `SSL_set_hostflags` | 1.1.0+ | Configure verification flags |

**Default Behavior**:
| Version | Default | Security |
|---------|---------|----------|
| All versions | No hostname verification | INSECURE |

### Legacy Hostname Verification (Pre-1.0.2)

For OpenSSL versions prior to 1.0.2, there is no built-in hostname verification API. Applications must implement manual hostname verification:

**Legacy API Functions**:
| Function | Purpose |
|----------|---------|
| `X509_NAME_get_text_by_NID()` | Extract CN from subject |
| `X509_get_ext_d2i(..., NID_subject_alt_name, ...)` | Get SAN extension |
| Manual string comparison | Compare with expected hostname |

**Legacy Verification Pattern (Error-Prone)**:
```c
// Get certificate (already verified in R2)
X509 *cert = SSL_get_peer_certificate(ssl);

// Try Subject Alternative Names first
GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
if (sans != NULL) {
    for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
        GENERAL_NAME *san = sk_GENERAL_NAME_value(sans, i);
        if (san->type == GEN_DNS) {
            // Compare san->d.dNSName with expected hostname
            // MUST handle wildcards correctly
        }
    }
}

// Fallback to Common Name (CN) if no SAN
X509_NAME *subject = X509_get_subject_name(cert);
char cn[256];
X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
// Compare cn with expected hostname
// MUST handle wildcards correctly
```

**Common Vulnerabilities in Legacy Code**:
1. **Missing SAN check**: Only checking CN, ignoring SANs
2. **Incorrect wildcard matching**: `*.example.com` should not match `foo.bar.example.com`
3. **NUL byte injection**: Not handling embedded NUL characters in CN/SAN
4. **Case sensitivity**: Hostname comparison must be case-insensitive
5. **No verification at all**: Many pre-1.0.2 applications simply skip hostname verification

**Detection Patterns**:
- Functions: `SSL_set1_host`, `X509_check_host`, `SSL_set_hostflags`, `X509_VERIFY_PARAM_set1_host`
- Legacy functions: `X509_NAME_get_text_by_NID`, `X509_get_ext_d2i`
- Constants: `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`, `X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS`, `NID_subject_alt_name`, `NID_commonName`
- Vulnerability: Certificate chain verified (R2 passes) but hostname not checked

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `SSL_set1_host(ssl, hostname)` called | SATISFIED | Automatic hostname verification |
| `X509_check_host()` called after handshake | SATISFIED | Manual verification (1.0.2+) |
| `X509_VERIFY_PARAM_set1_host()` called | SATISFIED | Alternative API (1.0.2+) |
| Legacy code with SAN + CN check + proper wildcard handling | SATISFIED | Manual verification (pre-1.0.2) |
| Legacy code with only CN check | CONDITIONAL | Vulnerable if cert has SAN |
| Legacy code with incorrect wildcard matching | UNSATISFIED | Bypass possible |
| No hostname verification function called | UNSATISFIED | Hostname not verified |
| Hostname from runtime variable | CONDITIONAL | Verify hostname source is correct |
| `SSL_set1_host(ssl, NULL)` | UNSATISFIED | Disables hostname checking |
