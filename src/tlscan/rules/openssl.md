# OpenSSL SSL/TLS Security Rules

This document defines library-specific security rules for OpenSSL-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2 | MUST | Protocol Version Enforcement |
| R5 | M5 | MUST | Cipher Suite Selection |
| R6 | S1 | SHOULD | Certificate Revocation Checking |
| R7 | S2 | SHOULD | Cryptographic Strength |
| R8 | S3 | SHOULD | Entropy/RNG Initialization |
| R9 | O1 | MAY | Certificate Pinning |

## Version Detection Hints

Use these patterns to identify OpenSSL version in binaries:

| Function/Symbol | Indicates |
|-----------------|-----------|
| `SSL_CTX_set_min_proto_version()` | OpenSSL 1.1.0+ |
| `SSL_set1_host()` | OpenSSL 1.1.0+ |
| `SSL_CTX_set_ciphersuites()` | OpenSSL 1.1.1+ (TLS 1.3) |
| `SSLv23_client_method()` | Older code (deprecated in 1.1.0) |
| `TLS_client_method()` | OpenSSL 1.1.0+ (preferred) |
| `SSL_CTX_set_options()` with `SSL_OP_NO_*` | Any version (legacy approach) |

---

## OpenSSL Version Defaults

When code does NOT explicitly configure an option, OpenSSL uses these version-specific defaults:

### Default Cipher Suites (R5)

| Version | Default String | Excludes | Security |
|---------|---------------|----------|----------|
| All | `ALL:!COMPLEMENTOFDEFAULT:!eNULL` | RC4, aNULL, eNULL, EXPORT, DES, LOW | SECURE |

**Resolution**: No `SSL_CTX_set_cipher_list()` or `SSL_CTX_set_ciphersuites()` → **SATISFIED** (defaults are secure)

### Default Minimum Protocol (R4)

| Version | Default Min TLS | Security |
|---------|----------------|----------|
| < 3.0 | TLS 1.0 | INSECURE |
| 3.0+ | TLS 1.2 (via security level 1) | SECURE |

**Resolution**: No protocol version set → Check OpenSSL version to determine result

### Default Cryptographic Strength (R7)

| Version | Default Security Level | Min RSA | Min Hash | Security |
|---------|----------------------|---------|----------|----------|
| 1.1.x | Level 1 | 1024-bit | SHA-1 allowed | INSECURE |
| 3.0+ | Level 2 | 2048-bit | SHA-256+ | SECURE |

**Resolution**:
- No strength checking + OpenSSL 3.0+ → **SATISFIED** (security level 2 by default)
- No strength checking + OpenSSL < 3.0 → **UNSATISFIED** (security level 1 allows weak crypto)

### Default Revocation Checking (R6)

| Version | Default | Security |
|---------|---------|----------|
| All | Disabled | N/A (SHOULD requirement) |

**Resolution**: No revocation checking → **UNSATISFIED** (revocation checking not implemented)

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

### Custom Callback Requirements

If a custom verification callback is provided to `SSL_CTX_set_verify()`:

**Secure Callback Requirements**:
1. MUST check `preverify_ok` parameter
2. MUST call `X509_STORE_CTX_get_error()` to retrieve specific error codes
3. MUST return 0 on any verification failure
4. MAY return 1 only for intentional policy decisions (e.g., allowing self-signed certs in specific cases)

**Insecure Callback Patterns**:
```c
// FAIL: Returns 1 unconditionally (bypasses all verification)
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    return 1;
}

// FAIL: Ignores preverify_ok (ignores OpenSSL's verification result)
int callback(int preverify_ok, X509_STORE_CTX *ctx) {
    return my_custom_check(ctx);
}
```

**Detection Patterns**:
- Functions: `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_get_verify_result`, `SSL_get_peer_certificate`
- Constants: `SSL_VERIFY_PEER`, `SSL_VERIFY_NONE`, `X509_V_OK`
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
| Callback always returns 1 | UNSATISFIED | Bypasses all verification |
| Callback ignores `preverify_ok` | UNSATISFIED | Ignores OpenSSL's verification |
| No CA certificates loaded | UNSATISFIED | Chain cannot be verified |

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

---

## R4: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is allowed; SSL 2.0/3.0 and TLS 1.0/1.1 are disabled.

**Implementation**:
- `SSL_CTX_set_min_proto_version()` (OpenSSL 1.1.0+): Set minimum version
- `SSL_CTX_set_options()` with `SSL_OP_NO_*` flags: Disable specific versions (any version)
- Default: Allows all supported versions including insecure ones

**Binary Analysis**:
| Constant | Hex Value | Version | Security |
|----------|-----------|---------|----------|
| `SSL3_VERSION` | 0x0300 | SSL 3.0 | INSECURE |
| `TLS1_VERSION` | 0x0301 | TLS 1.0 | INSECURE |
| `TLS1_1_VERSION` | 0x0302 | TLS 1.1 | INSECURE |
| `TLS1_2_VERSION` | 0x0303 | TLS 1.2 | SECURE |
| `TLS1_3_VERSION` | 0x0304 | TLS 1.3 | SECURE |

| Option Flag | Hex Value | Effect |
|-------------|-----------|--------|
| `SSL_OP_NO_SSLv2` | 0x00000000 | Disabled by default in modern OpenSSL |
| `SSL_OP_NO_SSLv3` | 0x02000000 | Disable SSL 3.0 |
| `SSL_OP_NO_TLSv1` | 0x04000000 | Disable TLS 1.0 |
| `SSL_OP_NO_TLSv1_1` | 0x10000000 | Disable TLS 1.1 |
| `SSL_OP_NO_TLSv1_2` | 0x08000000 | Disable TLS 1.2 (avoid!) |
| `SSL_OP_NO_TLSv1_3` | 0x20000000 | Disable TLS 1.3 (avoid!) |

**Default Behavior (Version-Dependent)**:
| OpenSSL Version | Default Min Protocol | Security |
|-----------------|---------------------|----------|
| < 1.1.0 | SSL 3.0 / TLS 1.0 | INSECURE |
| 1.1.0 - 1.1.1 | TLS 1.0 | INSECURE |
| 3.0+ | Configurable via openssl.cnf | Check config |

**Detection Patterns**:
- Functions: `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_options`, `SSL_get_version`
- Method selection: `TLS_client_method()` (preferred), `SSLv23_client_method()` (deprecated)
- Vulnerability: Missing version restrictions or using deprecated methods

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)` | SATISFIED | TLS 1.2+ enforced |
| `SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3\|SSL_OP_NO_TLSv1\|SSL_OP_NO_TLSv1_1)` | SATISFIED | Legacy disabling method |
| `SSL_CTX_set_options` without disabling TLS 1.0/1.1 | UNSATISFIED | Incomplete protocol restriction |
| No protocol restrictions + OpenSSL 3.0+ | SATISFIED | TLS 1.2 enforced by default (security level 1) |
| No protocol restrictions + OpenSSL < 3.0 | UNSATISFIED | Allows TLS 1.0/1.1 by default |
| No protocol restrictions + version unknown | UNDETERMINED | Cannot determine without version |
| `SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION)` | UNSATISFIED | Allows TLS 1.0 |
| `SSLv3_client_method()` used | UNSATISFIED | Forces SSL 3.0 only |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: MUST

**What to Verify**: Only strong cipher suites are allowed; NULL, RC4, EXPORT, and weak ciphers are disabled.

**Implementation**:
- `SSL_CTX_set_cipher_list()`: Set cipher suites for TLS 1.2 and below
- `SSL_CTX_set_ciphersuites()` (OpenSSL 1.1.1+): Set TLS 1.3 cipher suites
- Recommended string: `"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"`

**Binary Analysis**:
| Cipher String Pattern | Security |
|-----------------------|----------|
| `"HIGH:..."` | Good starting point |
| `"!aNULL"` | REQUIRED - Disables anonymous auth |
| `"!eNULL"` / `"!NULL"` | REQUIRED - Disables NULL encryption |
| `"!EXPORT"` | REQUIRED - Disables export ciphers |
| `"!RC4"` | REQUIRED - Disables RC4 |
| `"!DES"` | REQUIRED - Disables DES |
| `"!MD5"` | REQUIRED - Disables MD5-based MACs |
| `"ALL"` or `"DEFAULT"` without exclusions | INSECURE |
| `"eNULL"` / `"aNULL"` / `"LOW"` / `"EXPORT"` | INSECURE |

**Detection Patterns**:
- Functions: `SSL_CTX_set_cipher_list`, `SSL_CTX_set_ciphersuites`, `SSL_get_cipher_name`
- Vulnerability: No cipher restriction or weak cipher string

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Cipher string excludes NULL, EXPORT, RC4, weak ciphers | SATISFIED | Strong ciphers only |
| `SSL_CTX_set_cipher_list(ctx, "ALL")` | UNSATISFIED | Allows weak ciphers |
| No cipher restrictions set | SATISFIED | OpenSSL default excludes weak ciphers (see Version Defaults) |
| Cipher string from config/env | CONDITIONAL | Trace the value |
| TLS 1.3 only (OpenSSL 1.1.1+) | SATISFIED | TLS 1.3 has no weak ciphers |

---

## R6: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked via CRL or OCSP.

**Implementation**:
- CRL: `X509_STORE_set_flags()` with `X509_V_FLAG_CRL_CHECK` and `X509_V_FLAG_CRL_CHECK_ALL`
- OCSP Stapling: `SSL_CTX_set_tlsext_status_cb()` and `SSL_set_tlsext_status_type()`
- OCSP Manual: `OCSP_sendreq_bio()`, `OCSP_basic_verify()`

**Binary Analysis**:
| Constant | Value | Purpose |
|----------|-------|---------|
| `X509_V_FLAG_CRL_CHECK` | 0x4 | Check leaf certificate CRL |
| `X509_V_FLAG_CRL_CHECK_ALL` | 0x8 | Check entire chain CRL |
| `SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE` | 65 | OCSP stapling control |

**Detection Patterns**:
- Functions: `X509_STORE_set_flags`, `SSL_CTX_set_tlsext_status_cb`, `OCSP_basic_verify`
- CRL loading: `X509_STORE_add_crl`, `X509_load_crl_file`
- Vulnerability: No revocation checking implemented

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| CRL or OCSP checking implemented | SATISFIED | Revocation verified |
| OCSP stapling enabled | SATISFIED | Server provides OCSP response |
| No revocation checking | UNSATISFIED | Revocation checking not implemented |
| Revocation check from config | CONDITIONAL | Trace configuration |

---

## R7: Cryptographic Strength

**Meta-Rule(s)**: S2  |  **Priority**: SHOULD

**What to Verify**: Certificates use strong signature algorithms (SHA-256+) and adequate key sizes.

**Implementation**:
- `X509_get_signature_nid()`: Get signature algorithm NID
- `EVP_PKEY_bits()`: Get key size in bits
- `X509_get_pubkey()`: Extract public key for size checking

**Binary Analysis**:
| Algorithm NID | Name | Security |
|---------------|------|----------|
| `NID_md5WithRSAEncryption` | MD5 | INSECURE |
| `NID_sha1WithRSAEncryption` | SHA-1 | INSECURE |
| `NID_sha256WithRSAEncryption` | SHA-256 | SECURE |
| `NID_sha384WithRSAEncryption` | SHA-384 | SECURE |
| `NID_sha512WithRSAEncryption` | SHA-512 | SECURE |
| `NID_ecdsa_with_SHA256` | ECDSA-SHA256 | SECURE |

| Key Type | Minimum Bits |
|----------|--------------|
| RSA | 2048 |
| ECDSA/ECDH | 256 (224 per RFC) |
| DSA | 2048 |

**Detection Patterns**:
- Functions: `X509_get_signature_nid`, `EVP_PKEY_bits`, `X509_get_pubkey`
- Vulnerability: No strength validation or accepting weak signatures

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Certificate strength validation implemented | SATISFIED | Strong crypto enforced |
| No strength checking + OpenSSL 3.0+ | SATISFIED | Security level 2 by default (see Version Defaults) |
| No strength checking + OpenSSL < 3.0 | UNSATISFIED | Security level 1 allows weak crypto |
| No strength checking + version unknown | UNDETERMINED | Cannot determine without version |
| MD5/SHA-1 signatures explicitly rejected | SATISFIED | Weak algorithms blocked |

---

## R8: Entropy/RNG Initialization

**Meta-Rule(s)**: S3  |  **Priority**: SHOULD

**What to Verify**: Cryptographic RNG is properly seeded before TLS operations.

**Implementation**:
- `RAND_poll()`: Automatic seeding from system entropy (preferred)
- `RAND_seed()` / `RAND_add()`: Manual seeding
- `RAND_status()`: Check if RNG is properly seeded (returns 1 if OK)
- OpenSSL 1.1.0+: Automatic seeding on first use if /dev/urandom available

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `RAND_poll` | Seed from OS entropy sources |
| `RAND_seed` | Add entropy manually |
| `RAND_add` | Add entropy with estimate |
| `RAND_status` | Check seeding status |
| `RAND_bytes` | Generate random bytes |

**Default Behavior (Version-Dependent)**:
| Version | Platform | Default |
|---------|----------|---------|
| OpenSSL 1.1.0+ | Linux/macOS | Auto-seeded from /dev/urandom |
| OpenSSL 1.1.0+ | Embedded/No OS | **MUST** call `RAND_seed()` |
| OpenSSL 1.0.x | All | May require explicit seeding |

**Detection Patterns**:
- Functions: `RAND_poll`, `RAND_seed`, `RAND_add`, `RAND_status`
- Vulnerability indicators:
  - `RAND_seed(buffer, sizeof(buffer))` with predictable buffer (time, PID)
  - No entropy initialization on embedded systems
  - `rand()` or `srand()` used instead of RAND_* functions

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `RAND_poll()` called or system has /dev/urandom | SATISFIED | Proper entropy |
| `RAND_seed()` with hardware RNG data | SATISFIED | Good entropy source |
| `RAND_seed(time(NULL), sizeof(time_t))` | UNSATISFIED | Predictable seed |
| No RNG initialization on embedded system | UNSATISFIED | Weak randomness |
| System entropy availability unknown | CONDITIONAL | Check platform |

---

## R9: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented for high-security applications.

**Implementation**:
- Custom verify callback via `SSL_CTX_set_verify()` or `SSL_set_verify()`
- `X509_digest()`: Get certificate fingerprint
- `X509_get_pubkey()` + hash: Get public key hash (SPKI pinning)
- Compare against hardcoded/stored pin values

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `X509_digest` | Certificate fingerprint |
| `EVP_sha256` | SHA-256 for fingerprint |
| `X509_get_pubkey` | Extract public key |
| `i2d_PUBKEY` | Serialize public key (for SPKI) |
| Custom callback | Pin validation logic |

**Detection Patterns**:
- Functions: `X509_digest`, `EVP_sha256`, `X509_get_pubkey`, custom verification callbacks
- Hardcoded hashes: Look for 32-byte (SHA-256) or 64-character hex strings
- Vulnerability: Pinning without backup pins (lockout risk)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Certificate/public key pinning implemented | SATISFIED | Defense-in-depth |
| No pinning implemented | UNSATISFIED | Pinning not implemented |
| Pinning with no backup pins | SATISFIED (with warning) | Lockout risk noted |
| Pin values from external source | CONDITIONAL | Trace pin source |
