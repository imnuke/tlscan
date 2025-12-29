# GnuTLS SSL/TLS Security Rules

This document defines library-specific security rules for GnuTLS-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2, M5 | MUST | Protocol Version & Cipher Selection (Combined) |
| R5 | S1 | SHOULD | Certificate Revocation Checking |
| R6 | S2 | SHOULD | Cryptographic Strength |
| R7 | S3 | SHOULD | Entropy/RNG Initialization |
| R8 | O1 | MAY | Certificate Pinning |

**Notes**:
- R4 implements both M2 and M5 because GnuTLS uses priority strings (`gnutls_priority_set_direct()`) to control both protocol versions and cipher suites simultaneously.
- R6 (S2) can be enforced via priority string keywords like `SECURE128`, `SECURE192`, `SECURE256`.

## Version Detection Hints

| Function/Symbol | Indicates |
|-----------------|-----------|
| `gnutls_certificate_verify_peers3()` | GnuTLS 3.0.0+ |
| `gnutls_session_ticket_enable_client()` | GnuTLS 3.1.0+ |
| `gnutls_protocol_set_enabled()` | GnuTLS 3.6.0+ |
| `gnutls_certificate_verify_peers2()` | All versions (older API) |

## ⚠️ CRITICAL: Applicability Check

**This ruleset applies ONLY to binaries that implement TLS clients using GnuTLS.**

### Required Functions for Applicability

A binary MUST call this function to be applicable:
- `gnutls_handshake()` - TLS handshake

### Non-Applicable: Setup-Only Usage

If a binary only imports these functions WITHOUT `gnutls_handshake`:

| Function | Purpose | TLS Relevance |
|----------|---------|---------------|
| `gnutls_init` | Create session | Setup only |
| `gnutls_deinit` | Destroy session | Cleanup only |
| `gnutls_global_init` | Initialize library | Setup only |
| `gnutls_global_deinit` | Cleanup library | Cleanup only |
| `gnutls_certificate_allocate_credentials` | Alloc creds | Setup only |

**→ Set `applicable=false` with reason: "Binary uses GnuTLS setup/utility functions only (no gnutls_handshake)"**

### Binary Analysis Flow

1. **FIRST**: Check for `gnutls_handshake` imports/calls
2. **If NOT found**: Set `applicable=false`
3. **If found**: Continue with rule analysis (R1-R8)

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm TLS is actually used for connections, not just linked.

**Implementation**:
- `gnutls_init()`: Initialize TLS session
- `gnutls_handshake()`: Perform TLS handshake - MUST be called
- Default behavior: No TLS unless explicitly initialized and handshake performed

**Binary Analysis**:
| Function | Purpose | Required |
|----------|---------|----------|
| `gnutls_init` | Create TLS session | Yes |
| `gnutls_credentials_set` | Set credentials | Yes |
| `gnutls_handshake` | TLS handshake | Yes |
| `gnutls_record_send` / `gnutls_record_recv` | Data transfer | Yes (after handshake) |

**Detection Patterns**:
- Functions: `gnutls_init`, `gnutls_handshake`, `gnutls_record_send`, `gnutls_record_recv`
- Conditional patterns:
  - `if (use_tls)` before `gnutls_init()`
  - Port-based: different code paths for different ports
  - Protocol-based: checking URL scheme before TLS setup
- Vulnerability indicators:
  - GnuTLS functions linked but never called
  - Plain socket operations without GnuTLS wrapper
  - Conditional TLS defaulting to disabled
  - Plaintext fallback on handshake error

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_handshake()` always called | SATISFIED | TLS connection established |
| GnuTLS functions not called | UNSATISFIED | No TLS implementation |
| Plain socket without TLS wrapper | UNSATISFIED | Plaintext connection |
| TLS usage depends on config | CONDITIONAL | Trace variable |
| Fallback to plaintext on error | UNSATISFIED | Downgrade attack possible |

---

## R2: Certificate Chain Verification

**Meta-Rule(s)**: M3  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated against trusted CA store.

**Implementation**:
- `gnutls_certificate_verify_peers2()` / `gnutls_certificate_verify_peers3()`: Verify certificate
- Check return value for `GNUTLS_CERT_INVALID` flag
- `gnutls_certificate_set_x509_trust_file()`: Load CA certificates
- Default: **NO** automatic verification - must be explicitly called

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `gnutls_certificate_verify_peers2` | Verify certificate (older API) |
| `gnutls_certificate_verify_peers3` | Verify with hostname (3.0.0+) |
| `gnutls_certificate_set_x509_trust_file` | Load CA bundle |
| `gnutls_certificate_set_x509_system_trust` | Use system CA store |

| Verification Flag | Value | Meaning |
|-------------------|-------|---------|
| `GNUTLS_CERT_INVALID` | (1<<1) | Certificate invalid (check other flags for reason) |
| `GNUTLS_CERT_SIGNER_NOT_FOUND` | (1<<6) | CA not trusted |
| `GNUTLS_CERT_EXPIRED` | (1<<10) | Certificate expired |
| `GNUTLS_CERT_REVOKED` | (1<<5) | Certificate revoked |
| `GNUTLS_CERT_NOT_ACTIVATED` | (1<<11) | Not yet valid |
| `GNUTLS_CERT_SIGNATURE_FAILURE` | (1<<2) | Signature verification failed |
| `GNUTLS_CERT_INSECURE_ALGORITHM` | (1<<8) | Weak algorithm used |

**Default Behavior**:
| Version | Default | Security |
|---------|---------|----------|
| All versions | No verification | INSECURE |

### Proper Verification Pattern

**Correct Usage**:
```c
unsigned int status;
int ret;

// After gnutls_handshake() succeeds:
ret = gnutls_certificate_verify_peers2(session, &status);
if (ret < 0) {
    // UNSATISFIED - verification function failed
    gnutls_perror(ret);
    return error;
}

if (status != 0) {
    // UNSATISFIED - certificate verification failed
    // Check specific flags for details:
    if (status & GNUTLS_CERT_INVALID) {
        // Certificate is invalid
    }
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
        // Issuing CA not trusted
    }
    if (status & GNUTLS_CERT_EXPIRED) {
        // Certificate expired
    }
    return error;
}
// status == 0 means certificate is valid
```

**Incorrect Verification Patterns (Vulnerabilities)**:
```c
// UNSATISFIED: Only checking return value, ignoring status flags
ret = gnutls_certificate_verify_peers2(session, &status);
if (ret < 0) { handle_error(); }
// Missing: check for status != 0

// UNSATISFIED: Not calling verification at all
gnutls_handshake(session);
// Proceeding without calling gnutls_certificate_verify_peers2/3()

// UNSATISFIED: Ignoring the status variable entirely
gnutls_certificate_verify_peers2(session, &status);
// status not checked - all certificates accepted
```

### Certificate Presence Check

Unlike OpenSSL, GnuTLS returns `GNUTLS_E_NO_CERTIFICATE_FOUND` from `gnutls_certificate_verify_peers2()` if no certificate was provided, so the bug of "OK without certificate" does not exist in the same form.

However, you should still check for this error:
```c
ret = gnutls_certificate_verify_peers2(session, &status);
if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND) {
    // UNSATISFIED - server provided no certificate
    return error;
}
```

**Detection Patterns**:
- Vulnerability: No call to `gnutls_certificate_verify_peers2/3()` after handshake
- Vulnerability: Return value not checked (ret < 0)
- Vulnerability: Status flags not checked (status != 0)
- Vulnerability: No CA certificates loaded

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_certificate_verify_peers2/3()` called, ret and status checked | SATISFIED | Full verification |
| Verification function not called | UNSATISFIED | No certificate validation |
| Return value (ret) not checked | UNSATISFIED | Function errors ignored |
| Status flags not checked | UNSATISFIED | Verification result ignored |
| Only checks `ret < 0`, not `status != 0` | UNSATISFIED | Accepts invalid certificates |
| No CA certificates loaded | UNSATISFIED | Chain cannot be verified |
| Verification depends on config | CONDITIONAL | Trace variable |

---

## R3: Hostname Verification

**Meta-Rule(s)**: M4  |  **Priority**: MUST

**What to Verify**: Certificate's identity matches the intended server hostname.

**Implementation**:
- `gnutls_server_name_set()` with `GNUTLS_NAME_DNS`: Set expected hostname (SNI)
- `gnutls_certificate_verify_peers3()` with hostname parameter (preferred)
- `gnutls_x509_crt_check_hostname()`: Manual hostname verification
- Default: **NO** automatic hostname verification

**Binary Analysis**:
| Function | Version | Purpose |
|----------|---------|---------|
| `gnutls_server_name_set` | All | Set SNI hostname |
| `gnutls_certificate_verify_peers3` | 3.0.0+ | Verify with hostname |
| `gnutls_x509_crt_check_hostname` | All | Manual hostname check |

**Default Behavior**:
| Version | Default | Security |
|---------|---------|----------|
| All versions | No hostname verification | INSECURE |

**Detection Patterns**:
- `gnutls_certificate_verify_peers3(session, hostname, &status)` → SATISFIED (automatic)
- `gnutls_x509_crt_check_hostname()` called after handshake → SATISFIED (manual)
- Only `gnutls_certificate_verify_peers2()` without hostname check → UNSATISFIED
- No hostname verification function called → UNSATISFIED

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_certificate_verify_peers3()` with hostname | SATISFIED | Automatic hostname check |
| `gnutls_x509_crt_check_hostname()` called | SATISFIED | Manual hostname check |
| Only `gnutls_certificate_verify_peers2()` | UNSATISFIED | No hostname verification |
| No hostname verification | UNSATISFIED | Identity not verified |
| Hostname from variable | CONDITIONAL | Verify hostname source |

---

## R4: Protocol Version & Cipher Selection (Combined)

**Meta-Rule(s)**: M2, M5  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2+ is allowed and strong cipher suites are used.

**Implementation**:
- `gnutls_priority_set_direct()`: Set protocol and cipher priority string
- Priority string controls BOTH protocol versions AND cipher suites
- Default "NORMAL" includes TLS 1.0/1.1 - **INSECURE**
- Must use `-VERS-TLS1.0:-VERS-TLS1.1` to disable insecure versions

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `gnutls_priority_set_direct` | Set priority string |
| `gnutls_priority_init` | Initialize priority cache |
| `gnutls_priority_set` | Apply priority cache |
| `gnutls_protocol_set_enabled` | Enable/disable protocols (3.6.0+) |

**Priority String Keywords**:
| Keyword | Meaning |
|---------|---------|
| `NORMAL` | Default - includes TLS 1.0/1.1 (INSECURE) |
| `SECURE128` | 128-bit security minimum |
| `SECURE192` | 192-bit security minimum |
| `SECURE256` | 256-bit security minimum |
| `-VERS-TLS1.0` | Disable TLS 1.0 |
| `-VERS-TLS1.1` | Disable TLS 1.1 |
| `+VERS-TLS1.2` | Enable TLS 1.2 |
| `+VERS-TLS1.3` | Enable TLS 1.3 |
| `%SAFE_RENEGOTIATION` | Require safe renegotiation |

**Secure Priority Strings**:
```
"NORMAL:-VERS-TLS1.0:-VERS-TLS1.1"
"SECURE128:-VERS-TLS1.0:-VERS-TLS1.1"
"SECURE256:%SAFE_RENEGOTIATION"
"-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
```

**Insecure Priority Strings**:
```
"NORMAL" (allows TLS 1.0/1.1)
"NORMAL:+VERS-SSL3.0"
"+NULL" (allows NULL encryption)
"+EXPORT" (allows export ciphers)
```

**Default Behavior (Version-Dependent)**:
| GnuTLS Version | "NORMAL" Includes | Default Min TLS | Security |
|----------------|-------------------|-----------------|----------|
| 3.7.0+ | Vendor-configurable | TLS 1.2 | SECURE |
| 3.6.0 - 3.6.x | Vendor-configurable | TLS 1.2 | SECURE |
| < 3.6.0 | TLS 1.0, 1.1, 1.2 | TLS 1.0 | INSECURE |

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Priority disables TLS 1.0/1.1 | SATISFIED | Only secure versions |
| `"SECURE128/192/256"` without TLS 1.0/1.1 | SATISFIED | Strong configuration |
| `"NORMAL"` without version restrictions | UNSATISFIED | Allows TLS 1.0/1.1 |
| Priority allows NULL/EXPORT ciphers | UNSATISFIED | Weak ciphers enabled |
| No priority configured | DEFAULT | Not explicitly configured |
| Priority string from variable | CONDITIONAL | Trace variable |

---

## R5: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked via OCSP or CRL.

**Implementation**:
- OCSP Stapling: `gnutls_ocsp_status_request_enable_client()`
- OCSP Response: `gnutls_ocsp_status_request_get()` after handshake
- CRL: `gnutls_certificate_set_x509_crl_file()`

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `gnutls_ocsp_status_request_enable_client` | Request OCSP stapling |
| `gnutls_ocsp_status_request_get` | Get stapled OCSP response |
| `gnutls_certificate_set_x509_crl_file` | Load CRL file |
| `gnutls_certificate_set_x509_crl` | Set CRL from memory |

**Detection Patterns**:
- OCSP stapling enabled → SATISFIED
- CRL loaded → SATISFIED
- No revocation checking → DEFAULT (not explicitly configured)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| OCSP or CRL checking enabled | SATISFIED | Revocation verified |
| No revocation checking | DEFAULT | Not explicitly configured |
| Revocation check from config | CONDITIONAL | Trace configuration |

---

## R6: Cryptographic Strength

**Meta-Rule(s)**: S2  |  **Priority**: SHOULD

**What to Verify**: Certificates use strong signature algorithms (SHA-256+) and adequate key sizes (RSA 2048+).

**Implementation**:
- `gnutls_priority_set_direct()`: Set security level via priority string
- `SECURE128`: 128-bit minimum security level (RSA 2048+, SHA-256+)
- `SECURE192`: 192-bit minimum security level (RSA 3072+)
- `SECURE256`: 256-bit minimum security level (RSA 15360+, SHA-384+)
- `%VERIFY_ALLOW_BROKEN`: INSECURE - allows weak algorithms

**Priority String Keywords**:
| Keyword | Minimum Key Size | Hash Algorithm | Security |
|---------|------------------|----------------|----------|
| `SECURE128` | RSA 2048, ECDSA 256 | SHA-256+ | SATISFIED |
| `SECURE192` | RSA 3072, ECDSA 384 | SHA-384+ | SATISFIED |
| `SECURE256` | RSA 15360, ECDSA 512 | SHA-384+ | SATISFIED |
| `NORMAL` | RSA 1024 (older versions) | May include SHA-1 | Version-dependent |
| `%VERIFY_ALLOW_BROKEN` | Any | Any (including MD5) | UNSATISFIED |

**Default Behavior (Version-Dependent)**:
| GnuTLS Version | "NORMAL" Includes | Security |
|----------------|-------------------|----------|
| < 3.6.0 | RSA 1024, SHA-1 | UNSATISFIED |
| ≥ 3.6.0 | RSA 2048+, SHA-256+ | SATISFIED |

**Detection Patterns**:
- Priority string contains `SECURE128`, `SECURE192`, `SECURE256` → SATISFIED
- Priority string contains `%VERIFY_ALLOW_BROKEN` → UNSATISFIED
- Priority string is `NORMAL` + GnuTLS ≥ 3.6.0 → SATISFIED
- Priority string is `NORMAL` + GnuTLS < 3.6.0 → UNSATISFIED

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Priority uses `SECURE128/192/256` | SATISFIED | Strong crypto enforced |
| Priority uses `%VERIFY_ALLOW_BROKEN` | UNSATISFIED | Weak crypto allowed |
| No crypto strength configured | DEFAULT | Not explicitly configured |
| Priority string from variable | CONDITIONAL | Trace variable |

---

## R7: Entropy/RNG Initialization

**Meta-Rule(s)**: S3  |  **Priority**: SHOULD

**What to Verify**: Cryptographic RNG is properly initialized.

**Implementation**:
- GnuTLS uses system entropy (`/dev/urandom`) by default
- `gnutls_rnd()`: Generate random data
- On embedded systems: may need `gnutls_rnd_set_device()` or custom callback

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `gnutls_rnd` | Generate random bytes |
| `gnutls_rnd_set_device` | Set RNG device path |
| Custom RNG callback | Override default RNG |

**Default Behavior**:
| Platform | Default | Security |
|----------|---------|----------|
| Linux/macOS | /dev/urandom | SECURE |
| Embedded | May need configuration | Check platform |

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| System has /dev/urandom | SATISFIED | Automatic entropy |
| Custom RNG with good entropy | SATISFIED | Properly configured |
| No entropy source (embedded) | UNSATISFIED | Weak randomness |
| Platform unknown | CONDITIONAL | Check system |

---

## R8: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented.

**Implementation**:
- `gnutls_certificate_get_peers()`: Get server certificate chain
- `gnutls_x509_crt_get_fingerprint()`: Get certificate fingerprint
- `gnutls_certificate_set_verify_function()`: Custom verification callback
- Compare fingerprint against hardcoded/stored values

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `gnutls_certificate_get_peers` | Get peer certificates |
| `gnutls_x509_crt_get_fingerprint` | Get cert fingerprint |
| `gnutls_x509_crt_get_key_id` | Get public key ID |
| `gnutls_certificate_set_verify_function` | Custom verification |

**Detection Patterns**:
- Fingerprint comparison in verify callback → SATISFIED
- Hardcoded certificate hashes → SATISFIED (look for 32-byte or 64-char hex)
- No pinning implemented → UNSATISFIED (pinning not implemented)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Certificate/key pinning implemented | SATISFIED | Defense-in-depth |
| No pinning | UNSATISFIED | Pinning not implemented |
| Pin values from variable | CONDITIONAL | Trace pin source |
