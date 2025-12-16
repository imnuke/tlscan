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
| R6 | S3 | SHOULD | Entropy/RNG Initialization |
| R7 | O1 | MAY | Certificate Pinning |

**Combined Rule Note**: GnuTLS uses priority strings (`gnutls_priority_set_direct()`) to control both protocol versions and cipher suites simultaneously, hence R4 implements both M2 and M5.

## Version Detection Hints

| Function/Symbol | Indicates |
|-----------------|-----------|
| `gnutls_certificate_verify_peers3()` | GnuTLS 3.0.0+ |
| `gnutls_session_ticket_enable_client()` | GnuTLS 3.1.0+ |
| `gnutls_protocol_set_enabled()` | GnuTLS 3.6.0+ |
| `gnutls_certificate_verify_peers2()` | All versions (older API) |

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

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_handshake()` always called | PASS | TLS connection established |
| GnuTLS functions not called | FAIL | No TLS implementation |
| Plain socket without TLS wrapper | FAIL | Plaintext connection |
| TLS usage depends on config | CONDITIONAL | Trace variable |
| Fallback to plaintext on error | FAIL | Downgrade attack possible |

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

| Verification Flag | Meaning |
|-------------------|---------|
| `GNUTLS_CERT_INVALID` | Certificate invalid |
| `GNUTLS_CERT_SIGNER_NOT_FOUND` | CA not trusted |
| `GNUTLS_CERT_EXPIRED` | Certificate expired |
| `GNUTLS_CERT_REVOKED` | Certificate revoked |
| `GNUTLS_CERT_NOT_ACTIVATED` | Not yet valid |

**Default Behavior**:
| Version | Default | Security |
|---------|---------|----------|
| All versions | No verification | INSECURE |

**Detection Patterns**:
- Vulnerability: No call to `gnutls_certificate_verify_peers2/3()` after handshake
- Vulnerability: Return value not checked for error flags
- Vulnerability: No CA certificates loaded

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_certificate_verify_peers2/3()` called and flags checked | PASS | Verification enabled |
| Verification function not called | FAIL | No certificate validation |
| Return value not checked | FAIL | Errors ignored |
| No CA certificates loaded | FAIL | Chain cannot be verified |
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
- `gnutls_certificate_verify_peers3(session, hostname, &status)` → PASS (automatic)
- `gnutls_x509_crt_check_hostname()` called after handshake → PASS (manual)
- Only `gnutls_certificate_verify_peers2()` without hostname check → FAIL
- No hostname verification function called → FAIL

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `gnutls_certificate_verify_peers3()` with hostname | PASS | Automatic hostname check |
| `gnutls_x509_crt_check_hostname()` called | PASS | Manual hostname check |
| Only `gnutls_certificate_verify_peers2()` | FAIL | No hostname verification |
| No hostname verification | FAIL | Identity not verified |
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
| GnuTLS Version | "NORMAL" Includes | Security |
|----------------|-------------------|----------|
| < 3.6.0 | TLS 1.0, 1.1, 1.2 | INSECURE |
| ≥ 3.6.0 | Vendor-configurable | Check config |

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Priority disables TLS 1.0/1.1 | PASS | Only secure versions |
| `"SECURE128/192/256"` without TLS 1.0/1.1 | PASS | Strong configuration |
| `"NORMAL"` without version restrictions | FAIL | Allows TLS 1.0/1.1 |
| Priority allows NULL/EXPORT ciphers | FAIL | Weak ciphers enabled |
| No priority set | CONDITIONAL | Uses system default |
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
- OCSP stapling enabled → PASS
- CRL loaded → PASS
- No revocation checking → UNDETERMINED (SHOULD requirement)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| OCSP or CRL checking enabled | PASS | Revocation verified |
| No revocation checking | UNDETERMINED | SHOULD requirement |
| Revocation check from config | CONDITIONAL | Trace configuration |

---

## R6: Entropy/RNG Initialization

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

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| System has /dev/urandom | PASS | Automatic entropy |
| Custom RNG with good entropy | PASS | Properly configured |
| No entropy source (embedded) | FAIL | Weak randomness |
| Platform unknown | CONDITIONAL | Check system |

---

## R7: Certificate Pinning

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
- Fingerprint comparison in verify callback → PASS
- Hardcoded certificate hashes → PASS (look for 32-byte or 64-char hex)
- No pinning implemented → UNDETERMINED (optional)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Certificate/key pinning implemented | PASS | Defense-in-depth |
| No pinning | UNDETERMINED | Optional feature |
| Pin values from variable | CONDITIONAL | Trace pin source |
