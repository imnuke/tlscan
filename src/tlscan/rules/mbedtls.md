# mbedTLS SSL/TLS Security Rules

This document defines library-specific security rules for mbedTLS-based TLS client implementations. Each rule references the corresponding meta-rule(s) from `metarule.md`.

**Note**: mbedTLS is commonly used in embedded systems and IoT devices where resources are constrained. Entropy initialization (R7) is particularly critical in these environments.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3 | MUST | Certificate Chain Verification |
| R3 | M4 | MUST | Hostname Verification |
| R4 | M2 | MUST | Protocol Version Enforcement |
| R5 | M5 | MUST | Cipher Suite Selection |
| R6 | S1 | SHOULD | Certificate Revocation Checking |
| R7 | S3 | SHOULD | Entropy/RNG Initialization (CRITICAL for embedded) |
| R8 | O1 | MAY | Certificate Pinning |

## Version Detection Hints

| Function/Symbol | Indicates |
|-----------------|-----------|
| `mbedtls_ssl_conf_min_tls_version()` | mbedTLS 3.0.0+ |
| `mbedtls_ssl_conf_min_version()` | mbedTLS 2.x (deprecated in 3.0) |
| `mbedtls_ssl_config_defaults()` | All versions |
| `mbedtls_ssl_set_hostname()` | All versions |

## Binary Analysis Reference

### Authentication Mode Constants

| Constant | Value | Security |
|----------|-------|----------|
| `MBEDTLS_SSL_VERIFY_NONE` | 0 | INSECURE |
| `MBEDTLS_SSL_VERIFY_OPTIONAL` | 1 | INSECURE (requires manual check) |
| `MBEDTLS_SSL_VERIFY_REQUIRED` | 2 | SECURE |

### TLS Version Constants (mbedTLS 2.x)

| Constant | Major | Minor | Version |
|----------|-------|-------|---------|
| SSL 3.0 | 3 | 0 | INSECURE |
| TLS 1.0 | 3 | 1 | INSECURE |
| TLS 1.1 | 3 | 2 | INSECURE |
| TLS 1.2 | 3 | 3 | SECURE |
| TLS 1.3 | 3 | 4 | SECURE |

### TLS Version Constants (mbedTLS 3.x)

| Constant | Value | Version |
|----------|-------|---------|
| `MBEDTLS_SSL_VERSION_TLS1_2` | 0x0303 | TLS 1.2 |
| `MBEDTLS_SSL_VERSION_TLS1_3` | 0x0304 | TLS 1.3 |

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm TLS is actually used for connections, not just linked.

**Implementation**:
- `mbedtls_ssl_setup()`: Configure SSL context
- `mbedtls_ssl_handshake()`: Perform TLS handshake - MUST be called
- `mbedtls_ssl_set_bio()`: Attach I/O callbacks
- Default behavior: No TLS unless explicitly initialized and handshake performed

**Binary Analysis**:
| Function | Purpose | Required |
|----------|---------|----------|
| `mbedtls_ssl_init` | Initialize SSL context | Yes |
| `mbedtls_ssl_config_init` | Initialize config | Yes |
| `mbedtls_ssl_setup` | Apply config to context | Yes |
| `mbedtls_ssl_set_bio` | Set I/O callbacks | Yes |
| `mbedtls_ssl_handshake` | TLS handshake | Yes |
| `mbedtls_ssl_write` / `mbedtls_ssl_read` | Data transfer | Yes |

**Detection Patterns**:
- Functions: `mbedtls_ssl_setup`, `mbedtls_ssl_handshake`, `mbedtls_ssl_write`, `mbedtls_ssl_read`
- Initialization: `mbedtls_ssl_config_init` followed by actual usage
- Conditional patterns: TLS setup inside conditional branches
- Config-based: SSL enabled via configuration flags

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `mbedtls_ssl_handshake()` always called | PASS | TLS connection established |
| mbedTLS functions linked but not called | FAIL | No TLS implementation |
| Plain socket without mbedTLS wrapper | FAIL | Plaintext connection |
| TLS usage depends on config | CONDITIONAL | Trace variable |
| Fallback to plaintext on error | FAIL | Downgrade attack possible |

---

## R2: Certificate Chain Verification

**Meta-Rule(s)**: M3  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated against trusted CA store.

**Implementation**:
- `mbedtls_ssl_conf_authmode()`: Set verification mode
- `mbedtls_ssl_conf_ca_chain()`: Set trusted CA certificates
- Default for clients: `MBEDTLS_SSL_VERIFY_REQUIRED` (value 2) - **SECURE**

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `mbedtls_ssl_conf_authmode` | Set verification mode |
| `mbedtls_ssl_conf_ca_chain` | Set CA certificate chain |
| `mbedtls_ssl_get_verify_result` | Get verification result |
| `mbedtls_x509_crt_parse_file` | Load CA certificate file |
| `mbedtls_x509_crt_parse` | Parse CA certificate from memory |

| Mode | Value | Security |
|------|-------|----------|
| `MBEDTLS_SSL_VERIFY_NONE` | 0 | INSECURE |
| `MBEDTLS_SSL_VERIFY_OPTIONAL` | 1 | INSECURE (unless manual check performed) |
| `MBEDTLS_SSL_VERIFY_REQUIRED` | 2 | SECURE |

**Default Behavior**:
| Endpoint | Default Mode | Security |
|----------|--------------|----------|
| Client | `MBEDTLS_SSL_VERIFY_REQUIRED` (2) | SECURE |
| Server | `MBEDTLS_SSL_VERIFY_NONE` (0) | N/A (server mode) |

### MBEDTLS_SSL_VERIFY_OPTIONAL with Manual Verification

When `MBEDTLS_SSL_VERIFY_OPTIONAL` is used, the handshake succeeds even if certificate verification fails. The application **MUST** manually check the verification result:

**Correct Manual Verification Pattern**:
```c
// Set OPTIONAL mode (perhaps for custom error handling)
mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

// After mbedtls_ssl_handshake() succeeds:
uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
if (flags != 0) {
    // FAIL - certificate verification failed
    char buf[512];
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", flags);
    // Log/handle error: buf contains human-readable error
    return error;
}
// flags == 0 means verification passed
```

**Verification Result Flags**:
| Flag | Meaning |
|------|---------|
| `MBEDTLS_X509_BADCERT_EXPIRED` | Certificate expired |
| `MBEDTLS_X509_BADCERT_REVOKED` | Certificate revoked |
| `MBEDTLS_X509_BADCERT_CN_MISMATCH` | CN/SAN mismatch (hostname) |
| `MBEDTLS_X509_BADCERT_NOT_TRUSTED` | Not signed by trusted CA |
| `MBEDTLS_X509_BADCRL_NOT_TRUSTED` | CRL not trusted |
| `MBEDTLS_X509_BADCRL_EXPIRED` | CRL expired |
| `MBEDTLS_X509_BADCERT_MISSING` | No certificate provided |
| `MBEDTLS_X509_BADCERT_SKIP_VERIFY` | Verification was skipped |

**Incorrect Patterns (Vulnerabilities)**:
```c
// FAIL: OPTIONAL without checking result
mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
mbedtls_ssl_handshake(&ssl);
// Proceeding without calling mbedtls_ssl_get_verify_result()

// FAIL: Checking result but not handling failure
flags = mbedtls_ssl_get_verify_result(&ssl);
// flags not checked - proceeding regardless
```

### Certificate Presence Check

Unlike OpenSSL, mbedTLS sets `MBEDTLS_X509_BADCERT_MISSING` flag when no certificate is provided, so checking `flags != 0` will catch this case. However, when using `VERIFY_NONE`, you must explicitly check:

```c
// With VERIFY_NONE, you must get the peer certificate manually
const mbedtls_x509_crt *peer_cert = mbedtls_ssl_get_peer_cert(&ssl);
if (peer_cert == NULL) {
    // FAIL - no certificate provided
    return error;
}
```

**Detection Patterns**:
- `mbedtls_ssl_conf_authmode(conf, 2)` → PASS (REQUIRED)
- `mbedtls_ssl_conf_authmode(conf, 0)` → FAIL (NONE)
- `mbedtls_ssl_conf_authmode(conf, 1)` + `mbedtls_ssl_get_verify_result()` checked → PASS
- `mbedtls_ssl_conf_authmode(conf, 1)` without result check → FAIL
- `mbedtls_ssl_conf_authmode` not called → PASS (default is REQUIRED for clients)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Authmode set to `REQUIRED` (2) | PASS | Verification enabled |
| Authmode not set (client) | PASS | Default is REQUIRED |
| Authmode set to `NONE` (0) | FAIL | Verification disabled |
| `OPTIONAL` (1) without `mbedtls_ssl_get_verify_result()` check | FAIL | Errors ignored |
| `OPTIONAL` (1) + `mbedtls_ssl_get_verify_result()` checked for 0 | PASS | Manual verification |
| `NONE` (0) + `mbedtls_ssl_get_peer_cert()` + manual verification | CONDITIONAL | Check implementation |
| Authmode from variable | CONDITIONAL | Trace variable |
| No CA chain loaded | FAIL | Chain cannot be verified |

---

## R3: Hostname Verification

**Meta-Rule(s)**: M4  |  **Priority**: MUST

**What to Verify**: Certificate's identity matches the intended server hostname.

**Implementation**:
- `mbedtls_ssl_set_hostname()`: Set expected hostname
- Automatic verification when hostname is set AND authmode is REQUIRED
- Default: **NO** hostname verification unless `mbedtls_ssl_set_hostname()` is called

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `mbedtls_ssl_set_hostname` | Set expected hostname for verification |
| `mbedtls_x509_crt_verify_with_profile` | Manual verification with profile |

**Default Behavior**:
| Version | Default | Security |
|---------|---------|----------|
| All versions | No hostname verification | INSECURE |

**Detection Patterns**:
- `mbedtls_ssl_set_hostname(ssl, hostname)` called → PASS (automatic)
- `mbedtls_ssl_set_hostname` not called → FAIL (no hostname verification)
- `mbedtls_ssl_set_hostname(ssl, NULL)` → FAIL (disabled)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `mbedtls_ssl_set_hostname()` called with hostname | PASS | Hostname verified |
| `mbedtls_ssl_set_hostname()` not called | FAIL | Hostname not verified |
| `mbedtls_ssl_set_hostname(ssl, NULL)` | FAIL | Hostname verification disabled |
| Hostname from variable | CONDITIONAL | Verify hostname source |

---

## R4: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is allowed.

**Implementation**:
- mbedTLS 2.x: `mbedtls_ssl_conf_min_version()` / `mbedtls_ssl_conf_max_version()`
- mbedTLS 3.x: `mbedtls_ssl_conf_min_tls_version()` / `mbedtls_ssl_conf_max_tls_version()`
- Default: Depends on compile-time configuration

**Binary Analysis**:
| Function (2.x) | Function (3.x) | Purpose |
|----------------|----------------|---------|
| `mbedtls_ssl_conf_min_version` | `mbedtls_ssl_conf_min_tls_version` | Set minimum version |
| `mbedtls_ssl_conf_max_version` | `mbedtls_ssl_conf_max_tls_version` | Set maximum version |

**Version Values (mbedTLS 2.x)**:
| Major | Minor | Version | Security |
|-------|-------|---------|----------|
| 3 | 0 | SSL 3.0 | INSECURE |
| 3 | 1 | TLS 1.0 | INSECURE |
| 3 | 2 | TLS 1.1 | INSECURE |
| 3 | 3 | TLS 1.2 | SECURE |
| 3 | 4 | TLS 1.3 | SECURE |

**Version Values (mbedTLS 3.x)**:
| Constant | Value | Security |
|----------|-------|----------|
| `MBEDTLS_SSL_VERSION_TLS1_2` | 0x0303 | SECURE |
| `MBEDTLS_SSL_VERSION_TLS1_3` | 0x0304 | SECURE |

**Detection Patterns**:
- mbedTLS 2.x: `mbedtls_ssl_conf_min_version(conf, 3, 3)` → PASS (TLS 1.2)
- mbedTLS 3.x: `mbedtls_ssl_conf_min_tls_version(conf, 0x0303)` → PASS (TLS 1.2)
- `mbedtls_ssl_conf_min_version(conf, 3, 1)` → FAIL (allows TLS 1.0)
- No version restriction → CONDITIONAL (depends on build config)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Min version set to TLS 1.2 (3,3) or higher | PASS | Secure versions only |
| Min version allows TLS 1.0/1.1 | FAIL | Insecure protocols allowed |
| No version restriction set | CONDITIONAL | Depends on build configuration |
| Version from variable | CONDITIONAL | Trace variable |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: MUST

**What to Verify**: Only strong cipher suites are enabled.

**Implementation**:
- `mbedtls_ssl_conf_ciphersuites()`: Set allowed cipher suite IDs
- Pass array of cipher suite IDs terminated with 0
- Cipher suites are compile-time configurable in mbedTLS config

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `mbedtls_ssl_conf_ciphersuites` | Set allowed cipher suites |
| `mbedtls_ssl_get_ciphersuite_id` | Get cipher suite by name |

**Cipher Suite Categories**:
| Pattern | Security |
|---------|----------|
| `*_WITH_NULL_*` | INSECURE (no encryption) |
| `*_EXPORT_*` | INSECURE (weak) |
| `*_DES_*` | INSECURE (weak) |
| `*_RC4_*` | INSECURE (broken) |
| `*_AES_*_GCM_*` | SECURE (AEAD) |
| `*_CHACHA20_POLY1305_*` | SECURE (AEAD) |
| `*_AES_*_CCM_*` | SECURE (AEAD) |

**Detection Patterns**:
- Cipher array includes only AEAD suites → PASS
- Cipher array includes NULL/EXPORT/RC4 → FAIL
- No cipher restriction → CONDITIONAL (uses build default)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Only strong ciphers (GCM, CCM, ChaCha) | PASS | Weak ciphers excluded |
| NULL/EXPORT/RC4/DES ciphers allowed | FAIL | Insecure ciphers |
| No cipher configuration | CONDITIONAL | Uses compile-time default |
| Cipher list from variable | CONDITIONAL | Trace variable |

---

## R6: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked via CRL.

**Implementation**:
- CRL: `mbedtls_x509_crl_parse()` to load CRL
- Pass CRL to `mbedtls_ssl_conf_ca_chain()` or verification functions
- OCSP: Not natively supported in mbedTLS

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `mbedtls_x509_crl_init` | Initialize CRL structure |
| `mbedtls_x509_crl_parse` | Parse CRL from memory |
| `mbedtls_x509_crl_parse_file` | Parse CRL from file |
| `mbedtls_ssl_conf_ca_chain` | Set CA chain with CRL |

**Detection Patterns**:
- CRL loaded and passed to verification → PASS
- No CRL checking → UNDETERMINED (SHOULD requirement)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| CRL checking implemented | PASS | Revocation verified |
| No CRL checking | UNDETERMINED | SHOULD requirement |
| CRL path from config | CONDITIONAL | Trace configuration |

---

## R7: Entropy/RNG Initialization (CRITICAL for Embedded)

**Meta-Rule(s)**: S3  |  **Priority**: SHOULD (CRITICAL for embedded systems)

**What to Verify**: Cryptographic RNG is properly seeded with adequate entropy.

**Implementation**:
- `mbedtls_entropy_init()`: Initialize entropy context
- `mbedtls_ctr_drbg_init()`: Initialize DRBG
- `mbedtls_ctr_drbg_seed()`: Seed DRBG from entropy
- `mbedtls_ssl_conf_rng()`: Attach RNG to SSL config
- **ALL steps are REQUIRED** for proper operation

**Binary Analysis**:
| Function | Purpose | Required |
|----------|---------|----------|
| `mbedtls_entropy_init` | Initialize entropy pool | Yes |
| `mbedtls_ctr_drbg_init` | Initialize DRBG | Yes |
| `mbedtls_ctr_drbg_seed` | Seed DRBG | Yes |
| `mbedtls_ssl_conf_rng` | Attach RNG to config | Yes |
| `mbedtls_entropy_add_source` | Add custom entropy source | Embedded only |
| `mbedtls_hardware_poll` | Hardware RNG callback | Platform-dependent |

**Proper Initialization Sequence**:
```c
mbedtls_entropy_init(&entropy);
mbedtls_ctr_drbg_init(&ctr_drbg);
mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                      (const unsigned char *)pers, strlen(pers));
mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
```

**Default Behavior**:
| Platform | Entropy Source | Security |
|----------|----------------|----------|
| Linux/macOS | /dev/urandom | SECURE |
| Windows | CryptGenRandom | SECURE |
| Embedded (no OS) | **MUST provide** | Check implementation |
| RTOS | Platform-dependent | Check implementation |

**Detection Patterns**:
- All four functions called in sequence → PASS
- Missing `mbedtls_entropy_init` → FAIL
- Missing `mbedtls_ctr_drbg_seed` → FAIL
- Missing `mbedtls_ssl_conf_rng` → FAIL
- On embedded: check for `mbedtls_entropy_add_source` or `mbedtls_hardware_poll`

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Full entropy/DRBG initialization sequence | PASS | Proper RNG setup |
| Missing any initialization step | FAIL | Weak or no randomness |
| `mbedtls_ctr_drbg_seed` with predictable data | FAIL | Predictable RNG |
| Platform has /dev/urandom or equivalent | PASS | System entropy available |
| Embedded without hardware RNG | FAIL | No entropy source |
| Hardware RNG callback implemented | PASS | Good entropy source |

**Vulnerability Indicators**:
- Using `rand()` or `srand()` instead of mbedTLS RNG
- Seeding with predictable data (time, fixed string)
- Missing `mbedtls_entropy_add_source` on embedded systems
- No hardware RNG callback on systems without /dev/urandom

---

## R8: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented.

**Implementation**:
- Custom verification callback via `mbedtls_ssl_conf_verify()`
- `mbedtls_pk_write_pubkey_der()`: Extract public key
- `mbedtls_md()`: Hash for comparison
- Compare against hardcoded/stored pin values

**Binary Analysis**:
| Function | Purpose |
|----------|---------|
| `mbedtls_ssl_conf_verify` | Set custom verification callback |
| `mbedtls_pk_write_pubkey_der` | Serialize public key |
| `mbedtls_md` | Compute hash |
| `mbedtls_x509_crt_get_pk` | Get public key from cert |

**Detection Patterns**:
- Custom verify callback with pin comparison → PASS
- Hardcoded SHA-256 hashes (32 bytes or 64 hex chars) → PASS
- No pinning → UNDETERMINED (optional)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Certificate/key pinning implemented | PASS | Defense-in-depth |
| No pinning | UNDETERMINED | Optional feature |
| Pin values from variable | CONDITIONAL | Trace pin source |
