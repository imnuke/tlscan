# PHP cURL Extension SSL/TLS Security Rules

This document defines security rules for PHP cURL extension usage. Each rule references the corresponding meta-rule(s) from `metarule.md`. PHP cURL wraps libcurl, so the same options apply with PHP syntax.

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
- Entropy/RNG (S3) is not applicable to PHP cURL as it relies on the underlying SSL backend.
- PHP uses the same libcurl constants with PHP constant syntax.
- R7 (S2) is backend-dependent - PHP cURL relies on the SSL backend for cryptographic strength enforcement.

## PHP cURL Constants Reference

**Security-Critical Options**:
| PHP Constant | libcurl Code | Default | Secure Value |
|--------------|--------------|---------|--------------|
| `CURLOPT_SSL_VERIFYPEER` | 64 | `true` | `true` |
| `CURLOPT_SSL_VERIFYHOST` | 81 | `2` | `2` |
| `CURLOPT_SSLVERSION` | 32 | `0` | `≥ CURL_SSLVERSION_TLSv1_2` |

**SSL Version Constants**:
| PHP Constant | Value | Security |
|--------------|-------|----------|
| `CURL_SSLVERSION_DEFAULT` | 0 | CONDITIONAL |
| `CURL_SSLVERSION_TLSv1` | 1 | INSECURE |
| `CURL_SSLVERSION_SSLv2` | 2 | INSECURE |
| `CURL_SSLVERSION_SSLv3` | 3 | INSECURE |
| `CURL_SSLVERSION_TLSv1_0` | 4 | INSECURE |
| `CURL_SSLVERSION_TLSv1_1` | 5 | INSECURE |
| `CURL_SSLVERSION_TLSv1_2` | 6 | SECURE |
| `CURL_SSLVERSION_TLSv1_3` | 7 | SECURE |

## PHP Version Considerations

| PHP Version | libcurl | TLS 1.3 Support |
|-------------|---------|-----------------|
| PHP 7.0+ | 7.34.0+ | TLS 1.2 constants available |
| PHP 7.3+ | 7.52.0+ | `CURL_SSLVERSION_TLSv1_3` available |

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm HTTPS URLs are used, not HTTP or plaintext.

**Implementation**:
- Check URL scheme in `curl_setopt($ch, CURLOPT_URL, ...)`
- URL must start with `https://` not `http://`
- Check for conditional protocol usage

**PHP Functions**:
| Function | Purpose |
|----------|---------|
| `curl_init($url)` | Initialize with URL |
| `curl_setopt($ch, CURLOPT_URL, $url)` | Set URL |

**Detection Patterns**:
```php
// SATISFIED: HTTPS URL
curl_setopt($ch, CURLOPT_URL, "https://api.example.com");

// UNSATISFIED: HTTP URL
curl_setopt($ch, CURLOPT_URL, "http://api.example.com");

// CONDITIONAL: Variable URL
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_URL, $config['api_url']);

// UNSATISFIED: Protocol fallback
$url = $ssl ? "https://..." : "http://...";
```

**Vulnerability Indicators**:
- Hardcoded `http://` URLs for sensitive APIs
- Protocol fallback on cURL errors
- User-controllable protocol selection without validation
- Default to HTTP with optional HTTPS
- Environment variable controlling protocol: `getenv('USE_SSL')`

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | SATISFIED | TLS connection |
| URL starts with `http://` | UNSATISFIED | Plaintext connection |
| URL from variable | CONDITIONAL | Trace variable source |
| Protocol fallback logic | UNSATISFIED | Downgrade possible |

---

## R2: Certificate Chain Verification

**Meta-Rule(s)**: M3  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated against trusted CA store.

**Implementation**:
- `CURLOPT_SSL_VERIFYPEER`: Enable certificate verification (default: `true`)
- `CURLOPT_CAINFO`: Path to CA certificate bundle file
- `CURLOPT_CAPATH`: Path to directory with CA certificates

**PHP Options**:
| Option | Default | Secure | Insecure |
|--------|---------|--------|----------|
| `CURLOPT_SSL_VERIFYPEER` | `true` | `true` | `false`, `0` |
| `CURLOPT_CAINFO` | system | Valid CA path | Invalid path |
| `CURLOPT_CAPATH` | system | Valid CA dir | Invalid dir |

**Default Behavior**:
| PHP/libcurl Version | Default | Security |
|---------------------|---------|----------|
| All modern versions | `true` | SECURE |

**Detection Patterns**:
```php
// UNSATISFIED: Disables certificate verification
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

// SATISFIED: Explicit enable (redundant but safe)
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);

// SATISFIED: Not setting (uses secure default)
// No CURLOPT_SSL_VERIFYPEER call

// SATISFIED: Custom CA bundle
curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem');

// CONDITIONAL: Variable value
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $config['verify']);
```

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYPEER` = `true` | SATISFIED | Verification enabled |
| `CURLOPT_SSL_VERIFYPEER` not set | SATISFIED | Default is `true` |
| `CURLOPT_SSL_VERIFYPEER` = `false` | UNSATISFIED | Verification disabled |
| Value from variable | CONDITIONAL | Trace variable |
| `CURLOPT_CAINFO` not set, no system CA | CONDITIONAL | May unsatisfied silently |

---

## R3: Hostname Verification

**Meta-Rule(s)**: M4  |  **Priority**: MUST

**What to Verify**: Certificate's identity matches the target hostname.

**Implementation**:
- `CURLOPT_SSL_VERIFYHOST`: Hostname verification level
- Value `2`: Full hostname verification (SECURE, default)
- Value `1`: Deprecated (treated as `2` since libcurl 7.66.0)
- Value `0`: Disabled (INSECURE)

**PHP Options**:
| Option | Default | Secure | Insecure |
|--------|---------|--------|----------|
| `CURLOPT_SSL_VERIFYHOST` | `2` | `2` | `0`, `false` |

**Default Behavior**:
| PHP/libcurl Version | Default | Security |
|---------------------|---------|----------|
| All modern versions | `2` | SECURE |

**Value 1 History**:
| libcurl Version | Behavior |
|-----------------|----------|
| ≤ 7.28.0 | CN-only check (unreliable) |
| 7.28.1 - 7.65.3 | Returns error |
| ≥ 7.66.0 | Treated same as 2 |

**Detection Patterns**:
```php
// UNSATISFIED: Disables hostname verification
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

// UNSATISFIED: Deprecated value (unreliable in older versions)
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);

// SATISFIED: Full hostname check
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

// SATISFIED: Not setting (uses secure default)
// No CURLOPT_SSL_VERIFYHOST call

// CONDITIONAL: Variable value
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $config['verify_host']);
```

**Security Note**: CURLOPT_SSL_VERIFYHOST operates independently of CURLOPT_SSL_VERIFYPEER per libcurl documentation. Evaluate R3 based solely on VERIFYHOST setting. If R2 fails, note the combined security impact in evidence but do NOT change R3's result.

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYHOST` = `2` | SATISFIED | Full hostname check |
| `CURLOPT_SSL_VERIFYHOST` not set | SATISFIED | Default is `2` |
| `CURLOPT_SSL_VERIFYHOST` = `0` | UNSATISFIED | Hostname check disabled |
| `CURLOPT_SSL_VERIFYHOST` = `1` | UNSATISFIED | Deprecated/unreliable |
| Value from variable | CONDITIONAL | Trace variable |

---

## R4: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is negotiated.

**Implementation**:
- `CURLOPT_SSLVERSION`: Set minimum SSL/TLS version
- Default (`CURL_SSLVERSION_DEFAULT`): Relies on SSL backend

**PHP Options**:
| Constant | Value | Security |
|----------|-------|----------|
| `CURL_SSLVERSION_TLSv1_3` | 7 | SECURE |
| `CURL_SSLVERSION_TLSv1_2` | 6 | SECURE |
| `CURL_SSLVERSION_TLSv1_1` | 5 | INSECURE |
| `CURL_SSLVERSION_TLSv1_0` | 4 | INSECURE |
| `CURL_SSLVERSION_TLSv1` | 1 | INSECURE |
| `CURL_SSLVERSION_SSLv3` | 3 | INSECURE |
| `CURL_SSLVERSION_SSLv2` | 2 | INSECURE |
| `CURL_SSLVERSION_DEFAULT` | 0 | CONDITIONAL |

**Detection Patterns**:
```php
// SATISFIED: TLS 1.2 minimum
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
curl_setopt($ch, CURLOPT_SSLVERSION, 6);

// SATISFIED: TLS 1.3 minimum
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
curl_setopt($ch, CURLOPT_SSLVERSION, 7);

// UNSATISFIED: Allows TLS 1.0
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
curl_setopt($ch, CURLOPT_SSLVERSION, 1);

// UNSATISFIED: Insecure protocols
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);

// CONDITIONAL: Uses default
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
curl_setopt($ch, CURLOPT_SSLVERSION, 0);
// Or not setting CURLOPT_SSLVERSION at all
```

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSLVERSION` ≥ 6 | SATISFIED | TLS 1.2+ enforced |
| `CURLOPT_SSLVERSION` 1-5 | UNSATISFIED | Allows insecure protocols |
| `CURLOPT_SSLVERSION` = 0 or not set | DEFAULT | Not explicitly configured |
| Value from variable | CONDITIONAL | Trace variable |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: MUST

**What to Verify**: Strong cipher suites are configured.

**Implementation**:
- `CURLOPT_SSL_CIPHER_LIST`: Cipher string for TLS 1.2 and below
- `CURLOPT_TLS13_CIPHERS`: Cipher suites for TLS 1.3 (PHP 7.3+)
- Format depends on SSL backend (usually OpenSSL)

**PHP Options**:
| Option | PHP Version | Purpose |
|--------|-------------|---------|
| `CURLOPT_SSL_CIPHER_LIST` | All | TLS 1.2 ciphers |
| `CURLOPT_TLS13_CIPHERS` | 7.3+ | TLS 1.3 ciphers |

**Insecure Cipher Patterns**:
| Pattern | Risk |
|---------|------|
| `NULL` | No encryption |
| `EXPORT` | Weak export ciphers |
| `RC4` | Broken stream cipher |
| `DES` | Weak block cipher |
| `aNULL` | No authentication |
| `eNULL` | No encryption |

**Detection Patterns**:
```php
// SATISFIED: Strong ciphers
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4');

// UNSATISFIED: Allows weak ciphers
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'ALL');
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'DEFAULT:+RC4');

// CONDITIONAL: No cipher restriction
// Not setting CURLOPT_SSL_CIPHER_LIST
```

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string | SATISFIED | Weak ciphers excluded |
| Weak ciphers in string | UNSATISFIED | Insecure ciphers allowed |
| No cipher configuration | DEFAULT | Not explicitly configured |
| Cipher string from variable | CONDITIONAL | Trace variable |

---

## R6: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked.

**Implementation**:
- `CURLOPT_SSL_OPTIONS` with `CURLSSLOPT_REVOKE_BEST_EFFORT`
- Support varies by PHP version and SSL backend

**PHP Options**:
| Flag | Value | Purpose |
|------|-------|---------|
| `CURLSSLOPT_REVOKE_BEST_EFFORT` | 32 | Check CRL if available |
| `CURLSSLOPT_NO_REVOKE` | 2 | Disable revocation check |

**Detection Patterns**:
```php
// SATISFIED: Enable revocation checking
curl_setopt($ch, CURLOPT_SSL_OPTIONS, CURLSSLOPT_REVOKE_BEST_EFFORT);

// UNSATISFIED: Disable revocation checking
curl_setopt($ch, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
```

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Revocation checking enabled | SATISFIED | CRL/OCSP check performed |
| `CURLSSLOPT_NO_REVOKE` used | UNSATISFIED | Revocation check disabled |
| No configuration | DEFAULT | Not explicitly configured |

---

## R7: Cryptographic Strength (Backend-Dependent)

**Meta-Rule(s)**: S2  |  **Priority**: SHOULD

**What to Verify**: Certificates use strong signature algorithms (SHA-256+) and adequate key sizes (RSA 2048+).

**Implementation**:
- PHP cURL relies on the underlying SSL backend for cryptographic strength enforcement
- Check the backend version to determine default security level
- PHP cURL has no direct option to configure cryptographic strength requirements

**Backend Cryptographic Strength Defaults**:
| Backend | Version | Default Security Level | Verdict |
|---------|---------|----------------------|---------|
| OpenSSL | 3.0+ | Level 2 (SHA-256+, RSA 2048+) | SATISFIED |
| OpenSSL | 1.1.x | Level 1 (SHA-1 allowed, RSA 1024+) | UNSATISFIED |
| OpenSSL | 1.0.x | Level 0 (weak algorithms allowed) | UNSATISFIED |
| GnuTLS | 3.6+ | NORMAL priority (secure defaults) | SATISFIED |
| GnuTLS | < 3.6 | May allow weak algorithms | UNSATISFIED |

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No configuration | DEFAULT | Not explicitly configured (backend-dependent) |

**Note**: PHP cURL has no direct option to configure cryptographic strength. This is entirely
backend-dependent with no code-level configuration possible, so result is always DEFAULT.

---

## R8: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented.

**Implementation**:
- `CURLOPT_PINNEDPUBLICKEY`: SHA256 hash of public key
- Format: `sha256//base64-encoded-hash`
- Available in PHP 7.0+ with libcurl 7.39.0+

**Detection Patterns**:
```php
// SATISFIED: Pinning enabled
curl_setopt($ch, CURLOPT_PINNEDPUBLICKEY, 'sha256//hash1;sha256//hash2');

// UNSATISFIED: No pinning
// Not setting CURLOPT_PINNEDPUBLICKEY
```

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_PINNEDPUBLICKEY` set | SATISFIED | Pinning enabled |
| Pinning not configured | UNSATISFIED | Pinning not implemented |
| Pin value from variable | CONDITIONAL | Trace pin source |

---

## Error Handling

Proper error handling is important but should NOT lead to disabling verification.

**Correct Error Handling**:
```php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$result = curl_exec($ch);

if ($result === false) {
    $errno = curl_errno($ch);
    $error = curl_error($ch);

    // Log error but DO NOT disable verification
    if ($errno === CURLE_SSL_CACERT) {
        // Fix: Update CA bundle, not disable verification
        error_log("SSL CA cert error: $error");
    }
}
```

**SSL-Related Error Codes**:
| Constant | Code | Description |
|----------|------|-------------|
| `CURLE_SSL_CONNECT_ERROR` | 35 | SSL connection error |
| `CURLE_SSL_PEER_CERTIFICATE` | 51 | Peer certificate error |
| `CURLE_SSL_CACERT` | 60 | CA certificate error |
| `CURLE_SSL_CERTPROBLEM` | 58 | Client certificate error |
| `CURLE_SSL_PINNEDPUBKEYNOTMATCH` | 90 | Pinned key mismatch |

---

## Result Determination Summary

| Scenario | Result |
|----------|--------|
| Option explicitly set to secure value | SATISFIED |
| Option explicitly set to insecure value | UNSATISFIED |
| Option set to runtime variable | CONDITIONAL |
| Option NOT configured | DEFAULT |
| Cannot find relevant code at all | UNDETERMINED |

**Note**: DEFAULT means the option was not explicitly configured in code. The actual
security depends on PHP and libcurl/backend versions at runtime, which cannot be
determined from static analysis alone.
