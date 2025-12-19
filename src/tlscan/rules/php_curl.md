# PHP cURL Extension SSL/TLS Security Rules

This document defines security rules for PHP cURL extension usage. Each rule references the corresponding meta-rule(s) from `metarule.md`. PHP cURL wraps libcurl, so the same options apply with PHP syntax.

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
| LS1 | N/A | CRITICAL | PHP-Specific Vulnerabilities |

**Notes**:
- Entropy/RNG (S3) is not applicable to PHP cURL as it relies on the underlying SSL backend.
- PHP uses the same libcurl constants with PHP constant syntax.
- LS1 is marked CRITICAL because PHP developers commonly disable SSL verification incorrectly.

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
// PASS: HTTPS URL
curl_setopt($ch, CURLOPT_URL, "https://api.example.com");

// FAIL: HTTP URL
curl_setopt($ch, CURLOPT_URL, "http://api.example.com");

// CONDITIONAL: Variable URL
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_URL, $config['api_url']);

// FAIL: Protocol fallback
$url = $ssl ? "https://..." : "http://...";
```

**Vulnerability Indicators**:
- Hardcoded `http://` URLs for sensitive APIs
- Protocol fallback on cURL errors
- User-controllable protocol selection without validation
- Default to HTTP with optional HTTPS
- Environment variable controlling protocol: `getenv('USE_SSL')`

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | PASS | TLS connection |
| URL starts with `http://` | FAIL | Plaintext connection |
| URL from variable | CONDITIONAL | Trace variable source |
| Protocol fallback logic | FAIL | Downgrade possible |

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
// FAIL: Disables certificate verification
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

// PASS: Explicit enable (redundant but safe)
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);

// PASS: Not setting (uses secure default)
// No CURLOPT_SSL_VERIFYPEER call

// PASS: Custom CA bundle
curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem');

// CONDITIONAL: Variable value
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $config['verify']);
```

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYPEER` = `true` | PASS | Verification enabled |
| `CURLOPT_SSL_VERIFYPEER` not set | PASS | Default is `true` |
| `CURLOPT_SSL_VERIFYPEER` = `false` | FAIL | Verification disabled |
| Value from variable | CONDITIONAL | Trace variable |
| `CURLOPT_CAINFO` not set, no system CA | CONDITIONAL | May fail silently |

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
// FAIL: Disables hostname verification
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

// FAIL: Deprecated value (unreliable in older versions)
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);

// PASS: Full hostname check
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

// PASS: Not setting (uses secure default)
// No CURLOPT_SSL_VERIFYHOST call

// CONDITIONAL: Variable value
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $config['verify_host']);
```

**Security Note**: CURLOPT_SSL_VERIFYHOST operates independently of CURLOPT_SSL_VERIFYPEER per libcurl documentation. Evaluate R3 based solely on VERIFYHOST setting. If R2 fails, note the combined security impact in evidence but do NOT change R3's result.

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSL_VERIFYHOST` = `2` | PASS | Full hostname check |
| `CURLOPT_SSL_VERIFYHOST` not set | PASS | Default is `2` |
| `CURLOPT_SSL_VERIFYHOST` = `0` | FAIL | Hostname check disabled |
| `CURLOPT_SSL_VERIFYHOST` = `1` | FAIL | Deprecated/unreliable |
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
// PASS: TLS 1.2 minimum
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
curl_setopt($ch, CURLOPT_SSLVERSION, 6);

// PASS: TLS 1.3 minimum
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
curl_setopt($ch, CURLOPT_SSLVERSION, 7);

// FAIL: Allows TLS 1.0
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
curl_setopt($ch, CURLOPT_SSLVERSION, 1);

// FAIL: Insecure protocols
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);

// CONDITIONAL: Uses default
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
curl_setopt($ch, CURLOPT_SSLVERSION, 0);
// Or not setting CURLOPT_SSLVERSION at all
```

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_SSLVERSION` ≥ 6 | PASS | TLS 1.2+ enforced |
| `CURLOPT_SSLVERSION` 1-5 | FAIL | Allows insecure protocols |
| `CURLOPT_SSLVERSION` = 0 or not set | UNDETERMINED | Depends on libcurl version (not traceable) |
| Value from variable | CONDITIONAL | Trace variable |

---

## R5: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: SHOULD

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
// PASS: Strong ciphers
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4');

// FAIL: Allows weak ciphers
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'ALL');
curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'DEFAULT:+RC4');

// CONDITIONAL: No cipher restriction
// Not setting CURLOPT_SSL_CIPHER_LIST
```

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string | PASS | Weak ciphers excluded |
| Weak ciphers in string | FAIL | Insecure ciphers allowed |
| No cipher configuration | CONDITIONAL | Uses backend default |

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
// PASS: Enable revocation checking
curl_setopt($ch, CURLOPT_SSL_OPTIONS, CURLSSLOPT_REVOKE_BEST_EFFORT);

// FAIL: Disable revocation checking
curl_setopt($ch, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
```

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
- `CURLOPT_PINNEDPUBLICKEY`: SHA256 hash of public key
- Format: `sha256//base64-encoded-hash`
- Available in PHP 7.0+ with libcurl 7.39.0+

**Detection Patterns**:
```php
// PASS: Pinning enabled
curl_setopt($ch, CURLOPT_PINNEDPUBLICKEY, 'sha256//hash1;sha256//hash2');

// UNDETERMINED: No pinning
// Not setting CURLOPT_PINNEDPUBLICKEY
```

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `CURLOPT_PINNEDPUBLICKEY` set | PASS | Pinning enabled |
| Pinning not configured | UNDETERMINED | Optional feature |
| Pin value from variable | CONDITIONAL | Trace pin source |

---

## LS1: PHP-Specific Vulnerabilities

**Meta-Rule(s)**: N/A (library-specific)  |  **Priority**: CRITICAL

**What to Verify**: Common PHP cURL security mistakes are avoided.

### Common Vulnerability Patterns

**1. Disabling SSL to "fix" certificate errors**:
```php
// CRITICAL VULNERABILITY - Common anti-pattern
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
// Often copied from Stack Overflow
```

**2. Using boolean false instead of integer 0**:
```php
// Both are INSECURE - PHP treats false as 0
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);  // Same as 0
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);  // Same as 0
```

**3. Configuration-based disabling**:
```php
// CONDITIONAL - Trace config source
if ($config['debug'] || $config['dev_mode']) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
}
```

**4. Environment-based disabling**:
```php
// CONDITIONAL - Check environment values
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, getenv('VERIFY_SSL') !== 'false');
```

**5. Missing CA bundle on Windows**:
```php
// CONDITIONAL - Windows may not have CA bundle
// Check if CURLOPT_CAINFO is set or system CA exists
```

### Detection Patterns

Search for these patterns in PHP code:

| Pattern | Risk Level |
|---------|------------|
| `CURLOPT_SSL_VERIFYPEER.*false` | CRITICAL |
| `CURLOPT_SSL_VERIFYHOST.*0` | CRITICAL |
| `CURLOPT_SSL_VERIFYHOST.*false` | CRITICAL |
| `// disable.*ssl` (comment) | Review needed |
| `// fix.*certificate` (comment) | Review needed |
| `$verify.*=.*false` | Trace variable |

### Wrapper Functions

Watch for insecure wrapper functions/classes:

```php
// FAIL: Wrapper that disables verification
function makeRequest($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // Hidden insecurity
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    return curl_exec($ch);
}

// FAIL: Class with insecure defaults
class HttpClient {
    private $verifySSL = false;  // Insecure default
}
```

### Framework-Specific Patterns

**Laravel/Guzzle**:
```php
// FAIL: Guzzle with verify disabled
$client = new \GuzzleHttp\Client(['verify' => false]);

// PASS: Guzzle with verification
$client = new \GuzzleHttp\Client(['verify' => true]);
$client = new \GuzzleHttp\Client(['verify' => '/path/to/cacert.pem']);
```

**Symfony HttpClient**:
```php
// FAIL: Disabled verification
$client = HttpClient::create(['verify_peer' => false]);
```

### PASS/FAIL/CONDITIONAL Criteria

| Pattern | Result | Reason |
|---------|--------|--------|
| `VERIFYPEER = false` anywhere | FAIL | Verification disabled |
| `VERIFYHOST = 0` or `false` | FAIL | Hostname check disabled |
| Conditional disable (debug mode) | CONDITIONAL | May be disabled in production |
| Framework `verify => false` | FAIL | Framework-level insecurity |
| No insecure patterns found | PASS | Secure implementation |

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

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | Option explicitly secure | PASS |
| MUST | Option explicitly insecure | FAIL |
| MUST | No option, secure default | PASS |
| MUST | No option, version-dependent default | CONDITIONAL |
| SHOULD | Feature enabled | PASS |
| SHOULD | Feature explicitly disabled | FAIL |
| SHOULD | Feature not configured | UNDETERMINED |
| MAY | Feature implemented | PASS |
| MAY | Feature not implemented | UNDETERMINED |
| CRITICAL | Insecure PHP patterns found | FAIL |
