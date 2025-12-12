# libcurl SSL/TLS Security Rules

## Binary Analysis Reference

**IMPORTANT**: When analyzing compiled binaries, `curl_easy_setopt()` calls show numeric option codes instead of symbolic names. Use this reference to identify security-critical options:

### Security-Critical Options (MUST check)
| Option Name | Numeric Value | Secure Value | Vulnerability |
|-------------|---------------|--------------|---------------|
| CURLOPT_SSL_VERIFYPEER | 64 | 1 (default) | 0 = disables cert verification |
| CURLOPT_SSL_VERIFYHOST | 81 | 2 (default) | 0 or 1 = disables/weakens hostname check |
| CURLOPT_SSLVERSION | 32 | 6+ (TLS 1.2+) | <6 = allows insecure protocols |

### Other SSL-Related Options
| Option Name | Numeric Value | Description |
|-------------|---------------|-------------|
| CURLOPT_CAINFO | 10065 | CA certificate file path |
| CURLOPT_CAPATH | 10097 | CA certificate directory |
| CURLOPT_SSL_OPTIONS | 216 | SSL behavior flags |
| CURLOPT_SSL_CIPHER_LIST | 10083 | Allowed cipher suites |
| CURLOPT_PINNEDPUBLICKEY | 10230 | Certificate pinning |

### Common Non-SSL Options (for disambiguation)
| Option Name | Numeric Value | Description |
|-------------|---------------|-------------|
| CURLOPT_VERBOSE | 41 | Debug output |
| CURLOPT_URL | 10002 | Target URL |
| CURLOPT_POST | 47 | Enable POST |
| CURLOPT_POSTFIELDS | 10015 | POST data |

**Example**: `curl_easy_setopt(handle, 64, 0)` means CURLOPT_SSL_VERIFYPEER is set to 0 (VULNERABLE - certificate verification disabled).

## 1. SSL/TLS Usage Detection
**Priority**: MUST
**Description**: Verify that HTTPS/SSL is actually being used, not just available. Detect conditional usage or plaintext fallbacks.

**Implementation**:
- Check URL scheme: must be "https://" not "http://"
- Verify `curl_easy_setopt()` is actually called (not just declared)
- Look for protocol downgrades or fallbacks to HTTP
- Conditional patterns: SSL usage based on config/env variable
- Check `CURLOPT_URL` value or `curl_easy_setopt()` URL parameter

**Detection Patterns**:
- URL patterns: presence of "https://" in URL strings
- Conditional protocol: `url = (use_ssl ? "https" : "http") + "://..."`
- Port-based: different handling for port 443 vs 80
- Config/env checks: `if (config.ssl_enabled)` before setting https URL
- Functions: Look for `curl_easy_init()` followed by actual `curl_easy_perform()`

**Vulnerability Indicators**:
- Hardcoded "http://" URLs for sensitive operations
- Protocol fallback on CURLE_SSL_* errors
- Conditional SSL based on user-controllable input
- Default to plaintext with optional SSL upgrade

## 2. Certificate Chain and Validity Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain against trusted CA certificates

**Implementation**:
- Set `CURLOPT_SSL_VERIFYPEER` (option code 64) to `1L` (enabled by default)
- Provide CA bundle: `CURLOPT_CAINFO` (10065) or `CURLOPT_CAPATH` (10097)
- Vulnerability: Setting `CURLOPT_SSL_VERIFYPEER` to `0L` disables all certificate verification

**Detection Patterns**:
- Functions: `curl_easy_setopt()`
- Options: `CURLOPT_SSL_VERIFYPEER` (64), `CURLOPT_CAINFO` (10065), `CURLOPT_CAPATH` (10097)
- Vulnerability: `curl_easy_setopt(curl, 64, 0)` - disables certificate verification

## 3. Hostname Verification
**Priority**: MUST
**Description**: Verify that the certificate matches the hostname being connected to

**Implementation**:
- Set `CURLOPT_SSL_VERIFYHOST` (option code 81) to `2L` (full hostname check, default)
- Value `1L` is deprecated and should not be used
- Value `0L` disables hostname verification (insecure)

**Detection Patterns**:
- Options: `CURLOPT_SSL_VERIFYHOST` (81)
- Vulnerability: `curl_easy_setopt(curl, 81, 0)` or `curl_easy_setopt(curl, 81, 1)` - disables/weakens hostname verification

## 4. Certificate Revocation Status
**Priority**: RECOMMENDED
**Description**: Check certificate revocation status

**Implementation**:
- Use `CURLOPT_SSL_OPTIONS` with `CURLSSLOPT_REVOKE_BEST_EFFORT` (checks CRL if available)
- Not all SSL backends support revocation checking
- Consider OCSP stapling support (backend-dependent)

**Detection Patterns**:
- Options: `CURLOPT_SSL_OPTIONS`
- Constants: `CURLSSLOPT_REVOKE_BEST_EFFORT`

## 5. Protocol Version
**Priority**: MUST
**Description**: Enforce TLS 1.2 or higher, disable older insecure protocols

**Implementation**:
- Use `CURLOPT_SSLVERSION` (option code 32) with `CURL_SSLVERSION_TLSv1_2` (6) or `CURL_SSLVERSION_TLSv1_3` (7)
- Or use range: `CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_3`
- Default allows TLS 1.0+, which is insecure

**Detection Patterns**:
- Options: `CURLOPT_SSLVERSION` (32)
- Values: 0=default, 1=TLSv1, 2=SSLv2, 3=SSLv3, 4=TLSv1.0, 5=TLSv1.1, 6=TLSv1.2, 7=TLSv1.3
- Vulnerability: `curl_easy_setopt(curl, 32, <6)` - allows insecure protocols (SSLv2/SSLv3/TLS1.0/TLS1.1)

## 6. Cipher Suite Selection
**Priority**: RECOMMENDED
**Description**: Restrict cipher suites to strong algorithms

**Implementation**:
- Use `CURLOPT_SSL_CIPHER_LIST` to specify allowed ciphers (format depends on SSL backend)
- For OpenSSL backend: same format as OpenSSL cipher strings
- For other backends: consult backend-specific documentation

**Detection Patterns**:
- Options: `CURLOPT_SSL_CIPHER_LIST`
- Vulnerability: Not restricting cipher suites or allowing weak ciphers

## 7. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific certificates or public keys

**Implementation**:
- Use `CURLOPT_PINNEDPUBLICKEY` to specify SHA256 hash of public key
- Format: `"sha256//base64-encoded-hash"` or path to public key file
- Multiple pins: separate with semicolons

**Detection Patterns**:
- Options: `CURLOPT_PINNEDPUBLICKEY`
- Implementation: Presence of public key hashes or pinned certificate files
