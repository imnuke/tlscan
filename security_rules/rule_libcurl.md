# libcurl SSL/TLS Security Rules

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

## 2. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain against trusted CA certificates

**Implementation**:
- Set `CURLOPT_SSL_VERIFYPEER` to `1L` (enabled by default)
- Provide CA bundle: `CURLOPT_CAINFO` (file) or `CURLOPT_CAPATH` (directory)
- Vulnerability: Setting `CURLOPT_SSL_VERIFYPEER` to `0L` disables all certificate verification

**Detection Patterns**:
- Functions: `curl_easy_setopt()`
- Options: `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_CAINFO`, `CURLOPT_CAPATH`
- Vulnerability: `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L)`

## 3. Hostname Verification
**Priority**: MUST
**Description**: Verify that the certificate matches the hostname being connected to

**Implementation**:
- Set `CURLOPT_SSL_VERIFYHOST` to `2L` (full hostname check, default)
- Value `1L` is deprecated and should not be used
- Value `0L` disables hostname verification (insecure)

**Detection Patterns**:
- Options: `CURLOPT_SSL_VERIFYHOST`
- Vulnerability: `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L)` or `1L`

## 4. Protocol Version
**Priority**: MUST
**Description**: Enforce TLS 1.2 or higher, disable older insecure protocols

**Implementation**:
- Use `CURLOPT_SSLVERSION` with `CURL_SSLVERSION_TLSv1_2` or `CURL_SSLVERSION_TLSv1_3`
- Or use range: `CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_3`
- Default allows TLS 1.0+, which is insecure

**Detection Patterns**:
- Options: `CURLOPT_SSLVERSION`
- Constants: `CURL_SSLVERSION_TLSv1_2`, `CURL_SSLVERSION_TLSv1_3`, `CURL_SSLVERSION_MAX_*`
- Vulnerability: Not setting minimum TLS version or allowing SSLv2/SSLv3/TLS1.0/TLS1.1

## 5. Cipher Suite Selection
**Priority**: RECOMMENDED
**Description**: Restrict cipher suites to strong algorithms

**Implementation**:
- Use `CURLOPT_SSL_CIPHER_LIST` to specify allowed ciphers (format depends on SSL backend)
- For OpenSSL backend: same format as OpenSSL cipher strings
- For other backends: consult backend-specific documentation

**Detection Patterns**:
- Options: `CURLOPT_SSL_CIPHER_LIST`
- Vulnerability: Not restricting cipher suites or allowing weak ciphers

## 6. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific certificates or public keys

**Implementation**:
- Use `CURLOPT_PINNEDPUBLICKEY` to specify SHA256 hash of public key
- Format: `"sha256//base64-encoded-hash"` or path to public key file
- Multiple pins: separate with semicolons

**Detection Patterns**:
- Options: `CURLOPT_PINNEDPUBLICKEY`
- Implementation: Presence of public key hashes or pinned certificate files

## 7. Certificate Revocation
**Priority**: RECOMMENDED
**Description**: Check certificate revocation status

**Implementation**:
- Use `CURLOPT_SSL_OPTIONS` with `CURLSSLOPT_REVOKE_BEST_EFFORT` (checks CRL if available)
- Not all SSL backends support revocation checking
- Consider OCSP stapling support (backend-dependent)

**Detection Patterns**:
- Options: `CURLOPT_SSL_OPTIONS`
- Constants: `CURLSSLOPT_REVOKE_BEST_EFFORT`

## 8. SSL/TLS Backend Configuration
**Priority**: INFORMATIONAL
**Description**: Be aware of which SSL/TLS library libcurl is compiled against

**Implementation**:
- Check with `curl_version_info()` to determine SSL backend (OpenSSL, GnuTLS, NSS, etc.)
- Different backends have different security characteristics
- Backend-specific options via `CURLOPT_SSL_CTX_FUNCTION` (OpenSSL) or similar

**Detection Patterns**:
- Functions: `curl_version_info()`, `CURLOPT_SSL_CTX_FUNCTION`
- Backend-specific initialization code
