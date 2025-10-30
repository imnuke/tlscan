# PHP cURL Extension SSL/TLS Security Rules

## 1. SSL/TLS Usage Detection
**Priority**: MUST
**Description**: Verify that HTTPS URLs are actually being used, not HTTP.

**Implementation**:
- Check URL scheme passed to `curl_setopt($ch, CURLOPT_URL, ...)`
- Verify URL starts with "https://" not "http://"
- Look for conditional protocol selection based on config/env
- Check for HTTP fallback in error handling

**Detection Patterns**:
- URL patterns: `curl_setopt($ch, CURLOPT_URL, "https://...")`
- Conditional protocol: `$url = ($ssl ? "https" : "http") . "://..."`
- Config-based: `if ($config['use_ssl'])` affecting URL construction
- Environment: `$protocol = getenv('PROTOCOL') ?: 'http'`

**Vulnerability Indicators**:
- Hardcoded "http://" URLs for sensitive APIs
- Protocol fallback on curl errors
- User-controllable protocol selection without validation
- Default to HTTP with optional HTTPS

## 2. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain

**Implementation**:
- Use `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true)` to enable verification
- **CRITICAL VULNERABILITY**: Setting to `false` disables ALL certificate verification
- Provide CA bundle: `curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem')`
- Or CA path: `curl_setopt($ch, CURLOPT_CAPATH, '/path/to/ca/directory')`

**Detection Patterns**:
- Functions: `curl_setopt()`
- Constants: `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_CAINFO`, `CURLOPT_CAPATH`
- Vulnerability: `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)` or `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0)`

## 3. Hostname Verification
**Priority**: MUST
**Description**: Verify certificate matches hostname

**Implementation**:
- Use `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2)` for full hostname check
- Value `2` (default): full hostname verification
- Value `1`: deprecated, do not use
- **CRITICAL VULNERABILITY**: Value `0` or `false` disables hostname verification

**Detection Patterns**:
- Constants: `CURLOPT_SSL_VERIFYHOST`
- Vulnerability: `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0)` or `curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false)`

## 4. Protocol Version
**Priority**: MUST
**Description**: Enforce secure TLS versions

**Implementation**:
- Use `curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2)` for TLS 1.2 minimum
- Or `CURL_SSLVERSION_TLSv1_3` for TLS 1.3
- Default (`CURL_SSLVERSION_DEFAULT`) may allow insecure versions

**Detection Patterns**:
- Constants: `CURLOPT_SSLVERSION`, `CURL_SSLVERSION_TLSv1_2`, `CURL_SSLVERSION_TLSv1_3`
- Vulnerability: Not setting minimum version or using `CURL_SSLVERSION_SSLv2`, `CURL_SSLVERSION_SSLv3`, `CURL_SSLVERSION_TLSv1`

## 5. Common PHP-Specific Vulnerabilities
**Priority**: CRITICAL
**Description**: PHP developers commonly disable SSL verification incorrectly

**Common Mistakes**:
1. Disabling peer verification to "fix" certificate errors:
   ```php
   curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // INSECURE!
   ```

2. Disabling hostname verification:
   ```php
   curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0); // INSECURE!
   ```

3. Not updating CA bundle (using outdated or missing cacert.pem)

4. Copying insecure code from Stack Overflow without understanding implications

**Detection Patterns**:
- Search for `CURLOPT_SSL_VERIFYPEER` with `false` or `0`
- Search for `CURLOPT_SSL_VERIFYHOST` with `0` or `false`
- Look for comments like "disable SSL verification" or "fix certificate error"

## 6. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific public keys

**Implementation**:
- Use `curl_setopt($ch, CURLOPT_PINNEDPUBLICKEY, 'sha256//base64hash')`
- Format: `sha256//base64-encoded-hash` or path to public key file

**Detection Patterns**:
- Constants: `CURLOPT_PINNEDPUBLICKEY`
- Implementation: Public key hashes in PHP code

## 7. Cipher Suite Selection
**Priority**: RECOMMENDED
**Description**: Restrict cipher suites

**Implementation**:
- Use `curl_setopt($ch, CURLOPT_SSL_CIPHER_LIST, 'cipher_string')`
- Format depends on underlying libcurl SSL backend

**Detection Patterns**:
- Constants: `CURLOPT_SSL_CIPHER_LIST`

## 8. Error Handling
**Priority**: RECOMMENDED
**Description**: Properly handle SSL/TLS errors

**Implementation**:
- Check `curl_errno()` for error codes
- SSL-specific errors: `CURLE_SSL_CONNECT_ERROR`, `CURLE_SSL_PEER_CERTIFICATE`, `CURLE_SSL_CACERT`
- Use `curl_error()` to get error messages
- Never suppress errors by disabling verification

**Detection Patterns**:
- Functions: `curl_errno()`, `curl_error()`
- Error handling after `curl_exec()`
