# OpenSSL SSL/TLS Security Rules

## 1. SSL/TLS Usage Detection
**Priority**: MUST
**Description**: Verify that SSL/TLS is actually being used for connections, not just linked. Detect conditional usage or plaintext fallbacks.

**Implementation**:
- Check for SSL/TLS connection establishment: `SSL_connect()`, `SSL_accept()`, `SSL_new()`
- Verify SSL context is initialized: `SSL_CTX_new()` must be called
- Look for conditional usage patterns:
  - Config-based: SSL enabled only if config flag is set
  - Protocol scheme: Checks for "https://" vs "http://"
  - Port-based: Different behavior on port 443 vs 80
  - Environment variable: SSL enabled via env var (e.g., USE_SSL=1)
- Detect plaintext fallbacks:
  - Code paths with `connect()` + `send()`/`recv()` without SSL wrapper
  - Conditional branches that skip SSL initialization
  - Error handling that falls back to plaintext

**Detection Patterns**:
- Functions: `SSL_connect`, `SSL_accept`, `SSL_new`, `SSL_CTX_new`, `SSL_write`, `SSL_read`
- Conditional patterns:
  - `if (use_ssl)` or `if (config.enable_tls)` before SSL calls
  - `if (strncmp(url, "https://"))` for protocol detection
  - Port checks: `if (port == 443)` determining SSL usage
- Vulnerability indicators:
  - SSL functions exist but never called in dataflow
  - Unconditional `connect()` + `send()`/`recv()` without SSL
  - SSL initialization inside `if(0)` or disabled config branches
  - Error recovery that establishes plaintext connection

**Analysis Steps**:
1. Trace main connection function to verify SSL_connect() is actually reached
2. Check if SSL context initialization is conditional (config/env/flag-dependent)
3. Look for plaintext fallback paths (non-SSL socket operations)
4. If conditional, trace to configuration source (file/env/hardcoded)

## 2. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain against trusted CA certificates

**Implementation**:
- Use `SSL_CTX_set_verify()` or `SSL_set_verify()` with `SSL_VERIFY_PEER` to enable OpenSSL's default verification
- When `SSL_VERIFY_NONE` is used:
  - `SSL_get_peer_certificate()` MUST be called and checked (returns NULL if no cert provided)
  - `SSL_get_verify_result()` MUST be called and checked (returns X509_V_OK if valid)
  - Note: `SSL_get_verify_result()` returns X509_V_OK even without a certificate, hence the peer certificate check is required first
- When `SSL_VERIFY_PEER` is used: verification is automatic, but `SSL_get_verify_result()` can provide additional details

**Detection Patterns**:
- Functions: `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_get_verify_result`, `SSL_get_peer_certificate`
- Constants: `SSL_VERIFY_PEER`, `SSL_VERIFY_NONE`, `X509_V_OK`
- Vulnerability: Using `SSL_VERIFY_NONE` without manual verification

## 3. Hostname Verification
**Priority**: MUST
**Description**: Verify that the certificate matches the hostname being connected to

**Implementation**:
- Use `X509_check_host()` (OpenSSL 1.0.2+) to verify hostname against certificate
- Alternative: `SSL_set1_host()` (OpenSSL 1.1.0+) for automatic hostname verification
- Set hostname verification flags: `SSL_set_hostflags()` with `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`
- Older versions: Manual verification using `X509_NAME_get_text_by_NID()` and wildcard matching (error-prone)

**Detection Patterns**:
- Functions: `X509_check_host`, `SSL_set1_host`, `SSL_set_hostflags`, `X509_get_subject_name`
- Vulnerability: Missing hostname verification after certificate chain validation

## 4. Certificate Validity Period
**Priority**: RECOMMENDED
**Description**: Check certificate expiration and not-before dates

**Implementation**:
- Use `X509_get_notBefore()` and `X509_get_notAfter()` to get validity period
- Compare with current time using `X509_cmp_time()` or `X509_cmp_current_time()`
- Note: OpenSSL's default verification includes validity period checks when using `SSL_VERIFY_PEER`

**Detection Patterns**:
- Functions: `X509_get_notAfter`, `X509_get_notBefore`, `X509_cmp_time`, `X509_cmp_current_time`
- Automatic when using `SSL_VERIFY_PEER`

## 5. Certificate Revocation Status
**Priority**: RECOMMENDED
**Description**: Check if certificate has been revoked via OCSP or CRL

**Implementation**:
- OCSP: Use `OCSP_sendreq_bio()` and `OCSP_basic_verify()` to check revocation status
- CRL: Use `X509_STORE_set_flags()` with `X509_V_FLAG_CRL_CHECK` and `X509_V_FLAG_CRL_CHECK_ALL`
- OCSP Stapling: Check for stapled OCSP response using `SSL_get_tlsext_status_ocsp_resp()`

**Detection Patterns**:
- Functions: `OCSP_sendreq_bio`, `OCSP_basic_verify`, `X509_STORE_set_flags`, `SSL_get_tlsext_status_ocsp_resp`
- Constants: `X509_V_FLAG_CRL_CHECK`, `X509_V_FLAG_CRL_CHECK_ALL`
- Vulnerability: Missing revocation checks entirely

## 6. Protocol Version
**Priority**: MUST
**Description**: Enforce TLS 1.2 or higher, disable older insecure protocols

**Implementation**:
- Use `SSL_CTX_set_min_proto_version()` with `TLS1_2_VERSION` or `TLS1_3_VERSION` (OpenSSL 1.1.0+)
- Older versions: Use `SSL_CTX_set_options()` with `SSL_OP_NO_SSLv2`, `SSL_OP_NO_SSLv3`, `SSL_OP_NO_TLSv1`, `SSL_OP_NO_TLSv1_1`
- Check negotiated version: `SSL_get_version()` returns protocol version string

**Detection Patterns**:
- Functions: `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_max_proto_version`, `SSL_CTX_set_options`, `SSL_get_version`
- Constants: `TLS1_2_VERSION`, `TLS1_3_VERSION`, `SSL_OP_NO_SSLv2`, `SSL_OP_NO_SSLv3`, `SSL_OP_NO_TLSv1`, `SSL_OP_NO_TLSv1_1`
- Vulnerability: Allowing SSLv2, SSLv3, TLS 1.0, or TLS 1.1

## 7. Cipher Suite Selection
**Priority**: MUST
**Description**: Use strong cipher suites, avoid weak or export ciphers

**Implementation**:
- Use `SSL_CTX_set_cipher_list()` to specify allowed ciphers (TLS 1.2 and below)
- Use `SSL_CTX_set_ciphersuites()` for TLS 1.3 cipher suites (OpenSSL 1.1.1+)
- Recommended: `"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"` or `"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"`
- Avoid: NULL ciphers, EXPORT ciphers, DES, RC4, MD5-based MACs

**Detection Patterns**:
- Functions: `SSL_CTX_set_cipher_list`, `SSL_CTX_set_ciphersuites`, `SSL_get_cipher_name`, `SSL_get_cipher_list`
- Vulnerability: Using weak cipher strings or not restricting ciphers

## 8. Certificate Signature Algorithm and Key Strength
**Priority**: RECOMMENDED
**Description**: Verify certificate uses strong signature algorithms and key lengths

**Implementation**:
- Check signature algorithm: `X509_get_signature_nid()` or `X509_get0_signature()`
- Avoid: MD5, SHA1 signatures; prefer SHA256 or higher
- Check key strength: `EVP_PKEY_bits()` on public key from `X509_get_pubkey()`
- Minimum: RSA 2048-bit, ECDSA 256-bit

**Detection Patterns**:
- Functions: `X509_get_signature_nid`, `X509_get_pubkey`, `EVP_PKEY_bits`, `EVP_PKEY_id`
- Weakness: MD5, SHA1 signatures or RSA keys < 2048 bits

## 9. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific certificates or public keys to prevent MITM attacks

**Implementation**:
- Extract certificate/public key: `X509_digest()` for cert fingerprint or `EVP_PKEY_get1_RSA()` for public key
- Compare with pinned values in verification callback set via `SSL_CTX_set_verify()`
- Store pins as SHA256 hashes of certificates or SPKI (Subject Public Key Info)

**Detection Patterns**:
- Functions: `X509_digest`, `EVP_PKEY_get1_RSA`, custom verification callbacks
- Implementation: Hardcoded certificate fingerprints or public key hashes in code
