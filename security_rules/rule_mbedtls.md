# mbedTLS SSL/TLS Security Rules

## 1. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain

**Implementation**:
- Use `mbedtls_ssl_set_verify()` to set verification callback
- In callback, use `mbedtls_x509_crt_verify()` to verify certificate chain
- Load CA certificates with `mbedtls_x509_crt_parse_file()` or `mbedtls_x509_crt_parse()`
- Configuration: `mbedtls_ssl_conf_authmode()` with `MBEDTLS_SSL_VERIFY_REQUIRED`

**Detection Patterns**:
- Functions: `mbedtls_ssl_set_verify`, `mbedtls_x509_crt_verify`, `mbedtls_ssl_conf_authmode`, `mbedtls_x509_crt_parse`
- Constants: `MBEDTLS_SSL_VERIFY_REQUIRED`, `MBEDTLS_SSL_VERIFY_OPTIONAL`, `MBEDTLS_SSL_VERIFY_NONE`
- Vulnerability: Using `MBEDTLS_SSL_VERIFY_NONE` or not setting verification callback

## 2. Hostname Verification
**Priority**: MUST
**Description**: Verify certificate matches hostname

**Implementation**:
- Use `mbedtls_ssl_set_hostname()` to set expected hostname
- Automatic verification when hostname is set and verification mode is `REQUIRED`
- Manual: Use `mbedtls_x509_crt_verify_with_profile()` with custom verification

**Detection Patterns**:
- Functions: `mbedtls_ssl_set_hostname`, `mbedtls_x509_crt_verify_with_profile`
- Vulnerability: Not calling `mbedtls_ssl_set_hostname`

## 3. Protocol Version
**Priority**: MUST
**Description**: Enforce secure TLS versions

**Implementation**:
- Use `mbedtls_ssl_conf_min_version()` to set minimum protocol version
- Use `mbedtls_ssl_conf_max_version()` to set maximum protocol version
- Recommended: `MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3` for TLS 1.2 minimum
- Or `MBEDTLS_SSL_MINOR_VERSION_4` for TLS 1.3

**Detection Patterns**:
- Functions: `mbedtls_ssl_conf_min_version`, `mbedtls_ssl_conf_max_version`
- Constants: `MBEDTLS_SSL_MAJOR_VERSION_3`, `MBEDTLS_SSL_MINOR_VERSION_*`
- Vulnerability: Not setting minimum version or allowing TLS 1.0/1.1

## 4. Cipher Suite Selection
**Priority**: MUST
**Description**: Use strong cipher suites

**Implementation**:
- Use `mbedtls_ssl_conf_ciphersuites()` to specify allowed cipher suites
- Provide array of cipher suite IDs terminated with 0
- Recommended: Use only AEAD cipher suites (GCM, CCM, ChaCha20-Poly1305)

**Detection Patterns**:
- Functions: `mbedtls_ssl_conf_ciphersuites`, `mbedtls_ssl_get_ciphersuite_id`
- Constants: `MBEDTLS_TLS_*` cipher suite macros
- Vulnerability: Not restricting cipher suites or allowing weak ciphers

## 5. Certificate Revocation
**Priority**: RECOMMENDED
**Description**: Check certificate revocation

**Implementation**:
- CRL: Use `mbedtls_x509_crl_parse()` to load CRL
- Pass CRL to `mbedtls_x509_crt_verify()` or `mbedtls_x509_crt_verify_with_profile()`
- OCSP: Not natively supported, requires manual implementation

**Detection Patterns**:
- Functions: `mbedtls_x509_crl_parse`, `mbedtls_x509_crl_parse_file`
- Vulnerability: Missing CRL checks

## 6. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific certificates or public keys

**Implementation**:
- Manual implementation in verification callback
- Extract public key: `mbedtls_pk_write_pubkey_der()`
- Compare hash with pinned values

**Detection Patterns**:
- Functions: `mbedtls_pk_write_pubkey_der`, `mbedtls_md()` for hashing
- Implementation: Pin validation in custom verification callback

## 7. Entropy and Random Number Generation
**Priority**: MUST
**Description**: Ensure proper RNG initialization for mbedTLS (embedded systems)

**Implementation**:
- Initialize entropy: `mbedtls_entropy_init()`
- Setup RNG: `mbedtls_ctr_drbg_init()` and `mbedtls_ctr_drbg_seed()`
- Provide to SSL config: `mbedtls_ssl_conf_rng()`

**Detection Patterns**:
- Functions: `mbedtls_entropy_init`, `mbedtls_ctr_drbg_seed`, `mbedtls_ssl_conf_rng`
- Vulnerability: Missing or weak entropy source (critical for embedded systems)
