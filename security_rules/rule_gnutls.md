# GnuTLS SSL/TLS Security Rules

## 1. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain

**Implementation**:
- Use `gnutls_certificate_verify_peers2()` or `gnutls_certificate_verify_peers3()` to verify certificate
- Returns flags indicating verification status (check for `GNUTLS_CERT_INVALID`, `GNUTLS_CERT_REVOKED`, etc.)
- Must call after handshake with `gnutls_handshake()`
- Use `gnutls_certificate_set_x509_trust_file()` to load CA certificates

**Detection Patterns**:
- Functions: `gnutls_certificate_verify_peers2`, `gnutls_certificate_verify_peers3`, `gnutls_certificate_set_x509_trust_file`
- Constants: `GNUTLS_CERT_INVALID`, `GNUTLS_CERT_SIGNER_NOT_FOUND`, `GNUTLS_CERT_EXPIRED`
- Vulnerability: Not calling verification functions or ignoring return values

## 2. Hostname Verification
**Priority**: MUST
**Description**: Verify certificate matches hostname

**Implementation**:
- Use `gnutls_server_name_set()` with `GNUTLS_NAME_DNS` to set expected hostname
- Use `gnutls_certificate_verify_peers3()` with hostname parameter (preferred over `verify_peers2`)
- Alternative: manual verification using `gnutls_x509_crt_check_hostname()`

**Detection Patterns**:
- Functions: `gnutls_server_name_set`, `gnutls_certificate_verify_peers3`, `gnutls_x509_crt_check_hostname`
- Constants: `GNUTLS_NAME_DNS`
- Vulnerability: Not setting server name or not verifying hostname

## 3. Protocol Version and Cipher Selection
**Priority**: MUST
**Description**: Enforce secure protocol versions and cipher suites

**Implementation**:
- Use `gnutls_priority_set_direct()` with priority string to configure protocols and ciphers
- Recommended: `"NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"` (disables insecure versions)
- Or use `"SECURE128"`, `"SECURE192"`, `"SECURE256"` for predefined secure configurations
- More control: `gnutls_priority_init()` with detailed priority string

**Detection Patterns**:
- Functions: `gnutls_priority_set_direct`, `gnutls_priority_init`
- Priority strings: `NORMAL`, `SECURE128`, `SECURE192`, `SECURE256`, `VERS-TLS1.2`, `VERS-TLS1.3`
- Vulnerability: Using `NORMAL` without disabling old protocols, or custom weak priority strings

## 4. Certificate Revocation
**Priority**: RECOMMENDED
**Description**: Check certificate revocation status

**Implementation**:
- OCSP: Use `gnutls_ocsp_status_request_enable_client()` to enable OCSP stapling
- Check status with `gnutls_ocsp_status_request_get()`
- CRL: Use `gnutls_certificate_set_x509_crl_file()` to load CRL file

**Detection Patterns**:
- Functions: `gnutls_ocsp_status_request_enable_client`, `gnutls_ocsp_status_request_get`, `gnutls_certificate_set_x509_crl_file`
- Vulnerability: Missing revocation checks

## 5. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific certificates or public keys

**Implementation**:
- Manual implementation: extract certificate with `gnutls_certificate_get_peers()`
- Compute fingerprint: `gnutls_x509_crt_get_fingerprint()`
- Compare against pinned values in verification callback

**Detection Patterns**:
- Functions: `gnutls_certificate_get_peers`, `gnutls_x509_crt_get_fingerprint`, `gnutls_certificate_set_verify_function`
- Implementation: Hardcoded fingerprints or pin validation code

## 6. Session Resumption Security
**Priority**: RECOMMENDED
**Description**: Secure session resumption mechanisms

**Implementation**:
- Use `gnutls_session_ticket_enable_client()` for TLS 1.3 session tickets
- Ensure proper session data handling with `gnutls_session_get_data2()`
- Avoid insecure session ID caching

**Detection Patterns**:
- Functions: `gnutls_session_ticket_enable_client`, `gnutls_session_get_data2`
