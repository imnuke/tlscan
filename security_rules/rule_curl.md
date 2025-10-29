# cURL Command-Line Tool SSL/TLS Security Rules

## 1. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain against trusted CA certificates

**Implementation**:
- Default: certificate verification is enabled
- Specify CA bundle: `--cacert <file>` or `--capath <directory>`
- **CRITICAL VULNERABILITY**: `--insecure` or `-k` flag disables ALL certificate verification

**Detection Patterns**:
- Flags: `--cacert`, `--capath`
- Vulnerability: presence of `--insecure` or `-k` flag in command-line or scripts

## 2. Hostname Verification
**Priority**: MUST
**Description**: Verify that the certificate matches the hostname

**Implementation**:
- Default: hostname verification is enabled
- **CRITICAL VULNERABILITY**: `--insecure` or `-k` flag also disables hostname verification

**Detection Patterns**:
- Vulnerability: presence of `--insecure` or `-k` flag

## 3. Protocol Version
**Priority**: MUST
**Description**: Enforce secure TLS versions

**Implementation**:
- Use `--tlsv1.2` to enforce TLS 1.2 as minimum
- Use `--tlsv1.3` to enforce TLS 1.3
- Use `--tls-max <version>` to set maximum version
- Avoid: `--sslv2`, `--sslv3`, `--tlsv1.0`, `--tlsv1.1` (insecure)

**Detection Patterns**:
- Flags: `--tlsv1.2`, `--tlsv1.3`, `--tls-max`, `--ssl`, `--ssl-reqd`
- Vulnerability: Not specifying minimum TLS version or using insecure versions

## 4. Certificate Pinning
**Priority**: OPTIONAL (HIGH SECURITY)
**Description**: Pin specific public keys

**Implementation**:
- Use `--pinnedpubkey <hashes>` to specify SHA256 public key hashes
- Format: `sha256//base64hash` or path to file with public key

**Detection Patterns**:
- Flags: `--pinnedpubkey`
- Implementation: Public key hashes in command-line or config

## 5. Certificate Revocation
**Priority**: RECOMMENDED
**Description**: Check certificate revocation status

**Implementation**:
- CRL checking: limited support, depends on SSL backend
- `--ssl-no-revoke`: disables revocation checking (Windows only, insecure)

**Detection Patterns**:
- Flags: `--ssl-no-revoke`
- Vulnerability: Using `--ssl-no-revoke` flag

## 6. Cipher Suite Selection
**Priority**: RECOMMENDED
**Description**: Restrict cipher suites

**Implementation**:
- Use `--ciphers <list>` to specify allowed ciphers
- Format depends on SSL backend (OpenSSL, NSS, etc.)

**Detection Patterns**:
- Flags: `--ciphers`
- Vulnerability: Not restricting ciphers or allowing weak ciphers

## 7. Certificate File Formats
**Priority**: INFORMATIONAL
**Description**: Specify certificate file formats if needed

**Implementation**:
- `--cert-type <type>`: PEM (default), DER, P12
- `--cacert-type <type>`: CA certificate format
- `--key-type <type>`: private key format

**Detection Patterns**:
- Flags: `--cert-type`, `--cacert-type`, `--key-type`
