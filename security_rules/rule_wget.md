# wget Command-Line Tool SSL/TLS Security Rules

## 1. Certificate Chain Checking
**Priority**: MUST
**Description**: Verify the server's certificate chain

**Implementation**:
- Default: certificate verification is enabled
- Specify CA bundle: `--ca-certificate=FILE` to provide CA certificate file
- Specify CA directory: `--ca-directory=DIR` for directory with CA certificates
- **CRITICAL VULNERABILITY**: `--no-check-certificate` disables ALL certificate verification

**Detection Patterns**:
- Flags: `--ca-certificate`, `--ca-directory`
- Vulnerability: presence of `--no-check-certificate` in command-line, scripts, or wgetrc config

## 2. Hostname Verification
**Priority**: MUST
**Description**: Verify certificate matches hostname

**Implementation**:
- Default: hostname verification is enabled
- **CRITICAL VULNERABILITY**: `--no-check-certificate` also disables hostname verification

**Detection Patterns**:
- Vulnerability: presence of `--no-check-certificate`

## 3. Protocol Version
**Priority**: MUST
**Description**: Enforce secure TLS/SSL versions

**Implementation**:
- Use `--secure-protocol=TLSv1_2` to enforce TLS 1.2 minimum
- Or `--secure-protocol=TLSv1_3` for TLS 1.3
- Available options: `auto` (default), `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1_1`, `TLSv1_2`, `TLSv1_3`, `PFS`
- Avoid insecure: `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1_1`

**Detection Patterns**:
- Flags: `--secure-protocol`
- Vulnerability: Not specifying minimum protocol or using insecure versions

## 4. HTTPS Enforcement
**Priority**: RECOMMENDED
**Description**: Ensure HTTPS is used and enforce secure connections

**Implementation**:
- Use `--https-only` to reject non-HTTPS URLs
- Use `--no-http-keep-alive` if HTTP persistence causes security issues

**Detection Patterns**:
- Flags: `--https-only`
- Vulnerability: Not enforcing HTTPS for sensitive operations

## 5. Certificate File Formats
**Priority**: INFORMATIONAL
**Description**: Specify certificate file formats if needed

**Implementation**:
- `--certificate=FILE`: client certificate file
- `--certificate-type=TYPE`: PEM (default) or DER
- `--private-key=FILE`: private key file
- `--private-key-type=TYPE`: PEM (default) or DER

**Detection Patterns**:
- Flags: `--certificate`, `--certificate-type`, `--private-key`

## 6. Configuration Files
**Priority**: RECOMMENDED
**Description**: Check wget configuration files for insecure settings

**Implementation**:
- System-wide: `/etc/wgetrc` or `/usr/local/etc/wgetrc`
- User-specific: `~/.wgetrc` or file specified by `--config`
- Settings can override command-line flags

**Detection Patterns**:
- Config files: check for `check_certificate = off` or `secure_protocol = SSLv3`
- Vulnerability: Insecure settings in wgetrc files

## 7. Post-Processing and Security
**Priority**: INFORMATIONAL
**Description**: Secure handling of downloaded content

**Implementation**:
- Use `--content-disposition` to respect server-suggested filenames (with caution)
- Be aware of directory traversal via malicious filenames
- Use `--restrict-file-names` to sanitize downloaded filenames

**Detection Patterns**:
- Flags: `--content-disposition`, `--restrict-file-names`
- Vulnerability: Unsafe handling of downloaded files
