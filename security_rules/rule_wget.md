# wget Command-Line Tool SSL/TLS Security Rules

## 1. SSL/TLS Usage Detection
**Priority**: MUST
**Description**: Verify that HTTPS is actually being used in commands/scripts.

**Implementation**:
- Check URL scheme: "https://" vs "http://"
- Look for `--https-only` flag (enforces HTTPS-only mode)
- Check scripts for conditional URL construction
- Verify no HTTP fallback paths

**Detection Patterns**:
- Command patterns: `wget https://` vs `wget http://`
- Enforcement flag: `--https-only` presence
- Conditional URLs: shell variable substitution affecting protocol
- Config files: check `https_only = on` in wgetrc

**Vulnerability Indicators**:
- Hardcoded HTTP URLs for sensitive operations
- Missing `--https-only` flag
- Scripts with protocol fallback logic
- Config files with `https_only = off`

## 2. Certificate Chain Checking
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

## 3. Hostname Verification
**Priority**: MUST
**Description**: Verify certificate matches hostname

**Implementation**:
- Default: hostname verification is enabled
- **CRITICAL VULNERABILITY**: `--no-check-certificate` also disables hostname verification

**Detection Patterns**:
- Vulnerability: presence of `--no-check-certificate`

## 4. Protocol Version
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

## 5. HTTPS Enforcement
**Priority**: RECOMMENDED
**Description**: Ensure HTTPS is used and enforce secure connections

**Implementation**:
- Use `--https-only` to reject non-HTTPS URLs
- Use `--no-http-keep-alive` if HTTP persistence causes security issues

**Detection Patterns**:
- Flags: `--https-only`
- Vulnerability: Not enforcing HTTPS for sensitive operations

## 6. Certificate File Formats
**Priority**: INFORMATIONAL
**Description**: Specify certificate file formats if needed

**Implementation**:
- `--certificate=FILE`: client certificate file
- `--certificate-type=TYPE`: PEM (default) or DER
- `--private-key=FILE`: private key file
- `--private-key-type=TYPE`: PEM (default) or DER

**Detection Patterns**:
- Flags: `--certificate`, `--certificate-type`, `--private-key`

## 7. Configuration Files
**Priority**: RECOMMENDED
**Description**: Check wget configuration files for insecure settings

**Implementation**:
- System-wide: `/etc/wgetrc` or `/usr/local/etc/wgetrc`
- User-specific: `~/.wgetrc` or file specified by `--config`
- Settings can override command-line flags

**Detection Patterns**:
- Config files: check for `check_certificate = off` or `secure_protocol = SSLv3`
- Vulnerability: Insecure settings in wgetrc files

## 8. Post-Processing and Security
**Priority**: INFORMATIONAL
**Description**: Secure handling of downloaded content

**Implementation**:
- Use `--content-disposition` to respect server-suggested filenames (with caution)
- Be aware of directory traversal via malicious filenames
- Use `--restrict-file-names` to sanitize downloaded filenames

**Detection Patterns**:
- Flags: `--content-disposition`, `--restrict-file-names`
- Vulnerability: Unsafe handling of downloaded files
