# wget Command-Line SSL/TLS Security Rules

This document defines security rules for wget command-line tool usage in scripts and binaries. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3, M4 | MUST | Certificate & Hostname Verification (Combined) |
| R3 | M2 | MUST | Protocol Version Enforcement |
| R4 | M5 | SHOULD | Cipher Suite Selection (Limited) |
| LS1 | N/A | SHOULD | Configuration File Analysis |

**Notes**:
- Entropy/RNG (S3) is not applicable to wget CLI as it relies on the underlying SSL backend.
- Certificate revocation (S1) checking is not directly supported by wget.
- Certificate pinning (O1) is not supported by wget.
- R2 combines M3 and M4 because `--no-check-certificate` disables both certificate chain verification AND hostname verification simultaneously.

## Version Detection Hints

| Pattern | Indicates |
|---------|-----------|
| `--https-only` option | wget 1.17+ |
| `--secure-protocol=TLSv1_3` | wget 1.18+ with OpenSSL 1.1.1+ |
| `--secure-protocol=PFS` | wget with OpenSSL 1.0.1+ |
| `--ciphers` option | wget 1.18+ |

**wget Version History**:
| Version | Certificate Verification Default |
|---------|----------------------------------|
| < 1.10 | Disabled (INSECURE) |
| ≥ 1.10 | Enabled (SECURE) |

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm HTTPS is used for connections, not HTTP or plaintext.

**Implementation**:
- URL scheme must be `https://` not `http://`
- Use `--https-only` to reject non-HTTPS URLs (wget 1.17+)
- Default: Allows both HTTP and HTTPS

**Command-Line Options**:
| Option | Purpose | Secure Usage |
|--------|---------|--------------|
| URL argument | Target URL | Must start with `https://` |
| `--https-only` | Reject non-HTTPS | Use for HTTPS enforcement |
| `-O -` | Output to stdout | Verify URL is HTTPS |

**Configuration File Settings**:
| Setting | wgetrc syntax | Effect |
|---------|---------------|--------|
| HTTPS only | `https_only = on` | Reject non-HTTPS URLs |

**Detection Patterns**:
- URL strings: `https://` vs `http://` in command arguments
- HTTPS enforcement: `--https-only` flag
- Variable URLs: `wget "$URL"`, `wget "${SCHEME}://..."`
- Recursive downloads: `-r` with HTTPS start URL

**Vulnerability Indicators**:
- Hardcoded `http://` URLs for sensitive operations
- Shell variables constructing URLs without HTTPS enforcement
- Missing `--https-only` when handling sensitive data
- Recursive downloads that may follow HTTP links
- Fallback to HTTP in error handling: `wget https://... || wget http://...`

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | PASS | TLS connection |
| `--https-only` used | PASS | Only HTTPS allowed |
| URL starts with `http://` | FAIL | Plaintext connection |
| Fallback to HTTP on error | FAIL | Downgrade possible |
| URL from variable | CONDITIONAL | Trace variable source |
| Recursive without `--https-only` | CONDITIONAL | May follow HTTP links |

---

## R2: Certificate & Hostname Verification (Combined)

**Meta-Rule(s)**: M3, M4  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated AND certificate identity matches hostname.

**Implementation**:
- Default (≥1.10): Both certificate chain verification AND hostname verification are ENABLED
- `--no-check-certificate`: Disables ALL certificate checks (chain AND hostname)
- `--ca-certificate=<file>`: Specify CA certificate file
- `--ca-directory=<dir>`: Specify CA certificate directory

**Combined Rule Rationale**: The `--no-check-certificate` flag disables both M3 (certificate chain verification) and M4 (hostname verification) simultaneously. There is no wget option to disable only one of these checks - they are coupled.

**Command-Line Options**:
| Option | Purpose | Effect |
|--------|---------|--------|
| `--no-check-certificate` | Skip SSL verification | DISABLES M3 AND M4 |
| `--ca-certificate=FILE` | CA certificate file | Custom trust store |
| `--ca-directory=DIR` | CA certificate directory | Custom trust store |
| (default ≥1.10) | Normal verification | SECURE (both M3 and M4) |

**Configuration File Settings**:
| Setting | wgetrc syntax | Effect |
|---------|---------------|--------|
| Disable verification | `check_certificate = off` | INSECURE |
| CA certificate | `ca_certificate = /path/to/ca.crt` | Custom trust |
| CA directory | `ca_directory = /path/to/certs/` | Custom trust |

**Default Behavior (Version-Dependent)**:
| wget Version | Default | Security |
|--------------|---------|----------|
| < 1.10 | Disabled | INSECURE |
| ≥ 1.10 | Enabled | SECURE |

**Detection Patterns**:
- `wget ... --no-check-certificate` → FAIL (disables M3 AND M4)
- `wget https://...` (no --no-check-certificate) → PASS (uses defaults)
- `wget ... --ca-certificate=/path/to/ca.crt` → PASS (custom CA, verification enabled)
- Script variable: `wget $WGET_OPTS` where WGET_OPTS may contain `--no-check-certificate` → CONDITIONAL

**Vulnerability Indicators**:
- Presence of `--no-check-certificate` anywhere in command
- Environment variables that may inject the flag
- Alias definitions: `alias wget='wget --no-check-certificate'`
- Config file containing `check_certificate = off`

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No `--no-check-certificate` flag | PASS | Default verification enabled (M3+M4) |
| `--ca-certificate` or `--ca-directory` specified | PASS | Custom CA, verification enabled |
| `--no-check-certificate` present | FAIL | Both M3 and M4 disabled |
| `check_certificate = off` in wgetrc | FAIL | Both M3 and M4 disabled |
| Options from variable/config | CONDITIONAL | Trace option source |
| wgetrc file exists | CONDITIONAL | Check for insecure settings |

---

## R3: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is negotiated.

**Implementation**:
- `--secure-protocol=<protocol>`: Set TLS/SSL protocol version
- Default: `auto` - SSL library chooses (typically TLS 1.2 on modern systems)
- Available values: `auto`, `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1_1`, `TLSv1_2`, `TLSv1_3`, `PFS`

**Command-Line Options**:
| Option | Protocol | Security |
|--------|----------|----------|
| `--secure-protocol=TLSv1_3` | TLS 1.3 only | SECURE |
| `--secure-protocol=TLSv1_2` | TLS 1.2 only | SECURE |
| `--secure-protocol=PFS` | TLS with PFS ciphers | SECURE |
| `--secure-protocol=TLSv1_1` | TLS 1.1 only | INSECURE |
| `--secure-protocol=TLSv1` | TLS 1.0 only | INSECURE |
| `--secure-protocol=SSLv3` | SSL 3.0 only | INSECURE |
| `--secure-protocol=SSLv2` | SSL 2.0 only | INSECURE |
| `--secure-protocol=auto` or (default) | Library default | CONDITIONAL |

**Configuration File Settings**:
| Setting | wgetrc syntax | Effect |
|---------|---------------|--------|
| Protocol version | `secure_protocol = TLSv1_2` | Set protocol |

**PFS Mode**:
The `PFS` (Perfect Forward Secrecy) option enforces cipher suites that provide forward secrecy. This is secure but does not specify a minimum TLS version - combine with modern OpenSSL for TLS 1.2+.

**Default Behavior**:
| System | Default (`auto`) | Security |
|--------|------------------|----------|
| Modern Linux (OpenSSL 1.1.1+) | TLS 1.2+ | Typically SECURE |
| Older systems | May allow TLS 1.0/1.1 | CONDITIONAL |

**Detection Patterns**:
- `wget --secure-protocol=TLSv1_2 https://...` → PASS
- `wget --secure-protocol=TLSv1_3 https://...` → PASS
- `wget --secure-protocol=PFS https://...` → PASS (if OpenSSL supports TLS 1.2+)
- `wget --secure-protocol=TLSv1 https://...` → FAIL
- `wget --secure-protocol=SSLv3 https://...` → FAIL
- `wget https://...` (no protocol option) → CONDITIONAL (depends on system)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `--secure-protocol=TLSv1_2` or `TLSv1_3` | PASS | Secure protocol enforced |
| `--secure-protocol=PFS` | PASS | Forward secrecy enforced |
| `--secure-protocol=TLSv1`, `TLSv1_1` | FAIL | Insecure protocol |
| `--secure-protocol=SSLv2`, `SSLv3` | FAIL | Insecure protocol |
| `--secure-protocol=auto` or not set | CONDITIONAL | Depends on system |
| Protocol option from variable | CONDITIONAL | Trace variable |

---

## R4: Cipher Suite Selection (Limited)

**Meta-Rule(s)**: M5  |  **Priority**: SHOULD

**What to Verify**: Strong cipher suites are used if cipher selection is available.

**Implementation**:
- `--ciphers=<list>`: Specify cipher suites (wget 1.18+)
- `--secure-protocol=PFS`: Enforces Perfect Forward Secrecy ciphers
- Default: Uses SSL backend default ciphers

**Command-Line Options**:
| Option | Purpose | Availability |
|--------|---------|--------------|
| `--ciphers` | Cipher suite list | wget 1.18+ |
| `--secure-protocol=PFS` | PFS ciphers only | All versions |

**Configuration File Settings**:
| Setting | wgetrc syntax | Effect |
|---------|---------------|--------|
| Ciphers | `ciphers = HIGH:!aNULL:!eNULL` | Custom cipher list |

**Insecure Cipher Patterns** (in cipher string):
| Pattern | Risk |
|---------|------|
| `NULL` | No encryption |
| `EXPORT` | Weak export ciphers |
| `RC4` | Broken stream cipher |
| `DES` | Weak block cipher (56-bit) |
| `aNULL` | No authentication |
| `eNULL` | No encryption |

**Detection Patterns**:
- `--ciphers 'HIGH:!aNULL:!eNULL'` → PASS (strong ciphers)
- `--secure-protocol=PFS` → PASS (forward secrecy)
- `--ciphers` containing `NULL`, `EXPORT`, `RC4` → FAIL
- No cipher option → CONDITIONAL (uses backend default)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string configured | PASS | Weak ciphers excluded |
| `--secure-protocol=PFS` | PASS | Forward secrecy enforced |
| Cipher string contains weak ciphers | FAIL | Insecure ciphers allowed |
| No cipher configuration | CONDITIONAL | Uses backend default |
| Cipher string from variable | CONDITIONAL | Trace variable |

---

## LS1: Configuration File Analysis

**Meta-Rule(s)**: N/A (library-specific)  |  **Priority**: SHOULD

**What to Verify**: wgetrc configuration files do not contain insecure settings.

**Implementation**:
wget reads configuration from multiple locations in order:

1. System-wide: `/etc/wgetrc` or `/usr/local/etc/wgetrc`
2. User-specific: `~/.wgetrc`
3. Specified: `--config=<file>`
4. Environment: `WGETRC` variable

**Configuration File Locations**:
| Location | Scope | Priority |
|----------|-------|----------|
| `/etc/wgetrc` | System | Lowest |
| `/usr/local/etc/wgetrc` | System | Low |
| `~/.wgetrc` | User | Medium |
| `--config=FILE` | Command | High |
| `WGETRC` env var | Session | Highest |

**Security-Critical Settings**:
| Setting | Secure Value | Insecure Value |
|---------|--------------|----------------|
| `check_certificate` | `on` | `off` |
| `secure_protocol` | `TLSv1_2`, `TLSv1_3`, `PFS` | `SSLv2`, `SSLv3`, `TLSv1` |
| `https_only` | `on` | `off` |

**Dangerous wgetrc Contents**:
```
# INSECURE - disables certificate verification
check_certificate = off

# INSECURE - allows weak protocols
secure_protocol = SSLv3
secure_protocol = TLSv1

# Not necessarily insecure but should verify
https_only = off
```

**Safe wgetrc Example**:
```
# Enable certificate verification (default, but explicit is good)
check_certificate = on

# Enforce TLS 1.2 minimum
secure_protocol = TLSv1_2

# Enforce HTTPS only
https_only = on

# Custom CA bundle (if needed)
ca_certificate = /etc/ssl/certs/ca-certificates.crt
```

**Detection Patterns**:
- Presence of `check_certificate = off` in any wgetrc → FAIL for R2
- Presence of `secure_protocol = SSLv*` or `TLSv1` or `TLSv1_1` → FAIL for R3
- Presence of custom wgetrc via `--config` or `WGETRC` → CONDITIONAL

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No wgetrc files or all settings secure | PASS | Safe configuration |
| `check_certificate = off` found | FAIL | Disables verification |
| Insecure `secure_protocol` found | FAIL | Allows weak protocols |
| Custom wgetrc specified | CONDITIONAL | Must analyze file contents |
| `WGETRC` environment variable set | CONDITIONAL | Trace variable |

---

## Script Analysis Patterns

When analyzing shell scripts that use wget, look for these patterns:

### Environment Variables

| Variable | Risk |
|----------|------|
| `WGETRC` | Custom config file - verify contents |
| `SSL_CERT_FILE` | Custom CA - verify it's valid |
| `SSL_CERT_DIR` | Custom CA directory |

### Script Patterns to Flag

```bash
# FAIL: Hardcoded insecure
wget --no-check-certificate https://...

# FAIL: HTTP for sensitive data
wget http://api.example.com/secrets

# FAIL: Insecure protocol
wget --secure-protocol=SSLv3 https://...
wget --secure-protocol=TLSv1 https://...

# CONDITIONAL: Variable options
wget $WGET_OPTS https://...
wget ${WGET_FLAGS} https://...

# CONDITIONAL: Constructed URL
wget "${PROTOCOL}://example.com"

# FAIL: HTTP fallback
wget https://... || wget http://...

# PASS: Secure configuration
wget --https-only --secure-protocol=TLSv1_2 https://...

# CONDITIONAL: Custom config
wget --config=/path/to/custom.wgetrc https://...
```

### Recursive Download Considerations

When using recursive downloads (`-r`), consider:

```bash
# CONDITIONAL: May follow HTTP links from HTTPS page
wget -r https://example.com/

# PASS: Enforces HTTPS for recursive downloads
wget -r --https-only https://example.com/
```

---

## Unsupported Features

The following meta-rule features are **not supported** by wget:

| Feature | Meta-Rule | wget Support |
|---------|-----------|--------------|
| Certificate Revocation | S1 | Not supported |
| Certificate Pinning | O1 | Not supported |
| Separate hostname verification | M4 | Coupled with M3 |

For applications requiring these features, consider using curl or a custom TLS client.

---

## Result Determination Summary

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | Option explicitly secure | PASS |
| MUST | Option explicitly insecure | FAIL |
| MUST | No option, secure default (wget ≥1.10) | PASS |
| MUST | No option, version-dependent default | CONDITIONAL |
| SHOULD | Feature enabled | PASS |
| SHOULD | Feature explicitly disabled | FAIL |
| SHOULD | Feature not configured | CONDITIONAL |
| MAY | Feature not supported | N/A |
