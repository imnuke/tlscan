# wget Command-Line SSL/TLS Security Rules

This document defines security rules for wget command-line tool usage in scripts and binaries. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3, M4 | MUST | Certificate & Hostname Verification (Combined) |
| R3 | M2 | MUST | Protocol Version Enforcement |
| R4 | M5 | MUST | Cipher Suite Selection (Limited) |
| R5 | S2 | SHOULD | Cryptographic Strength (Backend-Dependent) |
| LS1 | N/A | SHOULD | Configuration File Analysis |

**Notes**:
- Entropy/RNG (S3) is not applicable to wget CLI as it relies on the underlying SSL backend.
- Certificate revocation (S1) checking is not directly supported by wget.
- Certificate pinning (O1) is not supported by wget.
- R2 combines M3 and M4 because `--no-check-certificate` disables both certificate chain verification AND hostname verification simultaneously.
- R5 (S2) is backend-dependent - wget relies on the SSL backend for cryptographic strength enforcement.

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

## Binary Analysis Guidance

**CRITICAL**: When analyzing compiled binaries (ELF files) for wget usage:

1. **wget is an EXTERNAL COMMAND, not a library function**
   - Do NOT search for "wget" in the function list - it won't exist
   - wget is invoked via system(), popen(), execvp(), or similar

2. **How to Find wget Usage in Binaries**:
   - Search STRINGS for command paths: `/usr/bin/wget`, `/bin/wget`, `wget `
   - Use `list_strings_filter(filter="wget")` to find command invocations
   - Look for strings containing wget arguments: `--no-check-certificate`, `https://`

3. **Analysis Flow for Binaries**:
   a. Search strings for "wget" patterns
   b. Find xrefs to these strings to locate calling functions
   c. Decompile those functions to see how wget command is constructed
   d. Check for insecure options in the command string

4. **Common Patterns**:
   - Hardcoded: `system("wget --no-check-certificate https://...")`
   - Variable: `snprintf(cmd, "wget %s https://...", opts)`
   - Environment: Command options from environment variables

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

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | SATISFIED | TLS connection |
| `--https-only` used | SATISFIED | Only HTTPS allowed |
| URL starts with `http://` | UNSATISFIED | Plaintext connection |
| Fallback to HTTP on error | UNSATISFIED | Downgrade possible |
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
- `wget ... --no-check-certificate` → UNSATISFIED (disables M3 AND M4)
- `wget https://...` (no --no-check-certificate) → SATISFIED (uses defaults)
- `wget ... --ca-certificate=/path/to/ca.crt` → SATISFIED (custom CA, verification enabled)
- Script variable: `wget $WGET_OPTS` where WGET_OPTS may contain `--no-check-certificate` → CONDITIONAL

**Vulnerability Indicators**:
- Presence of `--no-check-certificate` anywhere in command
- Environment variables that may inject the flag
- Alias definitions: `alias wget='wget --no-check-certificate'`
- Config file containing `check_certificate = off`

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No `--no-check-certificate` flag | SATISFIED | Default verification enabled (M3+M4) |
| `--ca-certificate` or `--ca-directory` specified | SATISFIED | Custom CA, verification enabled |
| `--no-check-certificate` present | UNSATISFIED | Both M3 and M4 disabled |
| `check_certificate = off` in wgetrc | UNSATISFIED | Both M3 and M4 disabled |
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
- `wget --secure-protocol=TLSv1_2 https://...` → SATISFIED
- `wget --secure-protocol=TLSv1_3 https://...` → SATISFIED
- `wget --secure-protocol=PFS https://...` → SATISFIED (if OpenSSL supports TLS 1.2+)
- `wget --secure-protocol=TLSv1 https://...` → UNSATISFIED
- `wget --secure-protocol=SSLv3 https://...` → UNSATISFIED
- `wget https://...` (no protocol option) → UNDETERMINED (system-dependent default)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `--secure-protocol=TLSv1_2` or `TLSv1_3` | SATISFIED | Secure protocol enforced |
| `--secure-protocol=PFS` | SATISFIED | Forward secrecy enforced |
| `--secure-protocol=TLSv1`, `TLSv1_1` | UNSATISFIED | Insecure protocol |
| `--secure-protocol=SSLv2`, `SSLv3` | UNSATISFIED | Insecure protocol |
| `--secure-protocol=auto` or not set | UNDETERMINED | Depends on system (not traceable) |
| Protocol option from variable | CONDITIONAL | Trace variable |

---

## R4: Cipher Suite Selection (Limited)

**Meta-Rule(s)**: M5  |  **Priority**: MUST

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
- `--ciphers 'HIGH:!aNULL:!eNULL'` → SATISFIED (strong ciphers)
- `--secure-protocol=PFS` → SATISFIED (forward secrecy)
- `--ciphers` containing `NULL`, `EXPORT`, `RC4` → UNSATISFIED
- No cipher option → CONDITIONAL (uses backend default)

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string configured | SATISFIED | Weak ciphers excluded |
| `--secure-protocol=PFS` | SATISFIED | Forward secrecy enforced |
| Cipher string contains weak ciphers | UNSATISFIED | Insecure ciphers allowed |
| No cipher configuration | CONDITIONAL | Uses backend default |
| Cipher string from variable | CONDITIONAL | Trace variable |

---

## R5: Cryptographic Strength (Backend-Dependent)

**Meta-Rule(s)**: S2  |  **Priority**: SHOULD

**What to Verify**: Certificates use strong signature algorithms (SHA-256+) and adequate key sizes (RSA 2048+).

**Implementation**:
- wget relies on the underlying SSL backend for cryptographic strength enforcement
- Check the backend version to determine default security level
- wget has no direct option to configure cryptographic strength requirements

**Backend Cryptographic Strength Defaults**:
| Backend | Version | Default Security Level | Verdict |
|---------|---------|----------------------|---------|
| OpenSSL | 3.0+ | Level 2 (SHA-256+, RSA 2048+) | SATISFIED |
| OpenSSL | 1.1.x | Level 1 (SHA-1 allowed, RSA 1024+) | UNSATISFIED |
| OpenSSL | 1.0.x | Level 0 (weak algorithms allowed) | UNSATISFIED |
| GnuTLS | 3.6+ | NORMAL priority (secure defaults) | SATISFIED |
| GnuTLS | < 3.6 | May allow weak algorithms | UNSATISFIED |

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Backend version with secure defaults (see table) | SATISFIED | Backend enforces strong crypto |
| Backend version with weak defaults (see table) | UNSATISFIED | Backend allows weak crypto |
| Backend version unknown | UNDETERMINED | Cannot determine backend security |

---

## LS1: Explicit Configuration File Analysis

**Meta-Rule(s)**: N/A (library-specific)  |  **Priority**: SHOULD

**What to Verify**: When code explicitly references a wgetrc configuration file, verify it does not contain insecure settings.

**Important**: This rule ONLY applies when the code explicitly references configuration files. Do NOT scan implicit config file locations (like `~/.wgetrc` or `/etc/wgetrc`) unless the code explicitly mentions them.

**When This Rule Applies**:
- Code uses `--config=<file>` option
- Code explicitly references `WGETRC` environment variable
- Code explicitly reads/mentions a wgetrc file path

**When This Rule Does NOT Apply**:
- Implicit default config file loading (wget's automatic wgetrc search)
- No explicit config file reference in the analyzed code

**Security-Critical Settings** (when config file IS analyzed):
| Setting | Secure Value | Insecure Value |
|---------|--------------|----------------|
| `check_certificate` | `on` | `off` |
| `secure_protocol` | `TLSv1_2`, `TLSv1_3`, `PFS` | `SSLv2`, `SSLv3`, `TLSv1` |
| `https_only` | `on` | `off` |

**Detection Patterns**:
- `wget --config=/path/to/file` → Analyze the specified config file
- `WGETRC=/path/to/file wget ...` → Analyze the specified config file
- `wget https://...` (no --config) → LS1 does NOT apply

**SATISFIED/UNSATISFIED/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No explicit config file reference | N/A | Rule does not apply |
| `--config=<file>` with secure settings | SATISFIED | Explicit config is safe |
| `--config=<file>` with `check_certificate = off` | UNSATISFIED | Disables verification |
| `--config=<file>` with insecure `secure_protocol` | UNSATISFIED | Allows weak protocols |
| `WGETRC` from variable | CONDITIONAL | Trace variable to find config path |
| Config file path from variable | CONDITIONAL | Trace variable to find config path |

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
# UNSATISFIED: Hardcoded insecure
wget --no-check-certificate https://...

# UNSATISFIED: HTTP for sensitive data
wget http://api.example.com/secrets

# UNSATISFIED: Insecure protocol
wget --secure-protocol=SSLv3 https://...
wget --secure-protocol=TLSv1 https://...

# CONDITIONAL: Variable options
wget $WGET_OPTS https://...
wget ${WGET_FLAGS} https://...

# CONDITIONAL: Constructed URL
wget "${PROTOCOL}://example.com"

# UNSATISFIED: HTTP fallback
wget https://... || wget http://...

# SATISFIED: Secure configuration
wget --https-only --secure-protocol=TLSv1_2 https://...

# CONDITIONAL: Custom config
wget --config=/path/to/custom.wgetrc https://...
```

### Recursive Download Considerations

When using recursive downloads (`-r`), consider:

```bash
# CONDITIONAL: May follow HTTP links from HTTPS page
wget -r https://example.com/

# SATISFIED: Enforces HTTPS for recursive downloads
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
| MUST | Option explicitly secure | SATISFIED |
| MUST | Option explicitly insecure | UNSATISFIED |
| MUST | No option, secure default (wget ≥1.10) | SATISFIED |
| MUST | No option, version-dependent default | UNDETERMINED |
| SHOULD | Feature enabled | SATISFIED |
| SHOULD | Feature explicitly disabled | UNSATISFIED |
| SHOULD | Feature not configured | UNDETERMINED |
| MAY | Feature not supported | N/A |
