# curl Command-Line SSL/TLS Security Rules

This document defines security rules for curl command-line tool usage in scripts and binaries. Each rule references the corresponding meta-rule(s) from `metarule.md`.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Usage Detection |
| R2 | M3, M4 | MUST | Certificate & Hostname Verification (Combined) |
| R3 | M2 | MUST | Protocol Version Enforcement |
| R4 | M5 | SHOULD | Cipher Suite Selection |
| R5 | S1 | SHOULD | Certificate Revocation Checking |
| R6 | O1 | MAY | Certificate Pinning |

**Notes**:
- Entropy/RNG (S3) is not applicable to curl CLI as it relies on the underlying SSL backend.
- R2 combines M3 and M4 because `--insecure`/`-k` disables both certificate chain verification AND hostname verification simultaneously.

## Version Detection Hints

| Pattern | Indicates |
|---------|-----------|
| `--tls-max` option | curl 7.54.0+ |
| `--tlsv1.3` option | curl 7.52.0+ |
| `--pinnedpubkey` option | curl 7.39.0+ |
| `--proto-default` option | curl 7.45.0+ |
| `--ssl-revoke-best-effort` | curl 7.70.0+ |

**Default TLS Version History**:
| curl Version | Default Minimum | Security |
|--------------|-----------------|----------|
| < 7.39.0 | SSLv3 allowed | INSECURE |
| 7.39.0 - 7.76.x | SSLv3 disabled, TLS 1.0+ | INSECURE |
| 7.77.0 - 8.15.x | SSL 2/3 refused, TLS 1.0+ | INSECURE |
| ≥ 8.16.0 | TLS 1.2 minimum | SECURE |

---

## R1: TLS Usage Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Confirm HTTPS is used for connections, not HTTP or plaintext.

**Implementation**:
- URL scheme must be `https://` not `http://`
- Use `--proto =https` to restrict to HTTPS only
- Use `--proto-redir =https` to prevent redirect downgrades
- Default: No protocol restriction - allows HTTP and HTTPS

**Command-Line Options**:
| Option | Purpose | Secure Usage |
|--------|---------|--------------|
| URL argument | Target URL | Must start with `https://` |
| `--proto` | Allowed protocols | `=https` or `-http` |
| `--proto-redir` | Protocols for redirects | `=https` or `-http` |
| `--proto-default` | Default for schemeless URLs | `https` |

**Detection Patterns**:
- URL strings: `https://` vs `http://` in command arguments
- Protocol restrictions: `--proto =https`, `--proto -all,https`
- Redirect safety: `--proto-redir =https`
- Variable URLs: `curl "$URL"`, `curl "${SCHEME}://..."`

**Vulnerability Indicators**:
- Hardcoded `http://` URLs for sensitive operations
- Shell variables constructing URLs: `curl "${USE_SSL:+https}://..."`
- Missing `--proto =https` when handling sensitive data
- No `--proto-redir` allowing HTTP redirect after HTTPS start
- Fallback to HTTP in error handling: `curl https://... || curl http://...`

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| URL starts with `https://` | PASS | TLS connection |
| `--proto =https` used | PASS | Only HTTPS allowed |
| URL starts with `http://` | FAIL | Plaintext connection |
| Fallback to HTTP on error | FAIL | Downgrade possible |
| URL from variable | CONDITIONAL | Trace variable source |
| No `--proto-redir` with HTTPS URL | CONDITIONAL | Redirect may downgrade |

---

## R2: Certificate & Hostname Verification (Combined)

**Meta-Rule(s)**: M3, M4  |  **Priority**: MUST

**What to Verify**: Server certificate chain is validated AND certificate identity matches hostname.

**Implementation**:
- Default: Both certificate chain verification AND hostname verification are ENABLED
- `--insecure` / `-k`: Disables ALL certificate checks (chain AND hostname)
- `--cacert <file>`: Specify CA certificate bundle
- `--capath <dir>`: Specify CA certificate directory

**Combined Rule Rationale**: The `--insecure`/`-k` flag disables both M3 (certificate chain verification) and M4 (hostname verification) simultaneously. There is no curl option to disable only one of these checks - they are coupled.

**Command-Line Options**:
| Option | Purpose | Effect |
|--------|---------|--------|
| `--insecure`, `-k` | Skip SSL verification | DISABLES M3 AND M4 |
| `--cacert <file>` | CA certificate file | Custom trust store |
| `--capath <dir>` | CA certificate directory | Custom trust store |
| (default) | Normal verification | SECURE (both M3 and M4) |

**Default Behavior**:
| Setting | Default | Security |
|---------|---------|----------|
| Certificate verification | Enabled | SECURE |
| Hostname verification | Enabled | SECURE |

**Detection Patterns**:
- `curl ... --insecure` → FAIL (disables M3 AND M4)
- `curl ... -k` → FAIL (same as --insecure)
- `curl https://...` (no -k) → PASS (uses defaults)
- `curl ... --cacert /path/to/ca.crt` → PASS (custom CA, verification enabled)
- Script variable: `curl $CURL_OPTS` where CURL_OPTS may contain `-k` → CONDITIONAL

**Vulnerability Indicators**:
- Presence of `--insecure` or `-k` anywhere in command
- Environment variables that may inject `-k`: `CURL_OPTIONS`, `CURL_OPTS`
- Alias definitions: `alias curl='curl -k'`
- Config file `.curlrc` containing `insecure` option

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| No `--insecure`/`-k` flag | PASS | Default verification enabled (M3+M4) |
| `--cacert` or `--capath` specified | PASS | Custom CA, verification enabled |
| `--insecure` or `-k` present | FAIL | Both M3 and M4 disabled |
| Options from variable/config | CONDITIONAL | Trace option source |
| `.curlrc` file exists | CONDITIONAL | Check for `insecure` setting |

---

## R3: Protocol Version Enforcement

**Meta-Rule(s)**: M2  |  **Priority**: MUST

**What to Verify**: Only TLS 1.2 or higher is negotiated.

**Implementation**:
- `--tlsv1.2`: Set TLS 1.2 as minimum version
- `--tlsv1.3`: Set TLS 1.3 as minimum version
- `--tls-max <version>`: Set maximum TLS version
- Default: Depends on curl version (see Version Detection Hints)

**Command-Line Options**:
| Option | Minimum Version | Security |
|--------|-----------------|----------|
| `--tlsv1.3` | TLS 1.3 | SECURE |
| `--tlsv1.2` | TLS 1.2 | SECURE |
| `--tlsv1.1` | TLS 1.1 | INSECURE |
| `--tlsv1.0` | TLS 1.0 | INSECURE |
| `--tlsv1` | TLS 1.0 | INSECURE |
| `--sslv3` | SSL 3.0 | INSECURE (refused since 7.77.0) |
| `--sslv2` | SSL 2.0 | INSECURE (refused since 7.77.0) |
| (none) | curl version dependent | See table below |

**curl Version Defaults (when no explicit --tlsv* flag)**:
| curl Version | Default Minimum | Security |
|--------------|-----------------|----------|
| < 7.39.0 | SSLv3 allowed | INSECURE |
| 7.39.0 - 8.15.x | TLS 1.0 | INSECURE |
| ≥ 8.16.0 | TLS 1.2 | SECURE |

**Backend Minimum (HARD FLOOR - applies regardless of curl version)**:
| Backend | Version Range | Library Default | With Config |
|---------|---------------|-----------------|-------------|
| OpenSSL | 3.0+ | TLS 1.2 | Use MinProtocol from openssl.cnf |
| OpenSSL | 1.1.1+ | TLS 1.0 | Use MinProtocol from openssl.cnf |
| OpenSSL | 1.0.x | TLS 1.0 | Use MinProtocol from openssl.cnf |
| GnuTLS | 3.6+ | TLS 1.2 | Use priority from gnutls config |
| GnuTLS | < 3.6 | TLS 1.0 | Use priority from gnutls config |
| mbedTLS | 2.x+ | TLS 1.2 | Compile-time only |
| wolfSSL | 4.x+ | TLS 1.2 | Compile-time only |

**IMPORTANT**: The backend's minimum is a hard floor that curl cannot go below.
If the backend config (e.g., openssl.cnf) sets MinProtocol=TLSv1.2, the backend
will refuse connections below TLS 1.2 even if curl's default would allow TLS 1.0.

**TLS Version Resolution (when no --tlsv* flag specified)**:

The effective minimum TLS version = max(curl_default, backend_minimum)

| curl Version | Backend | Config MinProtocol | Effective Min | Result |
|--------------|---------|-------------------|---------------|--------|
| 8.0.1 | OpenSSL 1.1.1 | TLSv1.2 | TLS 1.2 | PASS |
| 8.0.1 | OpenSSL 1.1.1 | (none) | TLS 1.0 | FAIL |
| 8.16.0 | OpenSSL 1.1.1 | (none) | TLS 1.2 | PASS |
| 7.50.0 | GnuTLS 3.7.0 | - | TLS 1.2 | PASS |
| Any | OpenSSL 3.0+ | (none) | TLS 1.2 | PASS |

**Resolution logic**:
1. If explicit --tlsv1.2 or --tlsv1.3 → PASS
2. If explicit --tlsv1.0 or --tlsv1.1:
   - Check backend config MinProtocol: if ≥ TLS 1.2 → PASS (backend refuses lower)
   - Otherwise → FAIL (insecure negotiation possible)
3. If no flag, both curl and backend versions known → Use max(curl_default, backend_minimum)
4. If backend config MinProtocol found → Use that as backend_minimum
5. If no config but backend version known → Use Library Default from table
6. If neither curl nor backend known → UNDETERMINED

**Detection Patterns**:
- `curl --tlsv1.2 https://...` → PASS (TLS 1.2 minimum)
- `curl --tlsv1.3 https://...` → PASS (TLS 1.3 minimum)
- `curl --tlsv1 https://...` → Check backend config/version for effective minimum
- `curl --tlsv1.0 https://...` → Check backend config/version for effective minimum
- `curl --tlsv1.1 https://...` → Check backend config/version for effective minimum
- `curl https://...` (no TLS option) → Use resolution logic above

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `--tlsv1.2` or `--tlsv1.3` used | PASS | Secure minimum enforced |
| `--tlsv1.*` with backend min ≥ TLS 1.2 | PASS | Backend refuses insecure protocols |
| `--tlsv1.*` with backend min < TLS 1.2 | FAIL | Insecure negotiation possible |
| `--sslv2`, `--sslv3` | FAIL | Insecure protocols |
| No flag, effective min ≥ TLS 1.2 | PASS | Resolution yields secure minimum |
| No flag, effective min < TLS 1.2 | FAIL | Resolution yields insecure minimum |
| No flag, cannot determine effective min | UNDETERMINED | Insufficient version info |
| TLS option from variable | CONDITIONAL | Trace variable |

---

## R4: Cipher Suite Selection

**Meta-Rule(s)**: M5  |  **Priority**: SHOULD

**What to Verify**: Strong cipher suites are used, weak ciphers excluded.

**Implementation**:
- `--ciphers <list>`: Cipher suites for TLS 1.2 and below
- `--tls13-ciphers <list>`: Cipher suites for TLS 1.3
- Format depends on SSL backend (OpenSSL, NSS, GnuTLS, etc.)
- Default: Uses SSL backend default ciphers

**Command-Line Options**:
| Option | Purpose | Format |
|--------|---------|--------|
| `--ciphers` | TLS 1.2 ciphers | Backend-specific |
| `--tls13-ciphers` | TLS 1.3 ciphers | Backend-specific |
| `--proxy-ciphers` | Proxy TLS 1.2 ciphers | Backend-specific |
| `--proxy-tls13-ciphers` | Proxy TLS 1.3 ciphers | Backend-specific |

**Insecure Cipher Patterns** (in cipher string):
| Pattern | Risk |
|---------|------|
| `NULL` | No encryption |
| `EXPORT` | Weak export ciphers |
| `RC4` | Broken stream cipher |
| `DES` | Weak block cipher (56-bit) |
| `MD5` | Weak hash for HMAC |
| `aNULL` | No authentication |
| `eNULL` | No encryption |

**Secure Cipher String Example** (OpenSSL format):
```
HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA
```

**Backend Cipher Suite Defaults (when no --ciphers specified)**:
| Backend | Version | Default Config | Security |
|---------|---------|----------------|----------|
| OpenSSL | 3.0+ | TLS_AES_* + ECDHE preferred | PASS |
| OpenSSL | 1.1.1+ | DEFAULT:!aNULL:!eNULL (ECDHE) | PASS |
| OpenSSL | 1.0.x | DEFAULT (may include weak) | CONDITIONAL |
| GnuTLS | 3.6+ | NORMAL priority | PASS |
| mbedTLS | 2.x+ | Secure defaults | PASS |
| wolfSSL | 4.x+ | Secure defaults | PASS |

**Resolution**: When no --ciphers specified and backend is detected, use Security column.

**Detection Patterns**:
- `--ciphers 'HIGH:!aNULL:!eNULL'` → PASS (strong ciphers)
- `--ciphers` containing `NULL`, `EXPORT`, `RC4` → FAIL
- No `--ciphers`, backend PASS in table → PASS (secure backend default)
- No `--ciphers`, backend unknown → CONDITIONAL (cannot verify default)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| Strong cipher string configured | PASS | Weak ciphers excluded |
| Cipher string contains weak ciphers | FAIL | Insecure ciphers allowed |
| No `--ciphers`, backend detected as PASS | PASS | Uses secure backend default |
| No `--ciphers`, backend unknown | CONDITIONAL | Cannot verify backend default |
| Cipher string from variable | CONDITIONAL | Trace variable |

---

## R5: Certificate Revocation Checking

**Meta-Rule(s)**: S1  |  **Priority**: SHOULD

**What to Verify**: Certificate revocation status is checked.

**Implementation**:
- Revocation checking support varies by SSL backend
- `--ssl-revoke-best-effort`: Check CRL if available (Windows, curl 7.70.0+)
- `--ssl-no-revoke`: Disable revocation checking (Windows only)
- Default: Backend-dependent

**Command-Line Options**:
| Option | Purpose | Security |
|--------|---------|----------|
| `--ssl-revoke-best-effort` | Best-effort CRL check | SECURE |
| `--ssl-no-revoke` | Disable revocation | INSECURE |
| (default) | Backend behavior | Variable |

**Platform Notes**:
| Platform | Default Behavior |
|----------|------------------|
| Windows (Schannel) | CRL checking enabled by default |
| Linux (OpenSSL) | No automatic revocation checking |
| macOS (SecureTransport) | May use system OCSP |

**Backend Revocation Defaults (when no revocation option specified)**:
| Backend | Default Behavior | Verdict |
|---------|-----------------|---------|
| OpenSSL | DISABLED (no CRL/OCSP) | CONDITIONAL |
| GnuTLS | DISABLED | CONDITIONAL |
| mbedTLS | DISABLED | CONDITIONAL |
| Schannel (Windows) | CRL enabled | PASS |
| SecureTransport (macOS) | May use system OCSP | CONDITIONAL |
| wolfSSL | DISABLED | CONDITIONAL |

**Resolution**: When no revocation option specified and backend is detected, use Verdict column.
**Note**: CONDITIONAL (not FAIL) because S1 is a SHOULD requirement, not MUST.

**Detection Patterns**:
- `--ssl-revoke-best-effort` → PASS (revocation enabled)
- `--ssl-no-revoke` → CONDITIONAL (explicit disable of SHOULD)
- No revocation option, backend known → use Verdict from table

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `--ssl-revoke-best-effort` used | PASS | Revocation checking enabled |
| `--ssl-no-revoke` used | CONDITIONAL | Explicit disable of SHOULD requirement |
| No option, Schannel backend | PASS | Schannel enables CRL by default |
| No option, other backend | CONDITIONAL | SHOULD requirement not satisfied |

---

## R6: Certificate Pinning

**Meta-Rule(s)**: O1  |  **Priority**: MAY

**What to Verify**: Certificate or public key pinning is implemented.

**Implementation**:
- `--pinnedpubkey <hashes>`: Pin public key by SHA256 hash
- Format: `sha256//base64-encoded-hash`
- Multiple pins: Semicolon-separated
- Alternative: Path to file containing public key in PEM or DER format

**Command-Line Options**:
| Option | Purpose | Format |
|--------|---------|--------|
| `--pinnedpubkey` | Pin public key | `sha256//hash` or file path |

**Pin Format Examples**:
```bash
# Single pin
curl --pinnedpubkey "sha256//WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=" https://example.com

# Multiple pins (backup)
curl --pinnedpubkey "sha256//hash1;sha256//hash2" https://example.com

# From file
curl --pinnedpubkey /path/to/pubkey.pem https://example.com
```

**Detection Patterns**:
- `--pinnedpubkey` option present → PASS (pinning enabled)
- `--pinnedpubkey` not used → FAIL (pinning not implemented)
- Pin value from variable → CONDITIONAL (trace pin source)

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| `--pinnedpubkey` with hash | PASS | Pinning enabled |
| `--pinnedpubkey` not used | FAIL | Pinning not implemented |
| Pin value from variable | CONDITIONAL | Trace pin source |

---

## Script Analysis Patterns

When analyzing shell scripts that use curl, look for these patterns:

### Configuration Files

**`.curlrc` locations** (checked in order):
1. `$CURL_HOME/.curlrc`
2. `$HOME/.curlrc`
3. (Windows) `%APPDATA%\_curlrc`

**Dangerous `.curlrc` contents**:
```
insecure
# or
-k
```

### Environment Variables

| Variable | Risk |
|----------|------|
| `CURL_CA_BUNDLE` | Custom CA - verify it's valid |
| `SSL_CERT_FILE` | Custom CA - verify it's valid |
| `SSL_CERT_DIR` | Custom CA directory |

### Script Patterns to Flag

```bash
# FAIL: Hardcoded insecure
curl -k https://...
curl --insecure https://...

# FAIL: HTTP for sensitive data
curl http://api.example.com/secrets

# CONDITIONAL: Variable options
curl $CURL_OPTS https://...
curl ${CURL_FLAGS} https://...

# CONDITIONAL: Constructed URL
curl "${PROTOCOL}://example.com"

# FAIL: HTTP fallback
curl https://... || curl http://...

# CONDITIONAL: Check .curlrc
if [ -f ~/.curlrc ]; then ...
```

---

## Result Determination Summary

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | Option explicitly secure | PASS |
| MUST | Option explicitly insecure | FAIL |
| MUST | No option, secure default | PASS |
| MUST | No option, version-dependent default | UNDETERMINED |
| SHOULD | Feature enabled | PASS |
| SHOULD | Feature explicitly disabled | FAIL |
| SHOULD | Feature not configured | UNDETERMINED |
| MAY | Feature implemented | PASS |
| MAY | Feature not implemented | UNDETERMINED |
