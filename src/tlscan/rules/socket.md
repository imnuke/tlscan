# Raw Socket SSL/TLS Security Rules

This document defines security rules for raw socket usage in binaries. When raw sockets are detected, this rule set helps identify whether SSL/TLS is properly applied and which library is used.

## Meta-Rule Mapping

| Rule | Meta-Rule(s) | Priority | Description |
|------|--------------|----------|-------------|
| R1 | M1 | MUST | TLS Wrapper Detection |
| R2 | N/A | MUST | SSL Library Identification |

**Notes**:
- Raw sockets (BSD sockets API) do not provide encryption by default.
- SSL/TLS must be implemented via a wrapper library (OpenSSL, GnuTLS, mbedTLS, etc.).
- Once the SSL library is identified, refer to the appropriate library-specific rules (e.g., `rule_openssl.md`).
- This rule set is a **gateway** to library-specific rules, not a comprehensive SSL/TLS analysis.

## Socket API Reference

**Core Socket Functions** (indicate network I/O):
| Function | Purpose |
|----------|---------|
| `socket()` | Create socket file descriptor |
| `connect()` | Connect to remote host |
| `send()` / `recv()` | Send/receive data (TCP) |
| `sendto()` / `recvfrom()` | Send/receive data (UDP) |
| `write()` / `read()` | Generic I/O on socket fd |
| `sendmsg()` / `recvmsg()` | Advanced message sending |

**Network Address Functions**:
| Function | Purpose |
|----------|---------|
| `getaddrinfo()` | DNS resolution |
| `inet_addr()` / `inet_pton()` | Address conversion |
| `gethostbyname()` | Legacy DNS lookup |

---

## R1: TLS Wrapper Detection

**Meta-Rule(s)**: M1  |  **Priority**: MUST

**What to Verify**: Raw sockets are wrapped with an SSL/TLS library before transmitting sensitive data.

**Implementation**:
The secure pattern requires an SSL/TLS library to wrap the socket:

```
socket() → connect() → [SSL_set_fd()] → [SSL_connect()] → [SSL_write()/SSL_read()]
                          ↑              ↑                  ↑
                   SSL library wraps the socket fd
```

The insecure pattern sends data directly on the socket:

```
socket() → connect() → send()/recv()  ← PLAINTEXT - No SSL wrapper
```

**SSL Wrapper Functions by Library**:

| Library | Set Socket FD | Handshake | Send | Receive |
|---------|---------------|-----------|------|---------|
| OpenSSL | `SSL_set_fd()` | `SSL_connect()` | `SSL_write()` | `SSL_read()` |
| GnuTLS | `gnutls_transport_set_int()` | `gnutls_handshake()` | `gnutls_record_send()` | `gnutls_record_recv()` |
| mbedTLS | `mbedtls_ssl_set_bio()` | `mbedtls_ssl_handshake()` | `mbedtls_ssl_write()` | `mbedtls_ssl_read()` |
| wolfSSL | `wolfSSL_set_fd()` | `wolfSSL_connect()` | `wolfSSL_write()` | `wolfSSL_read()` |
| NSS | `SSL_ImportFD()` | `SSL_ForceHandshake()` | `PR_Write()` | `PR_Read()` |

**Detection Patterns**:

**Secure Pattern** (SSL wrapper present):
1. Socket creation: `socket(AF_INET, SOCK_STREAM, 0)`
2. Connection: `connect(fd, ...)`
3. SSL binding: `SSL_set_fd(ssl, fd)` or equivalent
4. SSL handshake: `SSL_connect(ssl)` or equivalent
5. Encrypted I/O: `SSL_write(ssl, ...)` / `SSL_read(ssl, ...)`

**Insecure Pattern** (no SSL wrapper):
1. Socket creation: `socket(AF_INET, SOCK_STREAM, 0)`
2. Connection: `connect(fd, ...)`
3. **Direct I/O**: `send(fd, ...)` / `recv(fd, ...)` ← PLAINTEXT

**Conditional Pattern** (may be insecure):
```c
if (use_ssl) {
    SSL_connect(ssl);
    SSL_write(ssl, data, len);
} else {
    send(fd, data, len, 0);  // PLAINTEXT FALLBACK
}
```

**Binary Analysis**:

Look for these function call sequences:

| Sequence | Result | Reason |
|----------|--------|--------|
| `socket` → `connect` → `SSL_*` | Check library rules | SSL wrapper present |
| `socket` → `connect` → `gnutls_*` | Check library rules | SSL wrapper present |
| `socket` → `connect` → `mbedtls_*` | Check library rules | SSL wrapper present |
| `socket` → `connect` → `send`/`recv` | FAIL | No SSL wrapper |
| `socket` → `connect` → conditional | CONDITIONAL | May have plaintext path |

**Port-Based Detection**:
- Port 443: Expected to use SSL/TLS
- Port 80: Expected plaintext HTTP (may be vulnerability if sensitive data)
- Port 8443, 8080, etc.: Context-dependent

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Reason |
|----------|--------|--------|
| SSL library wrapper functions called | PASS (proceed to library rules) | SSL/TLS applied |
| Direct `send()`/`recv()` on network socket | FAIL | Plaintext transmission |
| Conditional SSL/plaintext paths | CONDITIONAL | Trace control flow |
| Only local/Unix sockets | N/A | Not network traffic |
| Cannot determine socket usage | UNDETERMINED | Insufficient evidence |

---

## R2: SSL Library Identification

**Meta-Rule(s)**: N/A (library-specific)  |  **Priority**: MUST

**What to Verify**: Identify which SSL/TLS library is used for detailed rule application.

**Implementation**:
Once R1 confirms SSL wrapper is present, identify the specific library to apply detailed rules.

**Library Detection Patterns**:

### OpenSSL

**Distinctive Functions**:
| Function | Purpose |
|----------|---------|
| `SSL_CTX_new()` | Create SSL context |
| `SSL_new()` | Create SSL object |
| `SSL_set_fd()` | Bind to socket |
| `SSL_connect()` | Client handshake |
| `SSL_write()` / `SSL_read()` | Encrypted I/O |
| `SSL_CTX_set_verify()` | Set verification mode |

**Linked Library**: `libssl.so`, `libcrypto.so`

**Rule File**: `rule_openssl.md`

---

### GnuTLS

**Distinctive Functions**:
| Function | Purpose |
|----------|---------|
| `gnutls_init()` | Initialize session |
| `gnutls_certificate_allocate_credentials()` | Create credentials |
| `gnutls_transport_set_int()` | Bind to socket |
| `gnutls_handshake()` | Perform handshake |
| `gnutls_record_send()` / `gnutls_record_recv()` | Encrypted I/O |

**Linked Library**: `libgnutls.so`

**Rule File**: `rule_gnutls.md`

---

### mbedTLS (formerly PolarSSL)

**Distinctive Functions**:
| Function | Purpose |
|----------|---------|
| `mbedtls_ssl_init()` | Initialize SSL context |
| `mbedtls_ssl_config_init()` | Initialize config |
| `mbedtls_ssl_set_bio()` | Bind to I/O callbacks |
| `mbedtls_ssl_handshake()` | Perform handshake |
| `mbedtls_ssl_write()` / `mbedtls_ssl_read()` | Encrypted I/O |
| `mbedtls_entropy_init()` | Initialize entropy |

**Linked Library**: `libmbedtls.so`, `libmbedcrypto.so`, `libmbedx509.so`

**Rule File**: `rule_mbedtls.md`

---

### wolfSSL (formerly CyaSSL)

**Distinctive Functions**:
| Function | Purpose |
|----------|---------|
| `wolfSSL_CTX_new()` | Create SSL context |
| `wolfSSL_new()` | Create SSL object |
| `wolfSSL_set_fd()` | Bind to socket |
| `wolfSSL_connect()` | Client handshake |
| `wolfSSL_write()` / `wolfSSL_read()` | Encrypted I/O |

**Linked Library**: `libwolfssl.so`

**Rule File**: Use `rule_openssl.md` as reference (API compatible)

---

### NSS (Network Security Services)

**Distinctive Functions**:
| Function | Purpose |
|----------|---------|
| `NSS_Init()` | Initialize NSS |
| `SSL_ImportFD()` | Create SSL socket |
| `SSL_ForceHandshake()` | Force handshake |
| `PR_Write()` / `PR_Read()` | NSPR I/O |

**Linked Library**: `libnss3.so`, `libnspr4.so`, `libssl3.so`

**Rule File**: No dedicated rule file (less common)

---

### BoringSSL

**Distinctive Functions**: Same as OpenSSL (fork)

**Notes**: BoringSSL is Google's fork of OpenSSL. It removes some APIs and changes defaults but uses similar function names.

**Rule File**: Use `rule_openssl.md` with awareness of BoringSSL differences

---

**Library Detection Summary**:

| Library | Key Function Prefix | Linked Library |
|---------|---------------------|----------------|
| OpenSSL | `SSL_*`, `EVP_*` | libssl, libcrypto |
| GnuTLS | `gnutls_*` | libgnutls |
| mbedTLS | `mbedtls_*` | libmbedtls, libmbedcrypto |
| wolfSSL | `wolfSSL_*` | libwolfssl |
| NSS | `SSL_*`, `NSS_*`, `PR_*` | libnss3, libnspr4 |

**PASS/FAIL/CONDITIONAL Criteria**:
| Scenario | Result | Next Step |
|----------|--------|-----------|
| OpenSSL functions detected | IDENTIFIED | Apply `rule_openssl.md` |
| GnuTLS functions detected | IDENTIFIED | Apply `rule_gnutls.md` |
| mbedTLS functions detected | IDENTIFIED | Apply `rule_mbedtls.md` |
| wolfSSL functions detected | IDENTIFIED | Apply `rule_openssl.md` (compatible) |
| Multiple libraries detected | CONDITIONAL | Analyze separately |
| No SSL library identified | FAIL | No SSL/TLS implementation |

---

## Vulnerability Indicators

### Critical Vulnerabilities

**1. No SSL Wrapper** (M1 violation):
```c
// FAIL: Plaintext transmission
fd = socket(AF_INET, SOCK_STREAM, 0);
connect(fd, ...);
send(fd, sensitive_data, len, 0);  // PLAINTEXT!
```

**2. Conditional SSL with Plaintext Fallback**:
```c
// FAIL: Downgrade attack possible
if (ssl_available && use_ssl) {
    SSL_connect(ssl);
} else {
    // Falls back to plaintext
}
send(...);
```

**3. Error Handling Falls Back to Plaintext**:
```c
// FAIL: Error fallback to plaintext
if (SSL_connect(ssl) != 1) {
    // Instead of failing, continues without SSL
    use_plaintext = true;
}
```

### Detection Patterns

**Plaintext Socket I/O** (look for these without SSL wrapper):
```
send(fd, ...)
recv(fd, ...)
write(fd, ...)  // when fd is a network socket
read(fd, ...)   // when fd is a network socket
sendto(fd, ...)
recvfrom(fd, ...)
```

**Port Numbers in Code**:
| Port | Expected Protocol | Risk if Plaintext |
|------|-------------------|-------------------|
| 80 | HTTP | Medium (if sensitive data) |
| 443 | HTTPS | HIGH (should be encrypted) |
| 8080 | HTTP alternate | Medium |
| 8443 | HTTPS alternate | HIGH |
| 25 | SMTP | HIGH (if auth/data) |
| 465/587 | SMTPS/Submission | HIGH |
| 993 | IMAPS | HIGH |
| 995 | POP3S | HIGH |

---

## Analysis Workflow

When analyzing a binary with raw socket usage:

```
1. Detect socket() calls
         ↓
2. Trace socket fd to I/O operations
         ↓
3. Check for SSL library wrapper (R1)
         ↓
   ┌─────┴─────┐
   │           │
   ↓           ↓
SSL wrapper  No wrapper
present      detected
   │           │
   ↓           ↓
4. Identify    FAIL for M1
library (R2)   (plaintext)
   │
   ↓
5. Apply library-specific rules:
   - OpenSSL → rule_openssl.md
   - GnuTLS  → rule_gnutls.md
   - mbedTLS → rule_mbedtls.md
   - libcurl → rule_libcurl.md
```

---

## Result Determination Summary

| Priority | Scenario | Result |
|----------|----------|--------|
| MUST | SSL wrapper detected | PASS (proceed to library rules) |
| MUST | No SSL wrapper, direct socket I/O | FAIL |
| MUST | Conditional SSL/plaintext | CONDITIONAL |
| MUST | Library identified | Proceed to library rules |
| MUST | No library identified but SSL present | UNDETERMINED |
| N/A | Only local/Unix sockets | Not applicable |
