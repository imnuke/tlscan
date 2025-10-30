# Raw Socket SSL/TLS Security Rules

## 1. SSL/TLS Usage Detection
**Priority**: MUST
**Description**: When using raw sockets (socket(), connect(), send(), recv()), detect if SSL/TLS wrappers are properly applied.

**Implementation**:
- Raw sockets MUST be wrapped with SSL/TLS library (OpenSSL, GnuTLS, mbedTLS, etc.)
- Check dataflow: socket() ’ connect() ’ SSL_set_fd() ’ SSL_connect() ’ SSL_write()/SSL_read()
- Avoid: socket() ’ connect() ’ send()/recv() directly (plaintext)
- Verify SSL/TLS is not conditional or has plaintext fallback

**Detection Patterns**:
- Secure pattern: `socket()` followed by `SSL_set_fd()` or equivalent
- Insecure pattern: `socket()` followed directly by `send()`/`recv()`/`write()`/`read()` without SSL wrapper
- Port-based checks: Different handling for port 443 vs 80 may indicate conditional SSL
- Protocol detection: Parsing data to determine if SSL should be used

**Vulnerability Indicators**:
- Direct use of send()/recv()/write()/read() on network sockets
- No SSL library initialization before data transmission
- Conditional SSL based on port number or user input
- Error handling that falls back to plaintext socket operations

**Common SSL Libraries for Socket Wrapping**:
- OpenSSL: SSL_set_fd(), SSL_connect(), SSL_write(), SSL_read()
- GnuTLS: gnutls_transport_set_int(), gnutls_handshake()
- mbedTLS: mbedtls_ssl_set_bio(), mbedtls_ssl_handshake()
- Other: Detect by looking for ssl/tls in function names wrapping socket FDs
