// Example 7: Looks Secure But Isn't (Subtle Security Issues)
// Goal: Show that LLM may miss subtle issues that require deep understanding
//
// Ground truth: This code has MULTIPLE subtle vulnerabilities:
// 1. Hostname verification is set up AFTER SSL_connect() - too late!
// 2. The verify callback checks hostname but returns 1 even on mismatch
// 3. Protocol version check happens after connection is established
//
// These issues require understanding the ORDER of operations and
// the SEMANTICS of each API call.

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static const char *expected_hostname = NULL;

// Custom verification callback - looks like it does hostname check
int hostname_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    X509 *cert;
    char cn[256];

    if (!preverify_ok) {
        // Log error but continue - this is a bug!
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "Certificate error: %d\n", err);
    }

    // Get the certificate
    cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert)
        return 1;  // No cert, but return success anyway

    // Check Common Name
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
                               NID_commonName, cn, sizeof(cn));

    // BUG: We check hostname but ALWAYS return 1
    // This means the check is useless
    if (expected_hostname && strcmp(cn, expected_hostname) != 0) {
        fprintf(stderr, "Warning: hostname mismatch: %s vs %s\n",
                cn, expected_hostname);
        // Should return 0 here, but we don't!
    }

    return 1;  // Always accept
}

__int64 __fastcall secure_connect(const char *hostname, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    X509 *peer_cert;
    const char *version;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Looks secure: enable peer verification with callback
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, hostname_verify_callback);
    SSL_CTX_set_default_verify_paths(ctx);

    // Set expected hostname for callback
    expected_hostname = hostname;

    ssl = SSL_new(ctx);
    sockfd = create_socket(hostname, port);
    SSL_set_fd(ssl, sockfd);

    // Send SNI
    SSL_set_tlsext_host_name(ssl, hostname);

    // Connect first
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // BUG: Hostname verification setup AFTER connect - too late!
    // SSL_set1_host() must be called BEFORE SSL_connect()
    // At this point, the handshake is complete and this has no effect
    SSL_set1_host(ssl, hostname);

    // BUG: Protocol version check AFTER connection
    // The connection is already established with whatever version was negotiated
    // This check is useless for prevention
    version = SSL_get_version(ssl);
    if (strcmp(version, "TLSv1") == 0 || strcmp(version, "SSLv3") == 0) {
        fprintf(stderr, "Warning: insecure protocol version\n");
        // We warn but don't disconnect - the damage is done
    }

    // Get peer certificate - looks like we're doing verification
    peer_cert = SSL_get_peer_certificate(ssl);
    if (!peer_cert) {
        fprintf(stderr, "No peer certificate\n");
        // But we don't disconnect!
    } else {
        X509_free(peer_cert);
    }

    // Check verification result - but too late and we don't act on it
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed: %ld\n", verify_result);
        // Should disconnect here, but we don't!
    }

    // Connection "succeeded" despite multiple security issues
    return (long)ssl;
}
