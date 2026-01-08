// Example 4: Misleading Code (Verify Callback Always Accepts)
// Goal: Show that LLM may be fooled by superficially secure code
//
// Ground truth: Although SSL_CTX_set_verify is called with SSL_VERIFY_PEER,
// the custom verify_callback always returns 1 (success), effectively
// disabling all certificate verification. This is a real-world vulnerability
// pattern found in many applications.

// This callback looks like it's doing verification, but it always accepts
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    // Log the certificate for debugging (looks legitimate)
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert) {
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        debug_log("Verifying certificate: %s", subject);
    }

    // Log any errors (looks like proper error handling)
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        debug_log("Certificate verification warning: %s",
                  X509_verify_cert_error_string(err));
        // But we continue anyway... this is the bug!
    }

    // BUG: Always return 1 regardless of verification result
    // This completely bypasses certificate verification
    // Any certificate (self-signed, expired, wrong hostname) will be accepted
    return 1;
}

__int64 __fastcall create_ssl_connection(const char *hostname, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // This LOOKS secure - we're setting SSL_VERIFY_PEER
    // But the callback makes it completely insecure
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    // Load CA certificates (pointless since callback ignores errors)
    SSL_CTX_set_default_verify_paths(ctx);

    // Good TLS settings (but verification is broken)
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    ssl = SSL_new(ctx);
    sockfd = create_socket(hostname, port);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Connection "succeeded" but accepts any certificate
    return (long)ssl;
}
