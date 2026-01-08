// Example 2: Complex Conditional Branches
// Goal: Show that LLM struggles to analyze multiple conditional paths
//
// Ground truth: This code has multiple security-relevant branches.
// The actual security depends on runtime values of use_ssl, skip_verify,
// cert_required, and allow_insecure flags.

__int64 __fastcall connect_with_options(
    const char *hostname,
    int port,
    int use_ssl,
    int skip_verify,
    int cert_required,
    int allow_insecure)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;

    sockfd = create_socket(hostname, port);
    if (sockfd < 0)
        return -1;

    if (!use_ssl) {
        // Plain TCP connection - no encryption at all
        return sockfd;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Complex conditional logic determines security behavior
    if (!skip_verify && cert_required) {
        // Secure path: full certificate verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    } else if (allow_insecure) {
        // Insecure path: no verification at all
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    } else if (skip_verify && !allow_insecure) {
        // Ambiguous path: skip verify but not explicitly insecure
        // What happens here? Default behavior depends on OpenSSL version
        // This is a subtle security issue
    } else {
        // Default path: what's the default behavior?
        // OpenSSL defaults to SSL_VERIFY_NONE
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Hostname verification only in one branch
    if (cert_required && !skip_verify) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    return (long)ssl;
}
