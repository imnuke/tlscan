// Example 3: Hidden Vulnerability (Missing Hostname Verification)
// Goal: Show that LLM may miss subtle security issues
//
// Ground truth: This code enables certificate verification but DOES NOT
// verify the hostname. An attacker with any valid certificate can perform
// a man-in-the-middle attack. This violates RFC 6125 and RFC 9525.

__int64 __fastcall secure_https_connect(const char *url)
{
    SSL_CTX *ctx;
    SSL *ssl;
    char hostname[256];
    int port;
    int sockfd;

    // Parse URL to extract hostname and port
    parse_url(url, hostname, &port);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Certificate verification is enabled - looks secure!
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Load trusted CA certificates
    SSL_CTX_set_default_verify_paths(ctx);

    // Set minimum TLS version to 1.2 - good practice
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Disable insecure ciphers - good practice
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4");

    ssl = SSL_new(ctx);
    sockfd = create_socket(hostname, port);
    SSL_set_fd(ssl, sockfd);

    // BUG: Missing SSL_set_tlsext_host_name(ssl, hostname)!
    // Without this, the server doesn't know which certificate to present
    // (SNI extension not sent)

    // BUG: Missing SSL_set1_host(ssl, hostname)!
    // Without this, OpenSSL won't verify that the certificate matches
    // the hostname we're connecting to

    // The connection will succeed with ANY valid certificate
    // An attacker with a certificate for attacker.com can MITM this connection

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Connection "succeeded" but is vulnerable to MITM
    return (long)ssl;
}
