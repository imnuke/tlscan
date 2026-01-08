// Example 1: Cross-file Dependency
// Goal: Show that LLM cannot trace values from function parameters
//
// Ground truth: The security of this code depends on how callers invoke it.
// Without dataflow analysis, we cannot determine the actual verify_mode value.

__int64 __fastcall ssl_connect_to_server(const char *hostname, int port, int verify_mode)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // The security behavior depends entirely on the verify_mode parameter
    // We need to trace callers to know if this is secure or not
    SSL_CTX_set_verify(ctx, verify_mode, NULL);

    ssl = SSL_new(ctx);
    sockfd = create_socket(hostname, port);

    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    return (long)ssl;
}

// This function is exported and called by other binaries
// The actual verify_mode value comes from:
// - A config file (e.g., /etc/myapp/ssl.conf)
// - Command line argument
// - Another binary that calls this library
__int64 __fastcall init_secure_connection(const char *host, int port, struct config *cfg)
{
    int verify;

    // verify comes from config structure, which is loaded from external file
    verify = cfg->ssl_verify_peer;

    return ssl_connect_to_server(host, port, verify);
}
