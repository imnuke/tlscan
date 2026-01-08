// Example 6: Configuration File Dependency
// Goal: Show that LLM cannot determine security without reading config files
//
// Ground truth: The security of this code depends ENTIRELY on the config file
// /etc/myapp/tls.conf. Without reading that file, we cannot determine if
// the application is secure or not.
//
// In real firmware analysis, we would need to:
// 1. Find the config file in the firmware filesystem
// 2. Parse it to extract tls_verify value
// 3. Determine the security posture based on that value

struct tls_config {
    int tls_enabled;
    int tls_verify;
    int tls_version_min;
    char ca_cert_path[256];
    char client_cert_path[256];
};

// Parse config file - simplified version
int parse_tls_config(const char *config_path, struct tls_config *cfg)
{
    FILE *fp;
    char line[512];
    char key[64], value[256];

    fp = fopen(config_path, "r");
    if (!fp)
        return -1;

    // Default values
    cfg->tls_enabled = 0;
    cfg->tls_verify = 0;  // Default: no verification
    cfg->tls_version_min = 0;
    cfg->ca_cert_path[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^=]=%255s", key, value) == 2) {
            if (strcmp(key, "tls_enabled") == 0)
                cfg->tls_enabled = atoi(value);
            else if (strcmp(key, "tls_verify") == 0)
                cfg->tls_verify = atoi(value);
            else if (strcmp(key, "tls_version_min") == 0)
                cfg->tls_version_min = atoi(value);
            else if (strcmp(key, "ca_cert_path") == 0)
                strncpy(cfg->ca_cert_path, value, sizeof(cfg->ca_cert_path) - 1);
        }
    }

    fclose(fp);
    return 0;
}

// Main TLS connection function
__int64 __fastcall connect_with_tls(const char *hostname, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    struct tls_config cfg;
    int sockfd;

    // Load configuration from file
    // The actual security depends on what's in /etc/myapp/tls.conf
    if (parse_tls_config("/etc/myapp/tls.conf", &cfg) < 0) {
        return -1;
    }

    if (!cfg.tls_enabled) {
        // Plain TCP - no encryption
        sockfd = create_socket(hostname, port);
        return sockfd;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Set minimum TLS version from config
    if (cfg.tls_version_min > 0) {
        SSL_CTX_set_min_proto_version(ctx, cfg.tls_version_min);
    }

    // Certificate verification depends on config value
    // We cannot know if this is secure without reading the config file!
    if (cfg.tls_verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        // Load CA certificates if specified
        if (cfg.ca_cert_path[0] != '\0') {
            SSL_CTX_load_verify_locations(ctx, cfg.ca_cert_path, NULL);
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else {
        // INSECURE: No certificate verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

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

    return (long)ssl;
}

// Alternative: environment variable based configuration
// Security depends on runtime environment
__int64 __fastcall connect_with_env_config(const char *hostname, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    const char *verify_env;
    int verify_peer;
    int sockfd;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Get verification setting from environment variable
    // Cannot determine security without knowing the runtime environment
    verify_env = getenv("TLS_VERIFY_PEER");
    verify_peer = verify_env ? atoi(verify_env) : 0;

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);
    sockfd = create_socket(hostname, port);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    return (long)ssl;
}
