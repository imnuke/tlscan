// Example 8: Library Default Behavior Dependency
// Goal: Show that security depends on understanding library defaults
//
// Ground truth: This code's security depends on LIBRARY DEFAULTS:
// - OpenSSL 1.0.x: SSL_VERIFY_NONE is default (INSECURE)
// - OpenSSL 1.1.x+: Still SSL_VERIFY_NONE by default
// - The code doesn't explicitly set verification mode in some paths
// - Security depends on which OpenSSL version is linked
//
// Multi-agent system would need to check binary's linked libraries
// to determine which OpenSSL version is used.

__int64 __fastcall create_client_context(int security_level)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return 0;

    switch (security_level) {
        case 0:
            // Explicitly insecure - no verification
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
            break;

        case 1:
            // "Default" security - but what IS the default?
            // We don't call SSL_CTX_set_verify at all
            // OpenSSL defaults to SSL_VERIFY_NONE
            // But developer might think "default = secure"
            break;

        case 2:
            // Explicitly secure
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_default_verify_paths(ctx);
            break;

        default:
            // Unknown level - use "safe default"
            // But we don't set anything, relying on library default
            // which is actually INSECURE
            break;
    }

    return (long)ctx;
}

// This function uses libcurl - different library, different defaults
// curl's default behavior has changed over versions
__int64 __fastcall curl_download(const char *url, int verify)
{
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (!curl)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);

    // If verify is -1, use "default" behavior
    // But what IS curl's default?
    // - Old curl: CURLOPT_SSL_VERIFYPEER defaults to 1 (secure)
    // - But CURLOPT_SSL_VERIFYHOST defaults to 2 (secure)
    // - Some embedded builds change these defaults!
    if (verify >= 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify ? 2 : 0);
    }
    // else: rely on defaults - security depends on curl build options

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

// This code's security depends on compile-time flags
// Cannot be determined without analyzing build system
#ifdef INSECURE_BUILD
#define DEFAULT_VERIFY 0
#else
#define DEFAULT_VERIFY 1
#endif

__int64 __fastcall conditional_compile_connect(const char *host, int port)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    // Security depends on compile-time flag
    // Binary analysis cannot easily determine this
    // without analyzing the actual binary values
    SSL_CTX_set_verify(ctx, DEFAULT_VERIFY ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

    if (DEFAULT_VERIFY) {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    ssl = SSL_new(ctx);
    sockfd = create_socket(host, port);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    return (long)ssl;
}
