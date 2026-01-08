// Example 5: Multi-layer Call Chain (Requires Deep Dataflow Analysis)
// Goal: Show that LLM cannot trace values through multiple function calls
//
// Ground truth: This code IS SECURE because:
// - upscli_connect() is called by upsmon_connect() with flags=0x12
// - 0x12 = 0x10 | 0x02 = UPSCONN_SECURE | UPSCONN_CERTVERIFY
// - This means verify=1 in upscli_sslinit(), enabling SSL_VERIFY_PEER
//
// But LLM cannot know this without tracing the full call chain.

// This is the low-level SSL initialization function
// Called by upscli_connect() with verify parameter
__int64 __fastcall upscli_sslinit(__int64 ups, int verify)
{
    SSL *ssl;

    ssl = SSL_new(ssl_ctx);
    *(_QWORD *)(ups + 656) = ssl;

    if (ssl) {
        SSL_set_fd(ssl, *(int *)(ups + 12));

        // Security depends on 'verify' parameter
        // We need to trace callers to know the actual value
        if (verify)
            SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
        else
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

        if (SSL_connect(ssl) == 1)
            return 1;
    }
    return -1;
}

// Middle layer: connection function
// Called by application code (upsmon, upsc, etc.)
__int64 __fastcall upscli_connect(__int64 ups, const char *host, int port, int flags)
{
    int use_ssl;
    int verify;

    // Parse flags:
    // bit 0 (0x01): UPSCONN_TRYSSL - try SSL but fall back
    // bit 1 (0x02): UPSCONN_CERTVERIFY - verify certificate
    // bit 4 (0x10): UPSCONN_SECURE - require SSL

    use_ssl = (flags & 0x11) != 0;  // TRYSSL or SECURE
    verify = (flags >> 1) & 1;       // CERTVERIFY bit

    if (upscli_tryconnect(ups, host, port, flags, NULL) < 0)
        return -1;

    if (use_ssl) {
        // verify comes from flags bit 1
        return upscli_sslinit(ups, verify);
    }

    return 0;
}

// Application layer: upsmon daemon connection
// This is the actual entry point called by the application
__int64 __fastcall upsmon_connect(const char *hostname)
{
    __int64 ups;
    int port;
    int flags;

    ups = malloc(0x300);
    port = 3493;  // Default NUT port

    // IMPORTANT: flags = 0x12 = UPSCONN_SECURE | UPSCONN_CERTVERIFY
    // This means SSL is required AND certificate verification is enabled
    flags = 0x12;

    return upscli_connect(ups, hostname, port, flags);
}

// Another application: upsc command-line tool
// This one uses INSECURE flags
__int64 __fastcall upsc_connect(const char *hostname)
{
    __int64 ups;
    int port;
    int flags;

    ups = malloc(0x300);
    port = 3493;

    // INSECURE: flags = 0x10 = UPSCONN_SECURE only, no CERTVERIFY
    // SSL is used but certificate is NOT verified!
    flags = 0x10;

    return upscli_connect(ups, hostname, port, flags);
}
