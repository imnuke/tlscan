"""Library indicator sets for network client detection.

Contains symbol and string patterns used to detect various SSL/TLS libraries
in binary files.
"""

from typing import Set, Dict, Callable, Tuple, Any

# ============================================================================
# Default ignore list
# ============================================================================

DEFAULT_IGNORE_FILES = [
    "busybox",        # Multi-call binary, too noisy
    "wget",           # The wget tool itself
    "curl",           # The curl tool itself
    "openvpn",        # OpenVPN binary
    "openssl",        # OpenSSL binary
    "libssl.so",      # OpenSSL library (exports SSL functions)
    "libcrypto.so",   # OpenSSL crypto library
    "libcurl.so",     # curl library (exports curl functions)
    "libgnutls.so",   # GnuTLS library
    "libmbedtls.so",  # mbed TLS library
    "libmbedcrypto",  # mbed crypto library
    "libc.so",        # Standard C library
    "ld-linux",       # Dynamic linker
]

# ============================================================================
# OpenSSL indicators
# ============================================================================

OPENSSL_STRONG: Set[str] = {
    "SSL_connect", "BIO_new_ssl_connect", "BIO_do_connect",
}
OPENSSL_CLIENT_METHODS: Set[str] = {
    "TLS_client_method", "DTLS_client_method", "SSLv23_client_method",
    "TLSv1_client_method", "TLSv1_1_client_method", "TLSv1_2_client_method",
}
OPENSSL_GENERIC_METHODS: Set[str] = {
    "TLS_method", "DTLS_method",
}
OPENSSL_STATE: Set[str] = {
    "SSL_set_connect_state",
}
OPENSSL_WEAK: Set[str] = {
    "SSL_set_tlsext_host_name", "SSL_set1_host", "X509_VERIFY_PARAM_set1_host",
    "SSL_CTX_set_verify", "SSL_set_verify", "SSL_set_fd", "SSL_set_bio",
}

# ============================================================================
# libcurl indicators
# ============================================================================

LIBCURL_STRONG: Set[str] = {
    "curl_easy_perform", "curl_multi_perform", "curl_easy_send", "curl_easy_recv",
}
LIBCURL_INIT: Set[str] = {
    "curl_easy_init", "curl_multi_init", "curl_global_init",
}
LIBCURL_SETOPT: Set[str] = {
    "curl_easy_setopt", "curl_multi_setopt", "curl_easy_setopt_array",
}
LIBCURL_INFO: Set[str] = {
    "curl_easy_getinfo", "curl_multi_info_read",
}
LIBCURL_WEAK: Set[str] = {
    "curl_easy_cleanup", "curl_multi_cleanup", "curl_global_cleanup",
    "curl_slist_append", "curl_slist_free_all", "curl_easy_strerror",
    "curl_multi_strerror", "curl_version", "curl_version_info",
    "curl_easy_escape", "curl_easy_unescape", "curl_free",
}

# ============================================================================
# GnuTLS indicators
# ============================================================================

GNUTLS_STRONG: Set[str] = {
    "gnutls_handshake", "gnutls_record_send", "gnutls_record_recv",
    "gnutls_record_send_early_data", "gnutls_record_recv_early_data",
}
GNUTLS_INIT: Set[str] = {
    "gnutls_init", "gnutls_global_init", "gnutls_global_init_extra",
}
GNUTLS_CLIENT_CONFIG: Set[str] = {
    "gnutls_credentials_set", "gnutls_certificate_allocate_credentials",
    "gnutls_certificate_set_x509_trust_file", "gnutls_certificate_set_x509_trust_dir",
    "gnutls_certificate_set_x509_system_trust", "gnutls_priority_set_direct",
    "gnutls_priority_init", "gnutls_server_name_set",
}
GNUTLS_VERIFICATION: Set[str] = {
    "gnutls_certificate_verify_peers2", "gnutls_certificate_verify_peers3",
    "gnutls_x509_crt_check_hostname", "gnutls_certificate_get_peers",
    "gnutls_ocsp_status_request_enable_client",
}
GNUTLS_WEAK: Set[str] = {
    "gnutls_deinit", "gnutls_global_deinit", "gnutls_bye", "gnutls_perror",
    "gnutls_strerror", "gnutls_check_version", "gnutls_transport_set_ptr",
    "gnutls_transport_set_int", "gnutls_session_set_data", "gnutls_session_get_data",
    "gnutls_cipher_get", "gnutls_protocol_get_version",
}

# ============================================================================
# mbed TLS indicators
# ============================================================================

MBEDTLS_STRONG: Set[str] = {
    "mbedtls_ssl_handshake", "mbedtls_ssl_write", "mbedtls_ssl_read",
    "mbedtls_ssl_send_alert_message",
}
MBEDTLS_INIT: Set[str] = {
    "mbedtls_ssl_init", "mbedtls_ssl_setup", "mbedtls_ssl_config_init",
    "mbedtls_ssl_config_defaults",
}
MBEDTLS_CLIENT_CONFIG: Set[str] = {
    "mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_ca_chain", "mbedtls_ssl_conf_own_cert",
    "mbedtls_ssl_conf_rng", "mbedtls_ssl_conf_min_version", "mbedtls_ssl_conf_max_version",
    "mbedtls_ssl_conf_ciphersuites", "mbedtls_ssl_set_hostname", "mbedtls_ssl_set_bio",
}
MBEDTLS_VERIFICATION: Set[str] = {
    "mbedtls_x509_crt_verify", "mbedtls_x509_crt_verify_with_profile",
    "mbedtls_x509_crt_check_extended_key_usage", "mbedtls_ssl_get_verify_result",
    "mbedtls_x509_crt_parse", "mbedtls_x509_crt_parse_file",
}
MBEDTLS_CRYPTO: Set[str] = {
    "mbedtls_ctr_drbg_init", "mbedtls_ctr_drbg_seed", "mbedtls_entropy_init",
    "mbedtls_entropy_func",
}
MBEDTLS_WEAK: Set[str] = {
    "mbedtls_ssl_free", "mbedtls_ssl_config_free", "mbedtls_ssl_close_notify",
    "mbedtls_ssl_session_reset", "mbedtls_strerror", "mbedtls_version_get_string",
    "mbedtls_x509_crt_init", "mbedtls_x509_crt_free", "mbedtls_ctr_drbg_free",
    "mbedtls_entropy_free",
}

# ============================================================================
# curl/wget CLI tool indicators (string-based)
# ============================================================================

CURL_WGET_TOOLS: Set[str] = {
    "curl", "wget", "/usr/bin/curl", "/usr/bin/wget", "/bin/curl", "/bin/wget",
}
CURL_WGET_URL_SCHEMES: Set[str] = {
    "http://", "https://", "ftp://", "ftps://",
}
CURL_WGET_CURL_INSECURE: Set[str] = {
    "-k", "--insecure", "--no-check-certificate", "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
}
CURL_WGET_WGET_INSECURE: Set[str] = {
    "--no-check-certificate", "--no-verify-peer", "--no-host-check",
}
CURL_WGET_CURL_OPTIONS: Set[str] = {
    "-X", "--request", "-d", "--data", "-H", "--header", "-o", "--output",
    "-O", "--remote-name", "-u", "--user",
}
CURL_WGET_WGET_OPTIONS: Set[str] = {
    "-O", "--output-document", "-P", "--directory-prefix", "-q", "--quiet",
    "-c", "--continue", "--user", "--password",
}

# ============================================================================
# PHP curl indicators (hybrid: symbols + strings)
# ============================================================================

PHP_CURL_FUNCTIONS: Set[str] = {
    "curl_init", "curl_exec", "curl_setopt", "curl_setopt_array", "curl_close",
    "curl_getinfo", "curl_error", "curl_errno", "curl_multi_init", "curl_multi_exec",
    "curl_multi_add_handle",
}
PHP_CURL_INTERNAL: Set[str] = {
    "php_curl_init", "php_curl_exec", "php_curl_setopt", "php_curl_close",
    "zif_curl_init", "zif_curl_exec", "zif_curl_setopt", "zif_curl_setopt_array",
    "zif_curl_close", "zif_curl_getinfo",
}
PHP_CURL_CURLOPT: Set[str] = {
    "CURLOPT_URL", "CURLOPT_RETURNTRANSFER", "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST", "CURLOPT_CAINFO", "CURLOPT_CAPATH",
    "CURLOPT_SSLVERSION", "CURLOPT_POST", "CURLOPT_POSTFIELDS",
    "CURLOPT_HTTPHEADER", "CURLOPT_FOLLOWLOCATION",
}
PHP_CURL_INSECURE: Set[str] = {
    "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST", "verify_peer", "verify_host",
}

# ASCII printable character range
PRINTABLE = set(range(0x20, 0x7F))

# ============================================================================
# Library applicability mapping
# ============================================================================

# Defines which file types each library can be detected in
LIBRARY_FILE_TYPES: Dict[str, list] = {
    "openssl": ["elf_binary"],
    "libcurl": ["elf_binary"],
    "gnutls": ["elf_binary"],
    "mbedtls": ["elf_binary"],
    "curl_wget": ["elf_binary", "php_script", "shell_script", "other_script"],
    "php_curl": ["php_script"],  # ONLY PHP scripts, never ELF binaries
}
