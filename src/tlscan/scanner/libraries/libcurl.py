"""libcurl library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for libcurl client detection
LIBCURL_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "curl_easy_perform",
            "curl_multi_perform",
            "curl_easy_send",
            "curl_easy_recv",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_init",
            "curl_multi_init",
            "curl_global_init",
        },
    ),
    IndicatorSet(
        name="setopt",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_setopt",
            "curl_multi_setopt",
            "curl_easy_setopt_array",
        },
    ),
    IndicatorSet(
        name="info",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_getinfo",
            "curl_multi_info_read",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "curl_easy_cleanup",
            "curl_multi_cleanup",
            "curl_global_cleanup",
            "curl_slist_append",
            "curl_slist_free_all",
            "curl_easy_strerror",
            "curl_multi_strerror",
            "curl_version",
            "curl_version_info",
            "curl_easy_escape",
            "curl_easy_unescape",
            "curl_free",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
LIBCURL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong client transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("setopt", [])) > 0,
        rationale_template="Client setup pattern: init + setopt",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("info", [])) > 0,
        rationale_template="Client info retrieval pattern: init + info",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("init", [])) > 0,
        rationale_template="Only initialization found: {init}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,  # Default threshold
        rationale_template="Multiple weak libcurl indicators",
    ),
]


# Backend-specific symbols for SSL backend detection
LIBCURL_BACKEND_SYMBOLS = {
    "openssl": {
        "Curl_ossl_init",
        "Curl_ossl_cleanup",
        "Curl_ossl_connect",
        "Curl_ossl_connect_nonblocking",
        "Curl_ossl_data_pending",
        "Curl_ossl_close",
        "Curl_ossl_shutdown",
        "Curl_ossl_session_free",
        "Curl_ossl_set_engine",
        "Curl_ossl_set_engine_default",
        "ossl_connect_common",
        "ossl_connect_step1",
        "ossl_connect_step2",
    },
    "gnutls": {
        "Curl_gtls_init",
        "Curl_gtls_cleanup",
        "Curl_gtls_connect",
        "Curl_gtls_connect_nonblocking",
        "Curl_gtls_data_pending",
        "Curl_gtls_close",
        "Curl_gtls_shutdown",
        "Curl_gtls_session_free",
        "gtls_connect_common",
        "gtls_connect_step1",
        "gtls_connect_step2",
    },
    "mbedtls": {
        "Curl_mbedtls_init",
        "Curl_mbedtls_cleanup",
        "Curl_mbedtls_connect",
        "Curl_mbedtls_connect_nonblocking",
        "Curl_mbedtls_data_pending",
        "Curl_mbedtls_close",
        "Curl_mbedtls_shutdown",
        "mbed_connect_common",
        "mbed_connect_step1",
        "mbed_connect_step2",
    },
    "nss": {
        "Curl_nss_init",
        "Curl_nss_cleanup",
        "Curl_nss_connect",
        "Curl_nss_connect_nonblocking",
        "Curl_nss_data_pending",
        "Curl_nss_close",
        "Curl_nss_shutdown",
        "Curl_nss_session_free",
        "nss_connect_common",
        "nss_connect_step1",
        "nss_connect_step2",
    },
    "wolfssl": {
        "Curl_wolfssl_init",
        "Curl_wolfssl_cleanup",
        "Curl_wolfssl_connect",
        "Curl_wolfssl_connect_nonblocking",
        "Curl_wolfssl_data_pending",
        "Curl_wolfssl_close",
        "Curl_wolfssl_shutdown",
        "wolfssl_connect_common",
        "wolfssl_connect_step1",
        "wolfssl_connect_step2",
    },
}


LIBCURL = LibraryDefinition(
    id="libcurl",
    name="libcurl",
    description="libcurl HTTP/HTTPS client library",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=LIBCURL_INDICATORS,
    scoring_rules=LIBCURL_SCORING_RULES,
    backend_symbols=LIBCURL_BACKEND_SYMBOLS,
)
