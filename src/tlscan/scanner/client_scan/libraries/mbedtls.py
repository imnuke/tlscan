"""mbedTLS library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for mbedTLS client detection
MBEDTLS_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "mbedtls_ssl_handshake",
            "mbedtls_ssl_write",
            "mbedtls_ssl_read",
            "mbedtls_ssl_send_alert_message",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "mbedtls_ssl_init",
            "mbedtls_ssl_setup",
            "mbedtls_ssl_config_init",
            "mbedtls_ssl_config_defaults",
        },
    ),
    IndicatorSet(
        name="client_config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "mbedtls_ssl_conf_authmode",
            "mbedtls_ssl_conf_ca_chain",
            "mbedtls_ssl_conf_own_cert",
            "mbedtls_ssl_conf_rng",
            "mbedtls_ssl_conf_min_version",
            "mbedtls_ssl_conf_max_version",
            "mbedtls_ssl_conf_ciphersuites",
            "mbedtls_ssl_set_hostname",
            "mbedtls_ssl_set_bio",
        },
    ),
    IndicatorSet(
        name="verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "mbedtls_x509_crt_verify",
            "mbedtls_x509_crt_verify_with_profile",
            "mbedtls_x509_crt_check_extended_key_usage",
            "mbedtls_ssl_get_verify_result",
            "mbedtls_x509_crt_parse",
            "mbedtls_x509_crt_parse_file",
        },
    ),
    IndicatorSet(
        name="crypto",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "mbedtls_ctr_drbg_init",
            "mbedtls_ctr_drbg_seed",
            "mbedtls_entropy_init",
            "mbedtls_entropy_func",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "mbedtls_ssl_free",
            "mbedtls_ssl_config_free",
            "mbedtls_ssl_close_notify",
            "mbedtls_ssl_session_reset",
            "mbedtls_strerror",
            "mbedtls_version_get_string",
            "mbedtls_x509_crt_init",
            "mbedtls_x509_crt_free",
            "mbedtls_ctr_drbg_free",
            "mbedtls_entropy_free",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
MBEDTLS_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong TLS handshake/transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0
            and len(h.get("client_config", [])) > 0
            and len(h.get("crypto", [])) > 0
        ),
        rationale_template="Complete client setup: init + config + crypto",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("verification", [])) > 0
        ),
        rationale_template="Client verification pattern: init + verify",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("crypto", [])) > 0,
        rationale_template="Basic mbed TLS setup: init + crypto initialization",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("init", [])) > 0,
        rationale_template="Only initialization found: {init}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,  # Default threshold
        rationale_template="Multiple weak mbed TLS indicators",
    ),
]


MBEDTLS = LibraryDefinition(
    id="mbedtls",
    name="mbed TLS",
    description="mbed TLS (formerly PolarSSL) client library",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=MBEDTLS_INDICATORS,
    scoring_rules=MBEDTLS_SCORING_RULES,
)
