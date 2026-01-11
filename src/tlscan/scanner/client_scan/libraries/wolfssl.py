"""WolfSSL library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
)

# Indicator sets for WolfSSL client detection
WOLFSSL_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "wolfSSL_connect",
            "wolfSSL_write",
            "wolfSSL_read",
            "wolfSSL_send",
            "wolfSSL_recv",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "wolfSSL_Init",
            "wolfSSL_CTX_new",
            "wolfSSL_new",
        },
    ),
    IndicatorSet(
        name="client_methods",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "wolfTLSv1_2_client_method",
            "wolfTLSv1_3_client_method",
            "wolfSSLv23_client_method",
            "wolfDTLSv1_2_client_method",
            "wolfDTLSv1_3_client_method",
        },
    ),
    IndicatorSet(
        name="config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "wolfSSL_CTX_set_verify",
            "wolfSSL_set_fd",
            "wolfSSL_UseSNI",
            "wolfSSL_CTX_load_verify_locations",
            "wolfSSL_CTX_SetMinVersion",
            "wolfSSL_set_tlsext_host_name",
        },
    ),
    IndicatorSet(
        name="verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "wolfSSL_check_domain_name",
            "wolfSSL_get_verify_result",
            "wolfSSL_X509_verify_cert_error_string",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "wolfSSL_free",
            "wolfSSL_CTX_free",
            "wolfSSL_get_error",
            "wolfSSL_Cleanup",
            "wolfSSL_shutdown",
            "wolfSSL_pending",
            "wolfSSL_get_session",
            "wolfSSL_set_session",
            "wolfSSL_library_init",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
WOLFSSL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong TLS handshake/transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("client_methods", [])) > 0
        ),
        rationale_template="Client setup pattern: init + client methods",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("config", [])) > 0
        ),
        rationale_template="Client setup pattern: init + config",
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
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("weak", [])) > 0,
        rationale_template="Basic WolfSSL usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,
        rationale_template="Multiple weak WolfSSL indicators",
    ),
]


WOLFSSL = LibraryDefinition(
    id="wolfssl",
    name="WolfSSL",
    description="WolfSSL TLS client library (embedded/IoT focused)",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=WOLFSSL_INDICATORS,
    scoring_rules=WOLFSSL_SCORING_RULES,
)
