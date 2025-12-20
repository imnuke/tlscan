"""OpenSSL library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for OpenSSL client detection
OPENSSL_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "SSL_connect",
            "BIO_new_ssl_connect",
            "BIO_do_connect",
        },
    ),
    IndicatorSet(
        name="client_methods",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "TLS_client_method",
            "DTLS_client_method",
            "SSLv23_client_method",
            "TLSv1_client_method",
            "TLSv1_1_client_method",
            "TLSv1_2_client_method",
        },
    ),
    IndicatorSet(
        name="generic_methods",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "TLS_method",
            "DTLS_method",
        },
    ),
    IndicatorSet(
        name="state",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "SSL_set_connect_state",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "SSL_set_tlsext_host_name",
            "SSL_set1_host",
            "X509_VERIFY_PARAM_set1_host",
            "SSL_CTX_set_verify",
            "SSL_set_verify",
            "SSL_set_fd",
            "SSL_set_bio",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
OPENSSL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong client connector(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("generic_methods", [])) > 0
            and (len(h.get("state", [])) > 0 or len(h.get("strong", [])) > 0)
        ),
        rationale_template="Generic method + client state/connect",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("client_methods", [])) > 0,
        rationale_template="Found client method(s): {client_methods}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 2,  # Uses openssl-specific threshold
        rationale_template="Multiple weak client-leaning indicators: {weak}",
    ),
]


OPENSSL = LibraryDefinition(
    id="openssl",
    name="OpenSSL",
    description="OpenSSL TLS/SSL client connections",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=OPENSSL_INDICATORS,
    scoring_rules=OPENSSL_SCORING_RULES,
)
