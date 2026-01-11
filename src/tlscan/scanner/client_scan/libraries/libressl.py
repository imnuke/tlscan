"""LibreSSL library definition.

LibreSSL is OpenBSD's fork of OpenSSL. It shares most symbols with OpenSSL,
but also provides the libtls API which is LibreSSL-specific. Detection relies
on libtls symbols or LibreSSL version strings (best-effort detection).
"""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for LibreSSL client detection
LIBRESSL_INDICATORS = [
    # libtls API - LibreSSL's modern, simple TLS API
    IndicatorSet(
        name="libtls_strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "tls_connect",
            "tls_connect_socket",
            "tls_read",
            "tls_write",
            "tls_handshake",
        },
    ),
    IndicatorSet(
        name="libtls_init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "tls_init",
            "tls_client",
            "tls_config_new",
        },
    ),
    IndicatorSet(
        name="libtls_config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "tls_config_set_ca_file",
            "tls_config_set_ca_path",
            "tls_config_set_ca_mem",
            "tls_config_insecure_noverifycert",
            "tls_config_insecure_noverifyname",
            "tls_config_set_protocols",
            "tls_configure",
        },
    ),
    IndicatorSet(
        name="libtls_verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "tls_peer_cert_provided",
            "tls_peer_cert_subject",
            "tls_peer_cert_issuer",
            "tls_peer_cert_hash",
            "tls_conn_version",
            "tls_conn_cipher",
        },
    ),
    IndicatorSet(
        name="libressl_version",
        strength=IndicatorStrength.STRONG,
        indicators={
            "LibreSSL",  # Version string marker
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "tls_close",
            "tls_free",
            "tls_config_free",
            "tls_error",
            "tls_reset",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
LIBRESSL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("libtls_strong", [])) > 0,
        rationale_template="Found libtls TLS connection function(s): {libtls_strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("libtls_init", [])) > 0 and len(h.get("libtls_config", [])) > 0
        ),
        rationale_template="libtls client setup pattern: init + config",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("libressl_version", [])) > 0,
        rationale_template="Found LibreSSL version string",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: (
            len(h.get("libtls_init", [])) > 0 and len(h.get("weak", [])) > 0
        ),
        rationale_template="Basic libtls usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 2,
        rationale_template="Multiple weak libtls indicators",
    ),
]


LIBRESSL = LibraryDefinition(
    id="libressl",
    name="LibreSSL",
    description="LibreSSL TLS library (OpenBSD's OpenSSL fork with libtls)",
    detection_method="both",  # symbols + strings (for version detection)
    applicable_file_types=["elf_binary"],
    indicator_sets=LIBRESSL_INDICATORS,
    scoring_rules=LIBRESSL_SCORING_RULES,
)
