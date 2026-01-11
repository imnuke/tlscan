"""BearSSL library definition.

BearSSL is a small SSL/TLS library with minimal footprint, designed for
constrained environments. It uses the br_ prefix for all functions.
"""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
)

# Indicator sets for BearSSL client detection
BEARSSL_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            # Client-side SSL connection functions
            "br_ssl_client_reset",
            "br_sslio_write",
            "br_sslio_read",
            "br_sslio_write_all",
            "br_sslio_read_all",
            "br_sslio_flush",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "br_ssl_client_init_full",
            "br_ssl_client_zero",
            "br_sslio_init",
            "br_ssl_engine_set_buffer",
            "br_ssl_engine_set_buffers_bidi",
        },
    ),
    IndicatorSet(
        name="config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "br_ssl_engine_set_x509",
            "br_ssl_engine_set_suites",
            "br_ssl_client_set_single_rsa",
            "br_ssl_client_set_single_ec",
            "br_ssl_engine_set_protocol_names",
            "br_ssl_engine_set_versions",
        },
    ),
    IndicatorSet(
        name="x509_verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "br_x509_minimal_init",
            "br_x509_minimal_set_hash",
            "br_x509_minimal_set_rsa",
            "br_x509_minimal_set_ecdsa",
            "br_x509_decoder_init",
            "br_x509_decoder_push",
        },
    ),
    IndicatorSet(
        name="crypto",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            # Random number generation
            "br_hmac_drbg_init",
            "br_hmac_drbg_generate",
            # Common crypto primitives
            "br_sha256_init",
            "br_sha384_init",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "br_ssl_engine_close",
            "br_ssl_engine_current_state",
            "br_ssl_engine_last_error",
            "br_sslio_close",
            "br_ssl_engine_get_session_parameters",
            "br_ssl_engine_set_session_parameters",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
BEARSSL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found BearSSL I/O function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("config", [])) > 0
        ),
        rationale_template="BearSSL client setup pattern: init + config",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("x509_verification", [])) > 0
        ),
        rationale_template="BearSSL X.509 verification pattern: init + x509",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("crypto", [])) > 0
        ),
        rationale_template="BearSSL crypto usage: init + crypto primitives",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("weak", [])) > 0,
        rationale_template="Basic BearSSL usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 2,
        rationale_template="Multiple weak BearSSL indicators",
    ),
]


BEARSSL = LibraryDefinition(
    id="bearssl",
    name="BearSSL",
    description="BearSSL TLS library (minimal footprint)",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=BEARSSL_INDICATORS,
    scoring_rules=BEARSSL_SCORING_RULES,
)
