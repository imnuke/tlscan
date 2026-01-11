"""BoringSSL library definition.

BoringSSL is Google's fork of OpenSSL. It shares most symbols with OpenSSL,
so detection relies on BoringSSL-specific symbols. If only standard OpenSSL
symbols are found, we report as OpenSSL (best-effort detection).
"""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
)

# Indicator sets for BoringSSL client detection
# These are symbols unique to BoringSSL (not in OpenSSL)
BORINGSSL_INDICATORS = [
    IndicatorSet(
        name="boringssl_specific",
        strength=IndicatorStrength.STRONG,
        indicators={
            # BoringSSL-specific APIs
            "CRYPTO_library_init",
            "SSL_SESSION_to_bytes",
            "SSL_SESSION_from_bytes",
            "SSL_set_ocsp_response",
            "SSL_get_signature_algorithm_name",
            "SSL_get_curve_name",
            # CRYPTO_BUFFER API (BoringSSL-specific)
            "CRYPTO_BUFFER_new",
            "CRYPTO_BUFFER_free",
            "CRYPTO_BUFFER_data",
            "CRYPTO_BUFFER_len",
            # Trust store API
            "SSL_CTX_set0_verify_cert_store",
            "SSL_CTX_set1_verify_cert_store",
        },
    ),
    IndicatorSet(
        name="boringssl_pool",
        strength=IndicatorStrength.STRONG,
        indicators={
            # CRYPTO_POOL API (BoringSSL-specific)
            "CRYPTO_POOL_new",
            "CRYPTO_POOL_free",
            "CRYPTO_POOL_alloc",
        },
    ),
    IndicatorSet(
        name="openssl_compat",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            # Standard OpenSSL-compatible functions
            "SSL_connect",
            "SSL_write",
            "SSL_read",
            "SSL_CTX_new",
            "SSL_new",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "SSL_free",
            "SSL_CTX_free",
            "SSL_get_error",
            "SSL_shutdown",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
BORINGSSL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("boringssl_specific", [])) > 0,
        rationale_template="Found BoringSSL-specific API(s): {boringssl_specific}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("boringssl_pool", [])) > 0,
        rationale_template="Found BoringSSL CRYPTO_POOL API: {boringssl_pool}",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: (
            len(h.get("boringssl_specific", [])) == 0
            and len(h.get("boringssl_pool", [])) == 0
            and len(h.get("openssl_compat", [])) > 0
        ),
        rationale_template=(
            "Found OpenSSL-compatible symbols but no BoringSSL-specific APIs; "
            "may be OpenSSL, BoringSSL, or LibreSSL"
        ),
    ),
]


BORINGSSL = LibraryDefinition(
    id="boringssl",
    name="BoringSSL",
    description="BoringSSL (Google's OpenSSL fork)",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=BORINGSSL_INDICATORS,
    scoring_rules=BORINGSSL_SCORING_RULES,
)
