"""GnuTLS library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for GnuTLS client detection
GNUTLS_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "gnutls_handshake",
            "gnutls_record_send",
            "gnutls_record_recv",
            "gnutls_record_send_early_data",
            "gnutls_record_recv_early_data",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "gnutls_init",
            "gnutls_global_init",
            "gnutls_global_init_extra",
        },
    ),
    IndicatorSet(
        name="client_config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "gnutls_credentials_set",
            "gnutls_certificate_allocate_credentials",
            "gnutls_certificate_set_x509_trust_file",
            "gnutls_certificate_set_x509_trust_dir",
            "gnutls_certificate_set_x509_system_trust",
            "gnutls_priority_set_direct",
            "gnutls_priority_init",
            "gnutls_server_name_set",
        },
    ),
    IndicatorSet(
        name="verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "gnutls_certificate_verify_peers2",
            "gnutls_certificate_verify_peers3",
            "gnutls_x509_crt_check_hostname",
            "gnutls_certificate_get_peers",
            "gnutls_ocsp_status_request_enable_client",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "gnutls_deinit",
            "gnutls_global_deinit",
            "gnutls_bye",
            "gnutls_perror",
            "gnutls_strerror",
            "gnutls_check_version",
            "gnutls_transport_set_ptr",
            "gnutls_transport_set_int",
            "gnutls_session_set_data",
            "gnutls_session_get_data",
            "gnutls_cipher_get",
            "gnutls_protocol_get_version",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
GNUTLS_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong TLS handshake/transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("client_config", [])) > 0
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
        rationale_template="Basic GnuTLS usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,  # Default threshold
        rationale_template="Multiple weak GnuTLS indicators",
    ),
]


GNUTLS = LibraryDefinition(
    id="gnutls",
    name="GnuTLS",
    description="GnuTLS TLS client library",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=GNUTLS_INDICATORS,
    scoring_rules=GNUTLS_SCORING_RULES,
)
