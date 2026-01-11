"""s2n-tls library definition.

s2n-tls is AWS's implementation of TLS. It has a distinct API with the s2n_ prefix.
"""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
)

# Indicator sets for s2n-tls client detection
S2N_TLS_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "s2n_negotiate",
            "s2n_send",
            "s2n_recv",
            "s2n_sendv",
            "s2n_sendv_with_offset",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "s2n_init",
            "s2n_connection_new",
            "s2n_config_new",
        },
    ),
    IndicatorSet(
        name="config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "s2n_connection_set_config",
            "s2n_set_server_name",
            "s2n_config_set_verification_ca_location",
            "s2n_config_set_cipher_preferences",
            "s2n_connection_set_fd",
            "s2n_connection_set_read_fd",
            "s2n_connection_set_write_fd",
        },
    ),
    IndicatorSet(
        name="verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "s2n_config_set_cert_chain_and_key",
            "s2n_config_set_verify_host_callback",
            "s2n_connection_get_peer_certificate_chain",
            "s2n_config_disable_x509_verification",
        },
    ),
    IndicatorSet(
        name="client_mode",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "s2n_connection_set_client_auth_type",
            "s2n_config_set_client_hello_cb",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "s2n_connection_free",
            "s2n_config_free",
            "s2n_cleanup",
            "s2n_strerror",
            "s2n_errno_location",
            "s2n_connection_get_cipher",
            "s2n_connection_get_protocol_version",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
S2N_TLS_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found s2n TLS negotiation/transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("config", [])) > 0
        ),
        rationale_template="s2n client setup pattern: init + config",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("verification", [])) > 0
        ),
        rationale_template="s2n verification pattern: init + verify",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("weak", [])) > 0,
        rationale_template="Basic s2n usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,
        rationale_template="Multiple weak s2n indicators",
    ),
]


S2N_TLS = LibraryDefinition(
    id="s2n_tls",
    name="s2n-tls",
    description="s2n-tls (AWS TLS implementation)",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=S2N_TLS_INDICATORS,
    scoring_rules=S2N_TLS_SCORING_RULES,
)
