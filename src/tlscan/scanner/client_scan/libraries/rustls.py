"""rustls library definition.

rustls is a modern TLS library written in Rust. It provides a C API via
rustls-ffi with the rustls_ prefix for use in non-Rust applications.
"""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
)

# Indicator sets for rustls client detection (C FFI API)
RUSTLS_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            # Connection operations
            "rustls_client_connection_new",
            "rustls_connection_write",
            "rustls_connection_read",
            "rustls_connection_write_tls",
            "rustls_connection_read_tls",
            "rustls_connection_process_new_packets",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "rustls_client_config_builder_new",
            "rustls_client_config_builder_build",
            "rustls_client_config_builder_new_custom",
        },
    ),
    IndicatorSet(
        name="config",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "rustls_client_config_builder_set_alpn_protocols",
            "rustls_client_config_builder_set_enable_sni",
            "rustls_client_config_builder_set_certified_key",
            "rustls_connection_set_buffer_limit",
            "rustls_client_config_builder_dangerous_set_certificate_verifier",
        },
    ),
    IndicatorSet(
        name="root_store",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "rustls_root_cert_store_new",
            "rustls_root_cert_store_add_pem",
            "rustls_client_config_builder_use_roots",
            "rustls_web_pki_server_cert_verifier_builder_new",
        },
    ),
    IndicatorSet(
        name="verification",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "rustls_connection_get_peer_certificate",
            "rustls_connection_get_negotiated_ciphersuite",
            "rustls_connection_get_protocol_version",
            "rustls_connection_get_sni_hostname",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "rustls_client_connection_free",
            "rustls_client_config_free",
            "rustls_root_cert_store_free",
            "rustls_connection_is_handshaking",
            "rustls_connection_wants_read",
            "rustls_connection_wants_write",
            "rustls_error",
            "rustls_strerror",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
RUSTLS_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found rustls connection function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("config", [])) > 0
        ),
        rationale_template="rustls client setup pattern: init + config",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: (
            len(h.get("init", [])) > 0 and len(h.get("root_store", [])) > 0
        ),
        rationale_template="rustls trust store setup: init + root store",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("weak", [])) > 0,
        rationale_template="Basic rustls usage: init + utilities",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,
        rationale_template="Multiple weak rustls indicators",
    ),
]


RUSTLS = LibraryDefinition(
    id="rustls",
    name="rustls",
    description="rustls TLS library (Rust-based with C FFI)",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=RUSTLS_INDICATORS,
    scoring_rules=RUSTLS_SCORING_RULES,
)
