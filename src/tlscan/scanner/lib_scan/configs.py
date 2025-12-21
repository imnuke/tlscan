"""Backend SSL/TLS configuration extraction from firmware.

Extracts TLS configuration (MinProtocol, MaxProtocol, etc.) from backend
config files in firmware to determine the effective TLS version floor.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


# ============================================================================
# Data Model
# ============================================================================


@dataclass
class BackendConfig:
    """Extracted backend TLS configuration."""

    min_protocol: Optional[str]  # "TLSv1.2", "TLSv1.0", etc.
    max_protocol: Optional[str]  # Optional max protocol
    config_source: str  # Path where config was found (relative to firmware root)


# ============================================================================
# OpenSSL Configuration Extraction
# ============================================================================

# Glob patterns for OpenSSL config files (searches recursively)
OPENSSL_CONFIG_PATTERNS = [
    "**/etc/ssl/openssl.cnf",
    "**/etc/pki/tls/openssl.cnf",
    "**/usr/lib/ssl/openssl.cnf",
    "**/usr/local/ssl/openssl.cnf",
]

# Pattern to match MinProtocol/MaxProtocol settings
# Examples: MinProtocol = TLSv1.2, MinProtocol=TLSv1.2
OPENSSL_PROTOCOL_PATTERN = re.compile(
    r"^\s*(Min|Max)Protocol\s*=\s*(\S+)", re.IGNORECASE | re.MULTILINE
)


def extract_openssl_config(firmware_root: str) -> Optional[BackendConfig]:
    """Extract OpenSSL config from firmware.

    Searches for openssl.cnf recursively and parses MinProtocol/MaxProtocol
    settings from [system_default_sect] or [ssl_sect] sections.

    Args:
        firmware_root: Path to firmware root directory

    Returns:
        BackendConfig if found and parsed, None otherwise
    """
    root = Path(firmware_root)

    for pattern in OPENSSL_CONFIG_PATTERNS:
        for full_path in root.glob(pattern):
            if not full_path.is_file():
                continue

            try:
                # Get relative path for logging/storage
                try:
                    config_path = str(full_path.relative_to(root))
                except ValueError:
                    config_path = str(full_path)

                content = full_path.read_text(errors="ignore")

                min_protocol = None
                max_protocol = None

                for match in OPENSSL_PROTOCOL_PATTERN.finditer(content):
                    directive = match.group(1).lower()
                    value = match.group(2).strip()

                    if directive == "min":
                        min_protocol = _normalize_protocol_version(value)
                    elif directive == "max":
                        max_protocol = _normalize_protocol_version(value)

                if min_protocol or max_protocol:
                    logger.debug(
                        f"Found OpenSSL config at {config_path}: "
                        f"min={min_protocol}, max={max_protocol}"
                    )
                    return BackendConfig(
                        min_protocol=min_protocol,
                        max_protocol=max_protocol,
                        config_source=config_path,
                    )
                else:
                    logger.debug(f"OpenSSL config at {config_path} has no MinProtocol/MaxProtocol")

            except Exception as e:
                logger.debug(f"Error reading OpenSSL config {full_path}: {e}")

    return None


# ============================================================================
# GnuTLS Configuration Extraction
# ============================================================================

# Glob patterns for GnuTLS config files (searches recursively)
GNUTLS_CONFIG_PATTERNS = [
    "**/etc/crypto-policies/back-ends/gnutls.config",
    "**/etc/gnutls/config",
    "**/etc/gnutls/default-priorities",
]

# Priority string patterns that indicate minimum TLS versions
# NORMAL, SECURE128, SECURE192, etc. have different defaults
# %LATEST_RECORD_VERSION, +VERS-TLS1.2, -VERS-TLS1.0, etc.
GNUTLS_PRIORITY_PATTERNS = {
    # Patterns that indicate TLS 1.2 minimum
    r"-VERS-TLS1\.0": "TLSv1.1",  # Disabling 1.0 means min 1.1
    r"-VERS-TLS1\.1": "TLSv1.2",  # Disabling 1.1 means min 1.2
    r"-VERS-ALL:\+VERS-TLS1\.2": "TLSv1.2",  # Explicit TLS 1.2 only
    r"-VERS-ALL:\+VERS-TLS1\.3": "TLSv1.3",  # Explicit TLS 1.3 only
}

# GnuTLS preset priority levels and their effective minimums
GNUTLS_PRESET_MINIMUMS = {
    "SECURE256": "TLSv1.2",
    "SECURE192": "TLSv1.2",
    "SECURE128": "TLSv1.2",
    "NORMAL": "TLSv1.0",  # NORMAL allows TLS 1.0 by default
    "LEGACY": "SSLv3",  # LEGACY allows very old protocols
    "PFS": "TLSv1.2",  # Perfect Forward Secrecy preset
}


def extract_gnutls_config(firmware_root: str) -> Optional[BackendConfig]:
    """Extract GnuTLS config from firmware.

    Searches for GnuTLS config files recursively and parses priority strings
    to determine minimum TLS version.

    Args:
        firmware_root: Path to firmware root directory

    Returns:
        BackendConfig if found and parsed, None otherwise
    """
    root = Path(firmware_root)

    for pattern in GNUTLS_CONFIG_PATTERNS:
        for full_path in root.glob(pattern):
            if not full_path.is_file():
                continue

            try:
                # Get relative path for logging/storage
                try:
                    config_path = str(full_path.relative_to(root))
                except ValueError:
                    config_path = str(full_path)

                content = full_path.read_text(errors="ignore")
                min_protocol = _parse_gnutls_priority(content)

                if min_protocol:
                    logger.debug(
                        f"Found GnuTLS config at {config_path}: min={min_protocol}"
                    )
                    return BackendConfig(
                        min_protocol=min_protocol,
                        max_protocol=None,
                        config_source=config_path,
                    )

            except Exception as e:
                logger.debug(f"Error reading GnuTLS config {full_path}: {e}")

    return None


def _parse_gnutls_priority(content: str) -> Optional[str]:
    """Parse GnuTLS priority string to determine minimum TLS version.

    Args:
        content: GnuTLS config file content

    Returns:
        Minimum TLS version string or None
    """
    # Check for explicit version disabling patterns
    for pattern, min_version in GNUTLS_PRIORITY_PATTERNS.items():
        if re.search(pattern, content, re.IGNORECASE):
            return min_version

    # Check for preset priority levels
    for preset, min_version in GNUTLS_PRESET_MINIMUMS.items():
        if re.search(rf"\b{preset}\b", content, re.IGNORECASE):
            return min_version

    return None


# ============================================================================
# Utilities
# ============================================================================


def _normalize_protocol_version(version: str) -> str:
    """Normalize protocol version string to consistent format.

    Args:
        version: Protocol version string (e.g., "TLSv1.2", "TLS1.2", "1.2")

    Returns:
        Normalized version string (e.g., "TLSv1.2")
    """
    version = version.strip().upper()

    # Already in correct format
    if version.startswith("TLSV"):
        return version.replace("TLSV", "TLSv")

    # Handle "TLS1.2" format
    if version.startswith("TLS"):
        return "TLSv" + version[3:]

    # Handle bare version numbers like "1.2"
    if re.match(r"^\d+\.\d+$", version):
        return f"TLSv{version}"

    # Handle SSLv3
    if version in ("SSLV3", "SSL3"):
        return "SSLv3"

    return version


def extract_backend_config(
    firmware_root: str, backend_name: str
) -> Optional[BackendConfig]:
    """Extract configuration for a specific backend.

    Args:
        firmware_root: Path to firmware root directory
        backend_name: Backend name ("OpenSSL", "GnuTLS", etc.)

    Returns:
        BackendConfig if found, None otherwise
    """
    backend_lower = backend_name.lower()

    if backend_lower in ("openssl", "libressl"):
        return extract_openssl_config(firmware_root)
    elif backend_lower == "gnutls":
        return extract_gnutls_config(firmware_root)
    # mbedTLS uses compile-time config, not runtime files
    # wolfSSL uses compile-time config
    # NSS uses system crypto policy on modern systems

    return None


def get_all_backend_configs(firmware_root: str) -> dict:
    """Extract all backend configs from firmware.

    Args:
        firmware_root: Path to firmware root directory

    Returns:
        Dict mapping backend names to their configs
    """
    configs = {}

    openssl_config = extract_openssl_config(firmware_root)
    if openssl_config:
        configs["openssl"] = openssl_config

    gnutls_config = extract_gnutls_config(firmware_root)
    if gnutls_config:
        configs["gnutls"] = gnutls_config

    return configs
