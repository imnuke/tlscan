"""SSL backend detection for curl/libcurl binaries.

Single source of truth for all backend detection symbols and logic.
Detects which SSL/TLS backend (OpenSSL, GnuTLS, mbedTLS, etc.) a curl
or libcurl binary was compiled with.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional, List, Set, Dict

from .elf import extract_needed_libs

logger = logging.getLogger(__name__)


# ============================================================================
# Backend Configuration (Single Source of Truth)
# ============================================================================

# Display names for backends
BACKEND_NAMES: Dict[str, str] = {
    "openssl": "OpenSSL",
    "gnutls": "GnuTLS",
    "mbedtls": "mbedTLS",
    "nss": "NSS",
    "wolfssl": "wolfSSL",
    "schannel": "Schannel",
    "securetransport": "SecureTransport",
}

# Library patterns that indicate each SSL backend (matched against DT_NEEDED)
BACKEND_LIBRARY_PATTERNS: Dict[str, List[str]] = {
    "openssl": ["libssl.so", "libcrypto.so"],
    "gnutls": ["libgnutls.so"],
    "mbedtls": ["libmbedtls.so", "libmbedcrypto.so", "libmbedx509.so"],
    "nss": ["libssl3.so", "libnss3.so", "libnssutil3.so"],
    "wolfssl": ["libwolfssl.so"],
}

# Backend-specific curl internal symbols (SINGLE SOURCE OF TRUTH)
# These symbols are only present when curl is compiled with that specific backend
# Previously duplicated in indicators.py and backend.py - now consolidated here
CURL_BACKEND_SYMBOLS: Dict[str, Set[str]] = {
    "openssl": {
        "Curl_ossl_init",
        "Curl_ossl_cleanup",
        "Curl_ossl_connect",
        "Curl_ossl_connect_nonblocking",
        "Curl_ossl_data_pending",
        "Curl_ossl_close",
        "Curl_ossl_shutdown",
        "Curl_ossl_session_free",
        "Curl_ossl_set_engine",
        "Curl_ossl_set_engine_default",
        "ossl_connect_common",
        "ossl_connect_step1",
        "ossl_connect_step2",
    },
    "gnutls": {
        "Curl_gtls_init",
        "Curl_gtls_cleanup",
        "Curl_gtls_connect",
        "Curl_gtls_connect_nonblocking",
        "Curl_gtls_data_pending",
        "Curl_gtls_close",
        "Curl_gtls_shutdown",
        "Curl_gtls_session_free",
        "gtls_connect_common",
        "gtls_connect_step1",
        "gtls_connect_step2",
    },
    "mbedtls": {
        "Curl_mbedtls_init",
        "Curl_mbedtls_cleanup",
        "Curl_mbedtls_connect",
        "Curl_mbedtls_connect_nonblocking",
        "Curl_mbedtls_data_pending",
        "Curl_mbedtls_close",
        "Curl_mbedtls_shutdown",
        "mbed_connect_common",
        "mbed_connect_step1",
        "mbed_connect_step2",
    },
    "nss": {
        "Curl_nss_init",
        "Curl_nss_cleanup",
        "Curl_nss_connect",
        "Curl_nss_connect_nonblocking",
        "Curl_nss_data_pending",
        "Curl_nss_close",
        "Curl_nss_shutdown",
        "Curl_nss_session_free",
        "nss_connect_common",
        "nss_connect_step1",
        "nss_connect_step2",
    },
    "wolfssl": {
        "Curl_wolfssl_init",
        "Curl_wolfssl_cleanup",
        "Curl_wolfssl_connect",
        "Curl_wolfssl_connect_nonblocking",
        "Curl_wolfssl_data_pending",
        "Curl_wolfssl_close",
        "Curl_wolfssl_shutdown",
        "wolfssl_connect_common",
        "wolfssl_connect_step1",
        "wolfssl_connect_step2",
    },
}

# Pattern to extract backend from libcurl version string
# Matches: "libcurl/7.73.0 OpenSSL/1.1.1w" or "libcurl/7.73.0-DEV GnuTLS/3.6.15"
CURL_VERSION_BACKEND_PATTERN = re.compile(
    rb"libcurl/[\d.]+(?:-\w+)?\s+(\w+)/(\d+\.\d+\.\d+[a-z]?)"
)

# Standalone backend version patterns
BACKEND_VERSION_PATTERNS: Dict[str, re.Pattern] = {
    "openssl": re.compile(rb"OpenSSL[/ ](\d+\.\d+\.\d+[a-z]?)"),
    "gnutls": re.compile(rb"GnuTLS[/ ](\d+\.\d+\.\d+)"),
    "mbedtls": re.compile(
        rb"(?:mbed\s*TLS|mbedTLS)[/ ](\d+\.\d+\.\d+)", re.IGNORECASE
    ),
    "nss": re.compile(rb"NSS[/ ](\d+\.\d+(?:\.\d+)?)"),
    "wolfssl": re.compile(rb"wolfSSL[/ ](\d+\.\d+\.\d+)"),
}


# ============================================================================
# Data Model
# ============================================================================


@dataclass
class BackendInfo:
    """Information about a detected SSL backend."""

    name: str  # Display name: "OpenSSL", "GnuTLS", etc.
    version: Optional[str]  # Backend version if detectable
    confidence: str  # "high", "medium", "low"
    detection_method: str  # "dynamic_linking", "symbols", "version_string"


# ============================================================================
# Detection Functions
# ============================================================================


def detect_backend_from_needed(needed_libs: List[str]) -> Optional[str]:
    """Detect SSL backend from ELF NEEDED entries.

    Args:
        needed_libs: List of library names from DT_NEEDED

    Returns:
        Backend key (e.g., "openssl") if found, None otherwise
    """
    for backend, patterns in BACKEND_LIBRARY_PATTERNS.items():
        for pattern in patterns:
            for lib in needed_libs:
                # Match library name prefix (handles versioned sonames)
                if lib.startswith(pattern.rstrip(".so")) or lib == pattern:
                    return backend
    return None


def detect_backend_from_symbols(symbols: Set[str]) -> Optional[str]:
    """Detect SSL backend from curl internal symbols.

    Args:
        symbols: Set of symbol names from the binary

    Returns:
        Backend key if backend-specific symbols are found, None otherwise
    """
    for backend, backend_symbols in CURL_BACKEND_SYMBOLS.items():
        matches = symbols & backend_symbols
        if matches:
            logger.debug(f"Found {len(matches)} {backend} backend symbols")
            return backend
    return None


def extract_backend_from_version_string(path: str) -> Optional[tuple]:
    """Extract backend name and version from binary's version strings.

    Args:
        path: Path to the binary file

    Returns:
        (backend_key, version) tuple if found, None otherwise
    """
    try:
        with open(path, "rb") as f:
            data = f.read()

        # First try the combined libcurl + backend pattern
        match = CURL_VERSION_BACKEND_PATTERN.search(data)
        if match:
            backend_name = match.group(1).decode("ascii", errors="ignore").lower()
            version = match.group(2).decode("ascii", errors="ignore")

            # Normalize backend name
            backend_key = None
            for key, display_name in BACKEND_NAMES.items():
                if (
                    backend_name.lower() == display_name.lower()
                    or backend_name.lower() == key
                ):
                    backend_key = key
                    break

            if backend_key:
                return (backend_key, version)

        # Fall back to individual backend version patterns
        for backend_key, pattern in BACKEND_VERSION_PATTERNS.items():
            match = pattern.search(data)
            if match:
                version = match.group(1).decode("ascii", errors="ignore")
                return (backend_key, version)

    except Exception as e:
        logger.debug(f"Error extracting backend from version string: {e}")
    return None


def detect_ssl_backend(
    path: str,
    symbols: Optional[Set[str]] = None,
    needed_libs: Optional[List[str]] = None,
) -> Optional[BackendInfo]:
    """Detect SSL backend for a curl/libcurl binary.

    Uses multiple detection methods with confidence ranking:
    1. Version string (high confidence) - explicit backend info in binary
    2. Dynamic linking (high confidence) - NEEDED entries show linked libraries
    3. Internal symbols (medium confidence) - curl backend-specific function names

    Args:
        path: Path to the binary file
        symbols: Pre-extracted symbols (optional, for efficiency)
        needed_libs: Pre-extracted NEEDED libraries (optional)

    Returns:
        BackendInfo if backend is detected, None otherwise
    """
    # Method 1: Version string (highest confidence, includes version)
    version_result = extract_backend_from_version_string(path)
    if version_result:
        backend_key, version = version_result
        logger.debug(f"Detected {backend_key} backend via version string: {version}")
        return BackendInfo(
            name=BACKEND_NAMES.get(backend_key, backend_key),
            version=version,
            confidence="high",
            detection_method="version_string",
        )

    # Method 2: Dynamic linking (high confidence, primary backend)
    if needed_libs is None:
        needed_libs = extract_needed_libs(path)

    backend_key = detect_backend_from_needed(needed_libs)
    if backend_key:
        logger.debug(f"Detected {backend_key} backend via dynamic linking")
        return BackendInfo(
            name=BACKEND_NAMES.get(backend_key, backend_key),
            version=None,
            confidence="high",
            detection_method="dynamic_linking",
        )

    # Method 3: Internal symbols (medium confidence, for static builds)
    if symbols:
        backend_key = detect_backend_from_symbols(symbols)
        if backend_key:
            logger.debug(f"Detected {backend_key} backend via internal symbols")
            return BackendInfo(
                name=BACKEND_NAMES.get(backend_key, backend_key),
                version=None,
                confidence="medium",
                detection_method="symbols",
            )

    return None


# ============================================================================
# Backend Behavior Defaults
# ============================================================================


def get_backend_default_behavior(backend: str, rule: str) -> Optional[dict]:
    """Get backend-specific default behavior for a rule.

    Provides known defaults for different SSL backends when
    curl/libcurl doesn't explicitly configure something.

    Args:
        backend: Backend key (e.g., "openssl", "gnutls")
        rule: Rule identifier (e.g., "cipher_suite", "revocation")

    Returns:
        Dict with 'default' and 'notes' fields, or None if unknown
    """
    defaults = {
        "openssl": {
            "cipher_suite": {
                "default": "DEFAULT:!aNULL:!eNULL",
                "notes": "OpenSSL 1.1.1+ defaults to TLS 1.2+ with forward secrecy",
            },
            "revocation": {
                "default": "disabled",
                "notes": "OpenSSL does not enable OCSP or CRL checking by default",
            },
            "min_tls_version": {
                "default": "1.2",
                "notes": "OpenSSL 1.1.1+ defaults to TLS 1.2 minimum",
            },
        },
        "gnutls": {
            "cipher_suite": {
                "default": "NORMAL",
                "notes": "GnuTLS NORMAL priority excludes known weak algorithms",
            },
            "revocation": {
                "default": "disabled",
                "notes": "GnuTLS requires explicit OCSP stapling enablement",
            },
            "min_tls_version": {
                "default": "1.2",
                "notes": "GnuTLS 3.6+ defaults to TLS 1.2 minimum",
            },
        },
        "mbedtls": {
            "cipher_suite": {
                "default": "secure defaults",
                "notes": "mbedTLS defaults exclude deprecated algorithms",
            },
            "revocation": {
                "default": "disabled",
                "notes": "mbedTLS requires explicit CRL/OCSP configuration",
            },
            "min_tls_version": {
                "default": "1.2",
                "notes": "mbedTLS 2.x+ defaults to TLS 1.2",
            },
        },
        "nss": {
            "cipher_suite": {
                "default": "secure defaults",
                "notes": "NSS has secure default cipher configuration",
            },
            "revocation": {
                "default": "ocsp_enabled",
                "notes": "NSS can be configured to enable OCSP by default",
            },
            "min_tls_version": {
                "default": "1.2",
                "notes": "Modern NSS defaults to TLS 1.2+",
            },
        },
        "wolfssl": {
            "cipher_suite": {
                "default": "secure defaults",
                "notes": "wolfSSL has secure default cipher configuration",
            },
            "revocation": {
                "default": "disabled",
                "notes": "wolfSSL requires explicit OCSP/CRL configuration",
            },
            "min_tls_version": {
                "default": "1.2",
                "notes": "wolfSSL defaults to TLS 1.2+ in recent versions",
            },
        },
    }

    backend_defaults = defaults.get(backend.lower(), {})
    return backend_defaults.get(rule)
