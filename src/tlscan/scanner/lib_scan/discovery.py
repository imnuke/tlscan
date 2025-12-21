"""Library file discovery in firmware.

Provides functions to find TLS library files and CLI tools in firmware
directories, and scan them for versions and backends.
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any

from .versions import (
    detect_library_version,
    extract_verdef_versions,
    parse_verneed_version,
    confidence_rank,
)
from .backends import detect_ssl_backend
from .configs import extract_backend_config

logger = logging.getLogger(__name__)


# ============================================================================
# Library File Patterns
# ============================================================================

LIBRARY_FILE_PATTERNS: List[Tuple[str, str]] = [
    # TLS libraries
    ("**/libssl.so*", "openssl"),
    ("**/libcrypto.so*", "openssl"),
    ("**/libcurl.so*", "libcurl"),
    ("**/libgnutls.so*", "gnutls"),
    ("**/libmbedtls.so*", "mbedtls"),
    ("**/libmbedcrypto.so*", "mbedtls"),
    # CLI tools
    ("**/bin/curl", "curl_cli"),
    ("**/bin/wget", "wget_cli"),
    ("**/sbin/curl", "curl_cli"),
    ("**/sbin/wget", "wget_cli"),
]


# ============================================================================
# Discovery Functions
# ============================================================================


def find_library_files(root: str) -> Dict[str, List[Path]]:
    """Find library files in a firmware directory.

    Args:
        root: Firmware root directory path

    Returns:
        Dict mapping library types to lists of found file paths
    """
    result: Dict[str, List[Path]] = {}
    root_path = Path(root)

    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        matches = []
        for lib_path in root_path.glob(pattern):
            if lib_path.is_symlink():
                continue
            if not lib_path.is_file():
                continue
            matches.append(lib_path)

        if matches:
            if lib_type not in result:
                result[lib_type] = []
            result[lib_type].extend(matches)

    return result


def scan_libraries(root: str) -> Dict[str, Dict[str, Any]]:
    """Scan firmware for TLS libraries and tools, detecting versions and backends.

    This is the main entry point for library scanning. It:
    1. Finds library files and CLI tools in the firmware
    2. Detects their versions using multiple methods
    3. Detects SSL backends for curl/libcurl

    Args:
        root: Firmware root directory path

    Returns:
        Dict mapping library types to version/backend info dicts
    """
    result: Dict[str, Dict[str, Any]] = {}
    root_path = Path(root)

    # First pass: Find library files and detect versions
    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        for lib_path in root_path.glob(pattern):
            if lib_path.is_symlink():
                continue
            if not lib_path.is_file():
                continue

            version_info = detect_library_version(str(lib_path), lib_type)
            if version_info:
                try:
                    version_info["source_path"] = str(lib_path.relative_to(root_path))
                except ValueError:
                    version_info["source_path"] = str(lib_path)

                if lib_type not in result:
                    result[lib_type] = version_info
                elif confidence_rank(version_info.get("confidence", "none")) > confidence_rank(
                    result[lib_type].get("confidence", "none")
                ):
                    result[lib_type] = version_info

    # Second pass: Check VERDEF for libraries not yet found
    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        if lib_type in result:
            continue

        for lib_path in root_path.glob(pattern):
            if lib_path.is_symlink() or not lib_path.is_file():
                continue

            verdef_versions = extract_verdef_versions(str(lib_path))
            if verdef_versions:
                highest = parse_verneed_version(verdef_versions, lib_type)
                if highest:
                    try:
                        source_path = str(lib_path.relative_to(root_path))
                    except ValueError:
                        source_path = str(lib_path)

                    result[lib_type] = {
                        "version": highest,
                        "confidence": "medium",
                        "method": "verdef",
                        "source_path": source_path,
                        "exported_versions": verdef_versions[:10],
                        "details": f"Exported versions: {', '.join(verdef_versions[:5])}",
                    }
                    break

    # Detect SSL backend for curl-related binaries
    for lib_type in ["libcurl", "curl_cli", "wget_cli"]:
        if lib_type in result:
            source_path = result[lib_type].get("source_path", "")
            if source_path:
                lib_path = root_path / source_path
                if lib_path.exists():
                    backend = detect_ssl_backend(str(lib_path))
                    if backend:
                        backend_data: Dict[str, Any] = {
                            "name": backend.name,
                            "version": backend.version,
                            "confidence": backend.confidence,
                            "detection_method": backend.detection_method,
                        }
                        # Extract backend config from firmware
                        backend_config = extract_backend_config(root, backend.name)
                        if backend_config:
                            backend_data["config"] = {
                                "min_protocol": backend_config.min_protocol,
                                "max_protocol": backend_config.max_protocol,
                                "config_source": backend_config.config_source,
                            }
                        result[lib_type]["backend"] = backend_data

    # Cross-reference backend versions with detected library versions
    backend_to_lib = {
        "OpenSSL": "openssl",
        "GnuTLS": "gnutls",
        "mbedTLS": "mbedtls",
        "wolfSSL": "wolfssl",
        "NSS": "nss",
    }

    for lib_type in ["libcurl", "curl_cli", "wget_cli"]:
        if lib_type in result and "backend" in result[lib_type]:
            backend = result[lib_type]["backend"]
            if not backend.get("version"):
                backend_name = backend.get("name", "")
                lib_key = backend_to_lib.get(backend_name)
                if lib_key and lib_key in result:
                    backend["version"] = result[lib_key].get("version")

    # Inherit backend for curl_cli from libcurl if not detected
    if "curl_cli" in result and "backend" not in result["curl_cli"]:
        if "libcurl" in result and "backend" in result["libcurl"]:
            result["curl_cli"]["backend"] = result["libcurl"]["backend"].copy()

    logger.info(f"Scanned {root}: found {len(result)} library types")
    return result
