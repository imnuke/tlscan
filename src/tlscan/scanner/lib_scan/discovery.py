"""Library file discovery in firmware.

Provides functions to find TLS library files and CLI tools in firmware
directories, and scan them for versions.
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
    ("**/libwolfssl.so*", "wolfssl"),
    # Note: BoringSSL uses libssl.so/libcrypto.so (same as OpenSSL)
    ("**/libtls.so*", "libressl"),  # libtls is LibreSSL's modern API
    ("**/libs2n.so*", "s2n_tls"),
    ("**/libbearssl.so*", "bearssl"),
    ("**/librustls.so*", "rustls"),
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
    """Scan firmware for TLS libraries and tools, detecting versions.

    This is the main entry point for library scanning. It:
    1. Finds library files and CLI tools in the firmware
    2. Detects their versions using multiple methods

    Args:
        root: Firmware root directory path

    Returns:
        Dict mapping library types to version info dicts
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

    logger.info(f"Scanned {root}: found {len(result)} library types")
    return result
