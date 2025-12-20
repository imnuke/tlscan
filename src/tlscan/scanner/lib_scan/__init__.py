"""Library scanning module for TLS infrastructure discovery.

This module finds TLS libraries and CLI tools in firmware,
detects their versions, and identifies SSL backends.

Usage:
    from tlscan.scanner.lib_scan import scan_libraries

    results = scan_libraries("/path/to/firmware")
    for lib_type, info in results.items():
        print(f"{lib_type}: {info['version']}")
"""

from .discovery import scan_libraries, find_library_files
from .versions import detect_library_version
from .backends import (
    detect_ssl_backend,
    BackendInfo,
    CURL_BACKEND_SYMBOLS,
    BACKEND_NAMES,
)

__all__ = [
    # Main scanning function
    "scan_libraries",
    "find_library_files",
    # Version detection
    "detect_library_version",
    # Backend detection
    "detect_ssl_backend",
    "BackendInfo",
    "CURL_BACKEND_SYMBOLS",
    "BACKEND_NAMES",
]
