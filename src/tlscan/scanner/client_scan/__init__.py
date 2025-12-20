"""TLS client detection module.

This module finds programs and scripts that use TLS as clients
by detecting their use of TLS libraries like OpenSSL, libcurl, etc.

Usage:
    from tlscan.scanner.client_scan import scan_file, scan_clients

    # Scan a single file
    result = scan_file("/path/to/binary")
    if result:
        for lib_id, detection in result.detections.items():
            print(f"{detection.library_name}: {detection.confidence}")

    # Scan a directory
    results = scan_clients("/path/to/firmware")
"""

from .detection import scan_file, scan_clients
from .scoring import score_library, score_all_libraries
from .libraries import (
    LIBRARY_REGISTRY,
    get_library,
    get_libraries_for_file_type,
    list_library_ids,
    get_library_info,
    LibraryDefinition,
)

__all__ = [
    # Main scanning functions
    "scan_file",
    "scan_clients",
    # Scoring
    "score_library",
    "score_all_libraries",
    # Library registry
    "LIBRARY_REGISTRY",
    "get_library",
    "get_libraries_for_file_type",
    "list_library_ids",
    "get_library_info",
    "LibraryDefinition",
]
