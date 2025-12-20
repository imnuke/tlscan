"""TLS/SSL scanner module.

This module provides two main capabilities:
1. **lib_scan**: Scan firmware for TLS libraries and tools, detect versions and backends
2. **client_scan**: Find programs that use TLS as clients

Usage:
    # Scan firmware for TLS infrastructure
    from tlscan.scanner import scan_libraries
    libs = scan_libraries("/path/to/firmware")
    for lib_type, info in libs.items():
        print(f"{lib_type}: {info['version']}")

    # Scan for TLS client programs
    from tlscan.scanner import scan_file, scan_clients
    result = scan_file("/path/to/binary")
    if result:
        for lib_id, detection in result.detections.items():
            print(f"{detection.library_name}: {detection.confidence}")
"""

# ============================================================================
# Task 1: Library Scanning (lib_scan)
# ============================================================================
from .lib_scan import (
    scan_libraries,
    find_library_files,
    detect_library_version,
    detect_ssl_backend,
    BackendInfo,
    CURL_BACKEND_SYMBOLS,
    BACKEND_NAMES,
)

# ============================================================================
# Task 2: Client Scanning (client_scan)
# ============================================================================
from .client_scan import (
    scan_file,
    scan_clients,
    score_library,
    score_all_libraries,
    LIBRARY_REGISTRY,
    get_library,
    get_libraries_for_file_type,
    list_library_ids,
    get_library_info,
    LibraryDefinition,
)

# ============================================================================
# Result Models
# ============================================================================
from .models import (
    ScanResult,
    DetectionResult,
    VersionInfo,
    BackendInfo as BackendInfoModel,
    ConfidenceLevel,
    FileType,
    DetectionMethod,
    FirmwareScanResult,
)

# ============================================================================
# Configuration
# ============================================================================
from .config import (
    ScannerConfig,
    ScoringThresholds,
    ExtractionConfig,
    DEFAULT_CONFIG,
    TOOL_VERSION,
    DEFAULT_IGNORE_FILES,
)

__all__ = [
    # Task 1: Library scanning
    "scan_libraries",
    "find_library_files",
    "detect_library_version",
    "detect_ssl_backend",
    "BackendInfo",
    "CURL_BACKEND_SYMBOLS",
    "BACKEND_NAMES",
    # Task 2: Client scanning
    "scan_file",
    "scan_clients",
    "score_library",
    "score_all_libraries",
    # Library registry
    "LIBRARY_REGISTRY",
    "get_library",
    "get_libraries_for_file_type",
    "list_library_ids",
    "get_library_info",
    "LibraryDefinition",
    # Results
    "ScanResult",
    "DetectionResult",
    "VersionInfo",
    "BackendInfoModel",
    "ConfidenceLevel",
    "FileType",
    "DetectionMethod",
    "FirmwareScanResult",
    # Configuration
    "ScannerConfig",
    "ScoringThresholds",
    "ExtractionConfig",
    "DEFAULT_CONFIG",
    "TOOL_VERSION",
    "DEFAULT_IGNORE_FILES",
]
