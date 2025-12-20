"""Network client scanner module.

Detects SSL/TLS library usage in ELF binaries and scripts.
Supports: OpenSSL, libcurl, GnuTLS, mbedTLS, curl/wget CLI tools, PHP curl.

Usage:
    from tlscan.scanner import scan_file, scan_directory

    # Scan a single file
    result = scan_file("/path/to/binary")
    if result:
        for lib_id, detection in result.detections.items():
            print(f"{detection.library_name}: {detection.confidence}")

    # Scan a directory
    results, firmware_versions = scan_directory("/path/to/firmware")
"""

# Main scanning functions
from .scanner import scan_file, scan_directory, walk_and_scan

# Result models
from .models import (
    ScanResult,
    DetectionResult,
    VersionInfo,
    BackendInfo,
    ConfidenceLevel,
    FileType,
    DetectionMethod,
    FirmwareScanResult,
)

# Configuration
from .config import (
    ScannerConfig,
    ScoringThresholds,
    ExtractionConfig,
    DEFAULT_CONFIG,
    TOOL_VERSION,
    DEFAULT_IGNORE_FILES,
)

# Library information
from .libraries import (
    list_library_ids,
    get_library_info,
    get_library,
    get_libraries_for_file_type,
    LIBRARY_REGISTRY,
)

# Version and backend detection (for direct use)
from .extractors.version import detect_library_version, scan_firmware_libraries
from .extractors.backend import detect_ssl_backend

# Backwards compatibility: expose old names
LIBRARIES = {
    lib_id: {
        "name": lib.name,
        "description": lib.description,
        "detection_method": lib.detection_method,
    }
    for lib_id, lib in LIBRARY_REGISTRY.items()
}

# File type mapping for backwards compatibility
LIBRARY_FILE_TYPES = {
    lib_id: lib.applicable_file_types
    for lib_id, lib in LIBRARY_REGISTRY.items()
}

__all__ = [
    # Main scanning
    "scan_file",
    "scan_directory",
    "walk_and_scan",  # Legacy alias
    # Results
    "ScanResult",
    "DetectionResult",
    "VersionInfo",
    "BackendInfo",
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
    # Library info
    "list_library_ids",
    "get_library_info",
    "get_library",
    "get_libraries_for_file_type",
    "LIBRARY_REGISTRY",
    # Direct detection
    "detect_library_version",
    "scan_firmware_libraries",
    "detect_ssl_backend",
    # Backwards compatibility
    "LIBRARIES",
    "LIBRARY_FILE_TYPES",
]
