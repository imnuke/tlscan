"""Network client scanner for SSL/TLS library detection.

Detects various TLS/HTTP client library usage in ELF binaries and scripts.
Supports: OpenSSL, libcurl, GnuTLS, mbed TLS, curl/wget CLI tools, and PHP curl.
"""

from .detector import (
    LIBRARIES,
    scan_file,
    walk_and_scan,
)
from .version import (
    detect_library_version,
    scan_firmware_libraries,
)
from .indicators import (
    DEFAULT_IGNORE_FILES,
    LIBRARY_FILE_TYPES,
)

__all__ = [
    # Main scanning functions
    "scan_file",
    "walk_and_scan",
    # Version detection
    "detect_library_version",
    "scan_firmware_libraries",
    # Configuration
    "LIBRARIES",
    "DEFAULT_IGNORE_FILES",
    "LIBRARY_FILE_TYPES",
]
