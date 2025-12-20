"""Configuration for the scanner module.

Centralizes all thresholds, defaults, and configuration options
that were previously scattered across the codebase.
"""

from dataclasses import dataclass, field
from typing import Set

# Tool version
TOOL_VERSION = "1.0.0"


@dataclass(frozen=True)
class ScoringThresholds:
    """Configurable thresholds for library detection scoring.

    These thresholds determine confidence levels based on indicator hits.
    """

    weak_minimum_openssl: int = 2
    """Minimum weak indicators for low-confidence OpenSSL detection."""

    weak_minimum_default: int = 3
    """Minimum weak indicators for low-confidence detection (most libraries)."""

    option_combinations_minimum: int = 2
    """Minimum option combinations for medium/high confidence (curl_wget)."""

    function_count_minimum: int = 2
    """Minimum function count for positive detection (php_curl)."""

    curlopt_minimum: int = 2
    """Minimum CURLOPT constants for php_curl detection."""


@dataclass(frozen=True)
class ExtractionConfig:
    """Configuration for binary data extraction."""

    min_string_length: int = 6
    """Minimum printable string length to extract from binaries."""

    max_file_size_mb: int = 64
    """Maximum file size (MB) to process for string extraction."""


@dataclass(frozen=True)
class ScannerConfig:
    """Master configuration for the scanner module."""

    scoring: ScoringThresholds = field(default_factory=ScoringThresholds)
    extraction: ExtractionConfig = field(default_factory=ExtractionConfig)


# Default configuration instance
DEFAULT_CONFIG = ScannerConfig()


# Files to ignore during scanning (e.g., the tools themselves)
DEFAULT_IGNORE_FILES: Set[str] = {
    "busybox",
    "curl",
    "wget",
    "openssl",
    "libcurl.so",
    "libssl.so",
    "libcrypto.so",
    "libgnutls.so",
    "libmbedtls.so",
    "libmbedcrypto.so",
    "libmbedx509.so",
}


# ASCII printable characters for string extraction
PRINTABLE: Set[int] = set(range(0x20, 0x7F))
