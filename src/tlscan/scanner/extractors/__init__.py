"""Data extraction utilities for binary analysis.

Provides functions for extracting symbols, strings, version information,
and SSL backend details from ELF binaries.
"""

from .elf import extract_symbols, extract_needed_libs, is_probably_elf
from .strings import extract_strings, contains_substring
from .version import detect_library_version, scan_firmware_libraries
from .backend import detect_ssl_backend, BackendInfo

__all__ = [
    # ELF utilities
    "extract_symbols",
    "extract_needed_libs",
    "is_probably_elf",
    # String utilities
    "extract_strings",
    "contains_substring",
    # Version detection
    "detect_library_version",
    "scan_firmware_libraries",
    # Backend detection
    "detect_ssl_backend",
    "BackendInfo",
]
