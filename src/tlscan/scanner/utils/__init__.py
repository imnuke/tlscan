"""Shared utilities for binary analysis.

Provides low-level functions for extracting data from ELF binaries:
- ELF symbol extraction
- String extraction
- File type detection

For version detection, use: tlscan.scanner.lib_scan.versions
For backend detection, use: tlscan.scanner.lib_scan.backends
"""

from .elf import extract_symbols, extract_needed_libs, is_probably_elf
from .strings import extract_strings, contains_substring

__all__ = [
    # ELF utilities
    "extract_symbols",
    "extract_needed_libs",
    "is_probably_elf",
    # String utilities
    "extract_strings",
    "contains_substring",
]
