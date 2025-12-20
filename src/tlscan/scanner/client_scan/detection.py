"""TLS client detection in binaries and scripts.

Provides the core scanning functions for detecting programs that use TLS
as clients. Clean separation of concerns:
- File type detection
- Data extraction (symbols, strings)
- Library scoring (data-driven)
- Version detection (only for positive detections)
- Backend detection (only for curl-like libraries)
"""

import os
import stat
import logging
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple, Any

from ..config import (
    ScannerConfig,
    DEFAULT_CONFIG,
    DEFAULT_IGNORE_FILES,
)
from ..models import (
    ScanResult,
    DetectionResult,
    VersionInfo,
    BackendInfo as BackendInfoModel,
    FileType,
    ConfidenceLevel,
)
from .libraries import get_library, get_libraries_for_file_type, list_library_ids
from .scoring import score_all_libraries
from ..utils.elf import extract_symbols, is_probably_elf
from ..utils.strings import extract_strings

# Import version and backend detection from lib_scan
from ..lib_scan import detect_library_version, detect_ssl_backend

logger = logging.getLogger(__name__)


# ============================================================================
# File Utilities
# ============================================================================


def is_regular_file(path: str) -> bool:
    """Check if path is a regular file (not symlink, directory, etc.)."""
    try:
        st = os.lstat(path)
        return stat.S_ISREG(st.st_mode)
    except Exception:
        return False


def get_file_type(path: str) -> FileType:
    """Determine file type for appropriate library selection.

    Args:
        path: Path to the file

    Returns:
        FileType enum value
    """
    # Check for ELF binary first
    if is_probably_elf(path):
        return FileType.ELF_BINARY

    # Check file extension
    if path.endswith(".php"):
        return FileType.PHP_SCRIPT
    if path.endswith(".sh"):
        return FileType.SHELL_SCRIPT

    # Check shebang and content
    try:
        with open(path, "rb") as f:
            first_bytes = f.read(256)

        try:
            first_line = first_bytes.split(b"\n")[0].decode("utf-8", errors="ignore")
        except Exception:
            return FileType.UNKNOWN

        if first_line.startswith("#!"):
            if "php" in first_line.lower():
                return FileType.PHP_SCRIPT
            if any(shell in first_line for shell in ["sh", "bash", "zsh", "ksh"]):
                return FileType.SHELL_SCRIPT
            return FileType.OTHER_SCRIPT

        if b"<?php" in first_bytes[:50]:
            return FileType.PHP_SCRIPT

    except Exception:
        pass

    return FileType.UNKNOWN


def should_ignore_file(path: str) -> bool:
    """Check if file should be ignored based on DEFAULT_IGNORE_FILES."""
    basename = os.path.basename(path)
    for pattern in DEFAULT_IGNORE_FILES:
        if pattern in basename:
            return True
    return False


# ============================================================================
# Main Scanning Functions
# ============================================================================


def scan_file(
    path: str,
    libraries: Optional[List[str]] = None,
    config: ScannerConfig = DEFAULT_CONFIG,
) -> Optional[ScanResult]:
    """Scan a single file for TLS client library usage.

    Clean separation of concerns:
    1. File type detection
    2. Data extraction (symbols, strings)
    3. Library scoring (data-driven)
    4. Version detection (only for positive detections)
    5. Backend detection (only for curl-like libraries)

    Args:
        path: Path to the file to scan
        libraries: List of library IDs to check (None = all applicable)
        config: Scanner configuration

    Returns:
        ScanResult if any libraries detected, None otherwise
    """
    # Basic file checks
    if not is_regular_file(path):
        return None

    if should_ignore_file(path):
        logger.debug(f"Ignoring file: {path}")
        return None

    # Determine file type
    file_type = get_file_type(path)
    if file_type == FileType.UNKNOWN:
        logger.debug(f"Unknown file type: {path}")
        return None

    # Get applicable library definitions
    if libraries:
        applicable = []
        for lib_id in libraries:
            lib_def = get_library(lib_id)
            if lib_def and file_type.value in lib_def.applicable_file_types:
                applicable.append(lib_def)
    else:
        applicable = get_libraries_for_file_type(file_type.value)

    if not applicable:
        return None

    # Determine what data to extract
    need_symbols = any(
        lib.detection_method in ("symbols", "both") for lib in applicable
    )
    need_strings = any(
        lib.detection_method in ("strings", "both") for lib in applicable
    )

    # Extract data
    symbols: Set[str] = set()
    strings: Set[str] = set()

    if need_symbols:
        symbols = extract_symbols(path)
    if need_strings:
        strings = extract_strings(path, config.extraction)

    # Score all applicable libraries
    detections = score_all_libraries(applicable, symbols, strings)

    if not detections:
        return None

    # Version detection (separate concern, only for positive detections)
    versions: Dict[str, VersionInfo] = {}
    if file_type == FileType.ELF_BINARY:
        for lib_id in detections:
            # Skip CLI tools for version detection
            if lib_id == "curl_wget":
                continue

            ver_info = detect_library_version(path, lib_id, symbols)
            if ver_info:
                versions[lib_id] = VersionInfo(
                    version=ver_info.get("version", "unknown"),
                    confidence=ConfidenceLevel(ver_info.get("confidence", "low")),
                    method=ver_info.get("method", "unknown"),
                    details=ver_info.get("details"),
                    source_path=ver_info.get("source_path"),
                )

        # Backend detection (separate concern, only for curl-like libraries)
        if "libcurl" in detections or "curl_wget" in detections:
            backend = detect_ssl_backend(path, symbols)
            if backend:
                target_lib = "libcurl" if "libcurl" in detections else "curl_wget"
                backend_model = BackendInfoModel(
                    name=backend.name,
                    version=backend.version,
                    confidence=ConfidenceLevel(backend.confidence),
                    detection_method=backend.detection_method,
                )

                if target_lib in versions:
                    versions[target_lib].backend = backend_model
                else:
                    versions[target_lib] = VersionInfo(
                        version="unknown",
                        confidence=ConfidenceLevel.LOW,
                        method="backend_only",
                        backend=backend_model,
                    )

    return ScanResult(
        path=path,
        file_type=file_type,
        detections=detections,
        versions=versions if versions else None,
    )


def scan_clients(
    root: str,
    libraries: Optional[List[str]] = None,
    config: ScannerConfig = DEFAULT_CONFIG,
) -> List[ScanResult]:
    """Scan directory for programs that use TLS as clients.

    Args:
        root: Root directory to scan
        libraries: List of library IDs to check (None = all)
        config: Scanner configuration

    Returns:
        List of ScanResults for files with detected TLS client usage
    """
    results: List[ScanResult] = []

    # Walk directory tree
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            result = scan_file(fp, libraries, config)
            if result:
                results.append(result)

    logger.info(f"Scanned {root}: found {len(results)} files with TLS clients")
    return results
