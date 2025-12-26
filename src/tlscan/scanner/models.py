"""Pydantic models for scanner results.

Provides type-safe result objects instead of raw dictionaries.
"""

from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Detection confidence level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FileType(str, Enum):
    """Supported file types for scanning."""

    ELF_BINARY = "elf_binary"
    SHELL_SCRIPT = "shell_script"
    PHP_SCRIPT = "php_script"
    OTHER_SCRIPT = "other_script"
    UNKNOWN = "unknown"


class DetectionMethod(str, Enum):
    """How the library is detected."""

    SYMBOLS = "symbols"
    STRINGS = "strings"
    BOTH = "both"


class VersionInfo(BaseModel):
    """Library version information."""

    version: str = Field(description="Version string (e.g., '1.1.1k')")
    confidence: ConfidenceLevel = Field(description="Detection confidence")
    method: str = Field(description="Detection method used")
    details: Optional[str] = Field(default=None, description="Additional version details")
    source_path: Optional[str] = Field(
        default=None, description="Path to library file (for firmware libs)"
    )


class DetectionResult(BaseModel):
    """Result of library detection for a single library."""

    library_id: str = Field(description="Library identifier (e.g., 'openssl')")
    library_name: str = Field(description="Human-readable name (e.g., 'OpenSSL')")
    confidence: ConfidenceLevel = Field(description="Detection confidence level")
    rationale: str = Field(description="Human-readable explanation for the detection")
    hits: Dict[str, List[str]] = Field(
        description="Categorized indicator matches (e.g., {'strong': ['SSL_connect']})"
    )
    detection_method: DetectionMethod = Field(description="Method used for detection")


class ScanResult(BaseModel):
    """Complete scan result for a single file."""

    path: str = Field(description="Absolute path to the scanned file")
    file_type: FileType = Field(description="Detected file type")
    detections: Dict[str, DetectionResult] = Field(
        description="Detection results keyed by library_id"
    )
    versions: Optional[Dict[str, VersionInfo]] = Field(
        default=None, description="Version info keyed by library_id"
    )

    def to_legacy_dict(self) -> Dict[str, Any]:
        """Convert to legacy dict format for backwards compatibility."""
        libraries = {}
        for lib_id, detection in self.detections.items():
            libraries[lib_id] = {
                "library": detection.library_name,
                "level": detection.confidence.value,
                "rationale": detection.rationale,
                "hits": detection.hits,
            }

        # versions field removed - redundant with library_versions.json

        return {
            "path": self.path,
            "file_type": self.file_type.value,
            "libraries": libraries,
        }


class FirmwareScanResult(BaseModel):
    """Results from a full firmware scan."""

    root_path: str = Field(description="Firmware root directory")
    scan_timestamp: str = Field(description="ISO format timestamp")
    tool_version: str = Field(description="Scanner version")
    firmware_libraries: Dict[str, VersionInfo] = Field(
        description="Detected firmware library versions"
    )
    file_results: List[ScanResult] = Field(description="Per-file scan results")
