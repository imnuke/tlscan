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


class BackendConfig(BaseModel):
    """Extracted backend TLS configuration from firmware config files."""

    min_protocol: Optional[str] = Field(
        default=None, description="Minimum TLS protocol (e.g., 'TLSv1.2')"
    )
    max_protocol: Optional[str] = Field(
        default=None, description="Maximum TLS protocol (e.g., 'TLSv1.3')"
    )
    config_source: Optional[str] = Field(
        default=None, description="Path to config file (relative to firmware root)"
    )


class BackendInfo(BaseModel):
    """SSL/TLS backend information for curl/libcurl."""

    name: str = Field(description="Backend name (e.g., OpenSSL, GnuTLS)")
    version: Optional[str] = Field(default=None, description="Backend version if detected")
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM, description="Detection confidence"
    )
    detection_method: str = Field(
        default="dynamic_linking",
        description="How backend was detected (dynamic_linking, symbols, version_string)",
    )
    config: Optional[BackendConfig] = Field(
        default=None, description="Extracted TLS config from firmware config files"
    )


class VersionInfo(BaseModel):
    """Library version information."""

    version: str = Field(description="Version string (e.g., '1.1.1k')")
    confidence: ConfidenceLevel = Field(description="Detection confidence")
    method: str = Field(description="Detection method used")
    details: Optional[str] = Field(default=None, description="Additional version details")
    source_path: Optional[str] = Field(
        default=None, description="Path to library file (for firmware libs)"
    )
    backend: Optional[BackendInfo] = Field(
        default=None, description="SSL backend info (for curl/libcurl)"
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

        version_dict = None
        if self.versions:
            version_dict = {}
            for lib_id, ver in self.versions.items():
                ver_data: Dict[str, Any] = {
                    "version": ver.version,
                    "confidence": ver.confidence.value,
                    "method": ver.method,
                }
                if ver.details:
                    ver_data["details"] = ver.details
                if ver.source_path:
                    ver_data["source_path"] = ver.source_path
                if ver.backend:
                    backend_data: Dict[str, Any] = {
                        "name": ver.backend.name,
                        "version": ver.backend.version,
                        "confidence": ver.backend.confidence.value,
                        "detection_method": ver.backend.detection_method,
                    }
                    if ver.backend.config:
                        backend_data["config"] = {
                            "min_protocol": ver.backend.config.min_protocol,
                            "max_protocol": ver.backend.config.max_protocol,
                            "config_source": ver.backend.config.config_source,
                        }
                    ver_data["backend"] = backend_data
                version_dict[lib_id] = ver_data

        return {
            "path": self.path,
            "file_type": self.file_type.value,
            "libraries": libraries,
            "versions": version_dict,
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
