"""Firmware metadata cache management.

This module manages firmware-specific cached data stored in the
.tlscan/ directory within the firmware root.

Cache files:
- library_versions.json: Detected library versions for firmware
- network_clients.json: Output from tlscan-detect
- metadata.json: Scan timestamp, tool version, etc.
"""

from pathlib import Path
import json
from typing import Optional, Dict, Any
from datetime import datetime

# Cache directory and file names
CACHE_DIR = ".tlscan"
VERSIONS_FILE = "library_versions.json"
CLIENTS_FILE = "network_clients.json"
METADATA_FILE = "metadata.json"

# Current tool version for cache compatibility
CACHE_VERSION = "1.0.0"


class FirmwareCache:
    """Manages firmware-specific cached data.

    The cache is stored in .tlscan/ directory inside the firmware root.
    This allows firmware-specific data to be stored alongside the firmware
    and reused across multiple analysis runs.

    Example:
        cache = FirmwareCache("/path/to/firmware")
        if cache.exists():
            versions = cache.load_versions()
        else:
            # Run tlscan-detect --save-cache to populate cache
            pass
    """

    def __init__(self, firmware_path: str):
        """Initialize cache with firmware root path.

        Args:
            firmware_path: Path to firmware root directory
        """
        self.firmware_path = Path(firmware_path)
        self.cache_dir = self.firmware_path / CACHE_DIR

    @property
    def versions_file(self) -> Path:
        """Path to library versions cache file."""
        return self.cache_dir / VERSIONS_FILE

    @property
    def clients_file(self) -> Path:
        """Path to network clients cache file."""
        return self.cache_dir / CLIENTS_FILE

    @property
    def metadata_file(self) -> Path:
        """Path to metadata cache file."""
        return self.cache_dir / METADATA_FILE

    def exists(self) -> bool:
        """Check if version cache exists.

        Returns:
            True if library_versions.json exists
        """
        return self.versions_file.exists()

    def cache_age_hours(self) -> Optional[float]:
        """Get age of cache in hours.

        Returns:
            Age in hours, or None if cache doesn't exist
        """
        if not self.exists():
            return None

        versions = self.load_versions()
        if not versions:
            return None

        timestamp_str = versions.get("scan_timestamp")
        if not timestamp_str:
            return None

        try:
            # Parse ISO format timestamp
            timestamp = datetime.fromisoformat(timestamp_str.rstrip("Z"))
            age = datetime.utcnow() - timestamp
            return age.total_seconds() / 3600
        except (ValueError, TypeError):
            return None

    def load_versions(self) -> Optional[Dict[str, Any]]:
        """Load cached library versions.

        Returns:
            Dict with firmware_libraries and binary_versions, or None if not found
        """
        if not self.versions_file.exists():
            return None

        try:
            return json.loads(self.versions_file.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Failed to load version cache: {e}")
            return None

    def save_versions(self, data: Dict[str, Any]) -> None:
        """Save library versions to cache.

        Automatically adds scan_timestamp and tool_version fields.

        Args:
            data: Dict with firmware_libraries and binary_versions
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Add metadata
        data["scan_timestamp"] = datetime.utcnow().isoformat() + "Z"
        data["tool_version"] = CACHE_VERSION

        self.versions_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def load_clients(self) -> Optional[Dict[str, Any]]:
        """Load cached network clients findings.

        Returns:
            Dict with findings list, or None if not found
        """
        if not self.clients_file.exists():
            return None

        try:
            return json.loads(self.clients_file.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Failed to load clients cache: {e}")
            return None

    def save_clients(self, data: Dict[str, Any]) -> None:
        """Save network clients findings to cache.

        Args:
            data: Dict with findings list
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Add metadata
        data["scan_timestamp"] = datetime.utcnow().isoformat() + "Z"
        data["tool_version"] = CACHE_VERSION

        self.clients_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def get_binary_version(
        self, binary_path: str, library: str
    ) -> Optional[Dict[str, Any]]:
        """Get version info for specific binary and library.

        Looks up version info in the following order:
        1. Binary-specific version requirements (from VERNEED)
        2. Firmware-level library version (from .so files)

        Args:
            binary_path: Path to binary being analyzed
            library: Library identifier (e.g., 'openssl', 'libcurl')

        Returns:
            Version info dict or None if not found
        """
        versions = self.load_versions()
        if not versions:
            return None

        # Try to match binary path (handle both absolute and relative paths)
        binary_versions = versions.get("binary_versions", {})

        # Normalize binary path for matching
        binary_name = Path(binary_path).name
        for cached_path, libs in binary_versions.items():
            # Match by basename or by path suffix
            if (
                binary_path.endswith(cached_path)
                or cached_path.endswith(binary_name)
                or Path(cached_path).name == binary_name
            ):
                if library in libs:
                    return libs[library]

        # Fall back to firmware-level library version
        return versions.get("firmware_libraries", {}).get(library)

    def get_firmware_library_version(self, library: str) -> Optional[Dict[str, Any]]:
        """Get firmware-level version for a library.

        Args:
            library: Library identifier (e.g., 'openssl', 'libcurl')

        Returns:
            Version info dict or None if not found
        """
        versions = self.load_versions()
        if not versions:
            return None

        return versions.get("firmware_libraries", {}).get(library)

    def clear(self) -> None:
        """Remove all cache files."""
        if self.versions_file.exists():
            self.versions_file.unlink()
        if self.clients_file.exists():
            self.clients_file.unlink()
        if self.metadata_file.exists():
            self.metadata_file.unlink()

        # Remove cache directory if empty
        if self.cache_dir.exists() and not any(self.cache_dir.iterdir()):
            self.cache_dir.rmdir()

    def __str__(self) -> str:
        """String representation showing cache status."""
        status = "exists" if self.exists() else "not found"
        age = self.cache_age_hours()
        age_str = f", {age:.1f}h old" if age is not None else ""
        return f"FirmwareCache({self.cache_dir}, {status}{age_str})"
