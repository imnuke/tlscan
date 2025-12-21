"""Output formatting for scanner results.

Provides functions for formatting scan results in human-readable
and JSON formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .config import TOOL_VERSION
from .models import ScanResult, FirmwareScanResult


def format_human_readable(results: List[ScanResult]) -> str:
    """Format scan results for human-readable console output.

    Args:
        results: List of ScanResult objects

    Returns:
        Formatted string for console output
    """
    lines = []

    for result in results:
        lines.append("")
        lines.append("=" * 80)
        lines.append(f"File: {result.path}")
        lines.append(f"Type: {result.file_type.value}")
        lines.append("=" * 80)

        for lib_id, detection in result.detections.items():
            lines.append("")
            lines.append(f"[{detection.confidence.value.upper()}] {detection.library_name}")
            lines.append(f"  {detection.rationale}")

            # Print hit details
            for category, items in detection.hits.items():
                if items:
                    display_items = sorted(items)[:5]
                    line = f"  {category}: {', '.join(display_items)}"
                    if len(items) > 5:
                        line += f" ... (+{len(items) - 5} more)"
                    lines.append(line)

    return "\n".join(lines)


def format_firmware_versions(firmware_versions: Dict[str, Dict[str, Any]]) -> str:
    """Format firmware library versions for console output.

    Args:
        firmware_versions: Dict mapping library types to version info

    Returns:
        Formatted string for console output
    """
    if not firmware_versions:
        return ""

    lines = ["Firmware Library Versions:", "=" * 40]

    for lib_type, info in sorted(firmware_versions.items()):
        version = info.get("version", "unknown")
        confidence = info.get("confidence", "unknown")
        method = info.get("method", "unknown")
        source = info.get("source_path", "")

        # Build version line with optional backend
        # NOTE: Escape square brackets to prevent Rich from interpreting as markup
        line = f"  {lib_type}: {version} ({confidence} confidence, {method})"
        backend = info.get("backend")
        if backend:
            backend_str = backend.get("name", "")
            if backend.get("version"):
                backend_str += f" {backend['version']}"
            # Escape the opening bracket for Rich compatibility
            line += f" \\[backend: {backend_str}]"

            # Add config info if available
            config = backend.get("config")
            if config and config.get("min_protocol"):
                line += f" \\[min: {config['min_protocol']}]"
        lines.append(line)

        if source:
            lines.append(f"    Source: {source}")

    lines.append("")
    return "\n".join(lines)


def results_to_json(
    results: List[ScanResult],
    firmware_versions: Dict[str, Dict[str, Any]],
    indent: int = 2,
) -> str:
    """Convert scan results to JSON string.

    Args:
        results: List of ScanResult objects
        firmware_versions: Firmware library versions dict
        indent: JSON indentation level

    Returns:
        JSON string
    """
    # Convert ScanResults to legacy dict format for compatibility
    findings = [result.to_legacy_dict() for result in results]

    output = {
        "firmware_library_versions": firmware_versions,
        "findings": findings,
    }

    return json.dumps(output, ensure_ascii=False, indent=indent)


def save_to_cache(
    root: str,
    results: List[ScanResult],
    firmware_versions: Dict[str, Dict[str, Any]],
) -> Path:
    """Save scan results to firmware cache directory.

    Creates .tlscan/ directory in firmware root and saves:
    - library_versions.json: Library version information
    - network_clients.json: TLS client findings (legacy filename kept for compatibility)

    Args:
        root: Firmware root directory
        results: List of ScanResult objects
        firmware_versions: Dict of firmware library versions

    Returns:
        Path to the cache directory
    """
    cache_dir = Path(root) / ".tlscan"
    cache_dir.mkdir(parents=True, exist_ok=True)

    root_path = Path(root)

    # Prepare version data with relative paths
    binary_versions: Dict[str, Dict[str, Any]] = {}
    for result in results:
        if result.versions:
            try:
                rel_path = str(Path(result.path).relative_to(root_path))
            except ValueError:
                rel_path = result.path

            # Convert VersionInfo models to dicts
            version_dict = {}
            for lib_id, ver in result.versions.items():
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

            binary_versions[rel_path] = version_dict

    versions_data = {
        "scan_timestamp": datetime.now().astimezone().isoformat(),
        "tool_version": TOOL_VERSION,
        "firmware_libraries": firmware_versions,
        "binary_versions": binary_versions,
    }

    # Save library versions
    versions_file = cache_dir / "library_versions.json"
    versions_file.write_text(json.dumps(versions_data, indent=2, ensure_ascii=False))

    # Convert findings paths to relative
    findings_relative = []
    for result in results:
        finding = result.to_legacy_dict()
        try:
            finding["path"] = str(Path(result.path).relative_to(root_path))
        except ValueError:
            pass
        findings_relative.append(finding)

    # Save TLS client findings
    clients_data = {
        "scan_timestamp": datetime.now().astimezone().isoformat(),
        "tool_version": TOOL_VERSION,
        "findings": findings_relative,
    }
    clients_file = cache_dir / "network_clients.json"
    clients_file.write_text(json.dumps(clients_data, indent=2, ensure_ascii=False))

    return cache_dir
