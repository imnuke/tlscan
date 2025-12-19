"""Command-line interface for network client scanner.

Provides CLI entry point and output formatting functions.
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .detector import LIBRARIES, scan_file, walk_and_scan


def print_human_readable(findings: List[Dict]) -> None:
    """Print findings in human-readable format."""
    for finding in findings:
        print(f"\n{'=' * 80}")
        print(f"File: {finding['path']}")
        print(f"Type: {finding['file_type']}")
        print('=' * 80)

        for lib_key, lib_result in finding["libraries"].items():
            print(f"\n[{lib_result['level'].upper()}] {lib_result['library']}")
            print(f"  {lib_result['rationale']}")

            # Print hit details
            for category, items in lib_result["hits"].items():
                if items:
                    print(f"  {category}: {', '.join(sorted(items)[:5])}", end="")
                    if len(items) > 5:
                        print(f" ... (+{len(items) - 5} more)")
                    else:
                        print()


def save_to_cache(root: str, findings: List[Dict], firmware_versions: Dict[str, Dict[str, Any]]) -> None:
    """Save scan results to firmware cache directory.

    Creates .tlscan/ directory in firmware root and saves:
    - library_versions.json: Library version information
    - network_clients.json: Network client findings

    Args:
        root: Firmware root directory
        findings: List of network client findings
        firmware_versions: Dict of firmware library versions
    """
    cache_dir = Path(root) / ".tlscan"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Prepare version data
    # Convert finding paths to relative paths
    root_path = Path(root)
    binary_versions: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        if finding.get("versions"):
            try:
                rel_path = str(Path(finding["path"]).relative_to(root_path))
            except ValueError:
                rel_path = finding["path"]
            binary_versions[rel_path] = finding["versions"]

    versions_data = {
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "tool_version": "1.0.0",
        "firmware_libraries": firmware_versions,
        "binary_versions": binary_versions,
    }

    # Save library versions
    versions_file = cache_dir / "library_versions.json"
    versions_file.write_text(json.dumps(versions_data, indent=2, ensure_ascii=False))

    # Convert findings paths to relative
    findings_relative = []
    for finding in findings:
        finding_copy = finding.copy()
        try:
            finding_copy["path"] = str(Path(finding["path"]).relative_to(root_path))
        except ValueError:
            pass
        findings_relative.append(finding_copy)

    # Save network clients findings
    clients_data = {
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "tool_version": "1.0.0",
        "findings": findings_relative,
    }
    clients_file = cache_dir / "network_clients.json"
    clients_file.write_text(json.dumps(clients_data, indent=2, ensure_ascii=False))

    print(f"\nCache saved to: {cache_dir}")
    print(f"  - {versions_file.name}: {len(firmware_versions)} firmware libraries, {len(binary_versions)} binaries")
    print(f"  - {clients_file.name}: {len(findings)} findings")


def main() -> None:
    """Main entry point for tlscan-detect CLI."""
    ap = argparse.ArgumentParser(
        description="Unified network client scanner - detects TLS/HTTP client library usage in ELF binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available libraries:
  openssl    - OpenSSL TLS/SSL client connections
  libcurl    - libcurl HTTP/HTTPS client library
  gnutls     - GnuTLS TLS client library
  mbedtls    - mbed TLS client library
  curl_wget  - curl and wget command-line tools
  php_curl   - PHP curl extension
  all        - Scan for all libraries (default)

Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware --libraries openssl libcurl
  %(prog)s /path/to/firmware --json > results.jsonl
  %(prog)s /path/to/firmware --save-cache  # Save to .tlscan/
        """
    )
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument(
        "--libraries",
        nargs='+',
        choices=list(LIBRARIES.keys()) + ['all'],
        default=['all'],
        help="Which libraries to scan for (default: all)"
    )
    ap.add_argument("--min-strlen", type=int, default=6,
                   help="Minimum printable-string length for string-based detection (default: 6)")
    ap.add_argument("--json", action="store_true",
                   help="Emit JSON lines (one object per finding)")
    ap.add_argument("--save-cache", action="store_true",
                   help="Save results to .tlscan/ directory in firmware root")
    args = ap.parse_args()

    # Resolve library list
    if 'all' in args.libraries:
        libraries = list(LIBRARIES.keys())
    else:
        libraries = args.libraries

    # Scan
    findings, firmware_versions = walk_and_scan(args.root, libraries, args.min_strlen)

    # Output
    if args.json:
        # JSON output includes firmware versions
        output = {
            "firmware_library_versions": firmware_versions,
            "findings": findings,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        # Print firmware library versions first
        if firmware_versions:
            print("Firmware Library Versions:")
            print("=" * 40)
            for lib_type, info in sorted(firmware_versions.items()):
                version = info.get("version", "unknown")
                confidence = info.get("confidence", "unknown")
                method = info.get("method", "unknown")
                source = info.get("source_path", "")

                # Build version line with optional backend
                line = f"  {lib_type}: {version} ({confidence} confidence, {method})"
                backend = info.get("backend")
                if backend:
                    backend_str = backend.get("name", "")
                    if backend.get("version"):
                        backend_str += f" {backend['version']}"
                    line += f" [backend: {backend_str}]"
                print(line)

                if source:
                    print(f"    Source: {source}")
            print()

        if not findings:
            print(f"No network clients detected in {args.root}")
        else:
            print(f"Found {len(findings)} file(s) with network client usage:\n")
            print_human_readable(findings)

    # Save to cache if requested
    if args.save_cache:
        save_to_cache(args.root, findings, firmware_versions)

    # Exit status: 0 if anything found, 1 if nothing
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
