"""Command-line interface for network client scanner.

Provides the CLI entry point (tlscan-detect) for scanning firmware
directories for network client library usage.
"""

import argparse
import logging

from .config import ScannerConfig, ExtractionConfig, TOOL_VERSION
from .libraries import list_library_ids, get_library_info
from .scanner import scan_directory
from .output import (
    format_human_readable,
    format_firmware_versions,
    results_to_json,
    save_to_cache,
)

logger = logging.getLogger(__name__)


def main() -> None:
    """Main entry point for tlscan-detect CLI."""
    # Build library help text
    lib_info = get_library_info()
    lib_help = "\n".join(
        f"  {lib_id:10} - {info['description']}"
        for lib_id, info in lib_info.items()
    )

    ap = argparse.ArgumentParser(
        description="Network client scanner - detects TLS/HTTP client library usage in ELF binaries and scripts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Available libraries:
{lib_help}
  all        - Scan for all libraries (default)

Examples:
  %(prog)s /path/to/firmware
  %(prog)s /path/to/firmware --libraries openssl libcurl
  %(prog)s /path/to/firmware --json > results.json
  %(prog)s /path/to/firmware --save-cache  # Save to .tlscan/
        """,
    )
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument(
        "--libraries",
        nargs="+",
        choices=list_library_ids() + ["all"],
        default=["all"],
        help="Which libraries to scan for (default: all)",
    )
    ap.add_argument(
        "--min-strlen",
        type=int,
        default=6,
        help="Minimum printable-string length for string-based detection (default: 6)",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (single object with all findings)",
    )
    ap.add_argument(
        "--save-cache",
        action="store_true",
        help="Save results to .tlscan/ directory in firmware root",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = ap.parse_args()

    # Configure logging
    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s: %(name)s: %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s: %(message)s",
        )

    # Resolve library list
    if "all" in args.libraries:
        libraries = None  # None means all libraries
    else:
        libraries = args.libraries

    # Build configuration
    config = ScannerConfig(
        extraction=ExtractionConfig(min_string_length=args.min_strlen),
    )

    # Scan
    results, firmware_versions = scan_directory(args.root, libraries, config)

    # Output
    if args.json:
        print(results_to_json(results, firmware_versions))
    else:
        # Print firmware library versions first
        version_output = format_firmware_versions(firmware_versions)
        if version_output:
            print(version_output)

        if not results:
            print(f"No network clients detected in {args.root}")
        else:
            print(f"Found {len(results)} file(s) with network client usage:")
            print(format_human_readable(results))

    # Save to cache if requested
    if args.save_cache:
        cache_dir = save_to_cache(args.root, results, firmware_versions)
        print(f"\nCache saved to: {cache_dir}")
        print(f"  - library_versions.json: {len(firmware_versions)} firmware libraries")
        print(f"  - network_clients.json: {len(results)} findings")

    # Exit status: 0 if anything found, 1 if nothing
    raise SystemExit(0 if results else 1)


if __name__ == "__main__":
    main()
