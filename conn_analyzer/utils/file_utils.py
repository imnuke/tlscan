"""
File utilities for conn_analyzer.

Provides functions for path resolution, call graph path computation, and rule loading.
"""

import os
import hashlib
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from conn_analyzer.config import SECURITY_RULES_DIR, TEMP_FILES_DIR

# Initialize console for output
console = Console()

# Libraries that require binary analysis (vs script-based libraries)
BINARY_LIBRARIES = {"openssl", "libcurl", "gnutls", "mbedtls", "socket"}


def requires_binary_analysis(library: str) -> bool:
    """Check if library requires binary analysis (call graph generation).

    Args:
        library: Library name

    Returns:
        True if library needs binary analysis, False for script-based libraries
    """
    return library in BINARY_LIBRARIES


def compute_call_graph_path(binary_path: str) -> str:
    """
    Compute unique call graph path based on binary content hash.

    Uses MD5 hash of binary contents to generate a unique filename.
    This ensures that different binaries get different call graph files,
    even if they have the same name.

    Args:
        binary_path: Path to the binary file

    Returns:
        Path to the call graph JSON file (e.g., 'temp_files/callgraph_abc123.json')
    """
    with open(binary_path, 'rb') as f:
        binary_hash = hashlib.md5(f.read()).hexdigest()[:8]

    # Ensure temp directory exists
    TEMP_FILES_DIR.mkdir(exist_ok=True)

    return str(TEMP_FILES_DIR / f"callgraph_{binary_hash}.json")


def resolve_binary_path(binary_path: str, firmware_path: str | None = None) -> str:
    """
    Resolve binary path, checking both absolute path and firmware-relative path.

    Args:
        binary_path: Path to the binary (can be absolute or relative)
        firmware_path: Optional path to firmware root for resolving relative paths

    Returns:
        Resolved absolute path to the binary

    Raises:
        FileNotFoundError: If the binary cannot be found at any checked location
    """
    # Try absolute path first
    if os.path.isabs(binary_path):
        resolved_path = binary_path
    # Try firmware-relative path if firmware root is provided
    elif firmware_path:
        resolved_path = os.path.join(firmware_path, binary_path)
    # Try current directory
    else:
        resolved_path = binary_path

    # Check if file exists
    if not os.path.exists(resolved_path):
        console.print(Panel(
            f"[bold red]✗ Binary Not Found[/bold red]\n\n"
            f"Resolved path: {resolved_path}\n"
            f"Original path: {binary_path}\n"
            + (f"Firmware root: {firmware_path}\n" if firmware_path else "") +
            "\nPlease check:\n"
            "• Binary path is correct\n"
            "• Firmware path is correct (if using relative path)\n"
            "• File has not been moved or deleted",
            border_style="red",
            title="[bold]File Error[/bold]"
        ))
        console.print()
        raise FileNotFoundError(f"Binary not found: {resolved_path}")

    return resolved_path


def load_security_rules(library_name: str = "openssl") -> str:
    """
    Load SSL/TLS security rules from markdown file.

    Args:
        library_name: Name of the SSL/TLS library
                     (openssl, curl, libcurl, gnutls, mbedtls, php_curl, wget)

    Returns:
        Content of the rules file, or empty string if file not found
    """
    rule_file = SECURITY_RULES_DIR / f"rule_{library_name}.md"

    if rule_file.exists():
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()
            console.print(f"[green]✓[/green] Loaded security rules from [bold]{rule_file}[/bold]")
            return content
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow]  Failed to load security rules from {rule_file}: {e}")
            return ""
    else:
        console.print(f"[yellow]⚠[/yellow]  Security rules file not found: {rule_file}")
        return ""
