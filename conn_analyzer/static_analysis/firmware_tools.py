import os
import subprocess
import re
from pathlib import Path
from typing import Optional
from langchain_core.tools import tool
from ..utils.binary_utils import is_elf_file, get_imported_function_list, get_exported_function_list

# Global firmware root path - will be set by the agent initialization
FIRMWARE_ROOT = None

def set_firmware_root(path: str):
    """Set the firmware root directory for all tools."""
    global FIRMWARE_ROOT
    FIRMWARE_ROOT = Path(path).resolve()

def _validate_path(path: str) -> Path:
    """
    Validate that a path is within firmware root and return absolute path.

    Args:
        path: Relative or absolute path to validate

    Returns:
        Absolute Path object

    Raises:
        ValueError: If path is outside firmware root
    """
    if FIRMWARE_ROOT is None:
        raise RuntimeError("Firmware root not set. Call set_firmware_root() first.")

    # Convert to absolute path
    if os.path.isabs(path):
        abs_path = Path(path).resolve()
    else:
        abs_path = (FIRMWARE_ROOT / path).resolve()

    # Security check: ensure path is within firmware root
    try:
        abs_path.relative_to(FIRMWARE_ROOT)
    except ValueError:
        raise ValueError(f"Path {path} is outside firmware root {FIRMWARE_ROOT}")

    return abs_path

# ============================================================================
# 1. FILE DISCOVERY & SEARCH
# ============================================================================

@tool
def search_files_by_name(pattern: str, max_results: int = 50) -> str:
    """
    Search for files by name pattern in firmware filesystem (fast search using fd).

    ⚠️ WARNING: Avoid overly broad patterns like "*" or single characters.
    Overly broad searches may return thousands of results and fail.

    Use this to find files matching a name pattern, such as:
    - Configuration files: "*.conf", "ssl.conf", "openssl.cnf"
    - Scripts: "*.sh", "init.d/*", "startup*"
    - Binaries: "httpd", "libssl*", "*.so"

    Args:
        pattern: Filename pattern (glob or regex). Examples: "*.conf", "ssl", "lib*.so"
                 MUST be specific - avoid patterns like "*" that match everything
        max_results: Maximum number of results to return (default: 50)

    Returns:
        List of matching file paths (relative to firmware root), one per line

    Examples:
        search_files_by_name("*.conf") - Find all .conf files (GOOD)
        search_files_by_name("*upsmon*.conf") - Find upsmon config files (GOOD)
        search_files_by_name("libupsclient*") - Find upsclient library files (GOOD)
        search_files_by_name("*") - Matches everything (BAD - too broad)
    """
    try:
        # Use fd for fast file searching
        cmd = [
            "fd",
            "--glob",  # Enable glob-based pattern matching (*.conf, lib*.so, etc.)
            "--max-results", str(max_results),
            "--type", "f",  # Files only
            pattern,
            str(FIRMWARE_ROOT)
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return f"Error: fd command failed: {result.stderr}"

        if not result.stdout.strip():
            return f"No files found matching pattern: {pattern}"

        # Convert absolute paths to relative paths
        files = []
        for line in result.stdout.strip().split('\n'):
            try:
                rel_path = Path(line).relative_to(FIRMWARE_ROOT)
                files.append(str(rel_path))
            except ValueError:
                files.append(line)

        return f"Found {len(files)} files:\n" + "\n".join(files)

    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds"
    except Exception as e:
        return f"Error searching files: {str(e)}"

@tool
def search_files_by_content(pattern: str, file_pattern: Optional[str] = None, max_results: int = 100) -> str:
    """
    Search for files containing specific text or regex pattern (fast search using ripgrep).

    ⚠️ WARNING: Patterns must be SPECIFIC library/function/daemon names.
    Generic words (like "ssl", "verify") or single characters will return
    thousands of matches and fail. ALWAYS use file_pattern to restrict scope.

    Use this to find files containing:
    - Specific daemon names: "upsmon", "httpd", "sshd"
    - Specific library names: "upsclient", "libcurl", "openssl"
    - Exact function names: "SSL_CTX_set_verify", "upscli_connect"
    - Exact constant names: "CURLOPT_SSL_VERIFYHOST", "CERT_NONE"

    Args:
        pattern: SPECIFIC identifier to search for (daemon/library/function/constant name).
                 For numbers, add full context (e.g., "upsmon_port_3" not "3").
        file_pattern: Optional glob to filter file types (e.g., "*.conf", "*.sh").
                      STRONGLY RECOMMENDED to avoid excessive matches.
        max_results: Maximum number of matching lines to return (default: 100)

    Returns:
        Matching lines with file paths and line numbers (format: path:line:content)

    Examples:
        search_files_by_content("upsmon", file_pattern="*.conf") - GOOD (specific daemon + filtered)
        search_files_by_content("upsclient") - GOOD (specific library name)
        search_files_by_content("CURLOPT_SSL_VERIFYHOST") - GOOD (exact constant)
        search_files_by_content("SSL_CTX_set_verify") - GOOD (exact function name)
        search_files_by_content("ssl") - BAD (too generic, appears everywhere)
        search_files_by_content("verify") - BAD (common word, too many matches)
        search_files_by_content("4") - BAD (single digit, returns thousands of matches)
    """
    try:
        cmd = [
            "rg",
            "--binary",  # Include binary files in search
            "--max-count", str(max_results), # Limit number of matches per file
            "--max-columns", "100", # Do not display long matched lines, like minified JS
            "--line-number",
            "--no-heading",
            "--color", "never",
        ]

        # Add user file_pattern FIRST (if provided)
        if file_pattern:
            cmd.extend(["--glob", file_pattern])

        # Add exclusions AFTER - they take final precedence over file_pattern
        # Exclude web files (minified JS/HTML/CSS can be 100KB+ on one line)
        cmd.extend([
            "--glob", "!*.js",
            "--glob", "!*.html",
            "--glob", "!*.htm",
            "--glob", "!*.css",
            "--glob", "!*.svg",
            "--glob", "!*.txt",
            # Exclude metadata/documentation files
            "--glob", "!ChangeLog*",
            "--glob", "!CHANGES*",
            "--glob", "!COPYING*",
            "--glob", "!LICENSE*",
            "--glob", "!NEWS*",
            "--glob", "!README*",
            "--glob", "!*manifest*",
            # Exclude files produced by IDA
            "--glob", "!*.idb",
            "--glob", "!*.i64",
            "--glob", "!*.id0",
            "--glob", "!*.id1",
            "--glob", "!*.id2",
            "--glob", "!*.nam",
            "--glob", "!*.til",
            "--glob", "!*.sig",
            # Exclude files produced by firmware extractors
            "--glob", "!*.uncompressed",
            # Exclude language/localization files
            "--glob", "!*Danish*",
            "--glob", "!*Czech*",
            "--glob", "!*English*",
            "--glob", "!*Dutch*",
            "--glob", "!*Croatian*",
            "--glob", "!*Chinese*",
            "--glob", "!*Bulgarian*",
            "--glob", "!*Arabic*",
            "--glob", "!*Russian*",
            "--glob", "!*Spanish*",
            "--glob", "!*French*",
            "--glob", "!*German*",
            "--glob", "!*Italian*",
            "--glob", "!*Japanese*",
            "--glob", "!*Korean*",
            "--glob", "!*Portuguese*",
            "--glob", "!*Turkish*",
            "--glob", "!*Romanian*",
            "--glob", "!*Greek*",
            "--glob", "!*Slovak*",
            "--glob", "!*Slovenian*",
            "--glob", "!*Polish*",
            "--glob", "!*Hungarian*",
            "--glob", "!*Swedish*",
            "--glob", "!*Norwegian*",
            "--glob", "!*Finnish*",
        ])

        cmd.extend([pattern, str(FIRMWARE_ROOT)])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # ripgrep returns 0 for matches, 1 for no matches, 2+ for errors
        if result.returncode >= 2:
            return f"Error: ripgrep command failed: {result.stderr}"

        if not result.stdout.strip():
            filter_msg = f" in {file_pattern}" if file_pattern else ""
            return f"No matches found for pattern: {pattern}{filter_msg}"

        # Convert absolute paths to relative paths
        lines = []
        for line in result.stdout.strip().split('\n'):
            # Format: /abs/path/file:line:content
            match = re.match(r'^(.+?):(\d+):(.*)$', line)
            if match:
                abs_path, line_num, content = match.groups()
                try:
                    rel_path = Path(abs_path).relative_to(FIRMWARE_ROOT)
                    lines.append(f"{rel_path}:{line_num}:{content}")
                except ValueError:
                    lines.append(line)
            else:
                lines.append(line)

        return f"Found {len(lines)} matches:\n" + "\n".join(lines)

    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds"
    except Exception as e:
        return f"Error searching content: {str(e)}"

# ============================================================================
# 2. FILE READING
# ============================================================================

@tool
def read_file(path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """
    Read file contents from firmware filesystem.

    Use this to read:
    - Configuration files to check SSL/TLS settings
    - Script files to understand startup/configuration logic
    - Text files containing relevant information

    Args:
        path: File path (relative to firmware root or absolute within firmware)
        start_line: Optional starting line number (1-indexed)
        end_line: Optional ending line number (inclusive)

    Returns:
        File contents (optionally filtered to line range)

    Examples:
        read_file("etc/ssl/openssl.cnf") - Read OpenSSL config
        read_file("etc/init.d/httpd") - Read httpd startup script
        read_file("etc/ssl.conf", 10, 30) - Read lines 10-30 of ssl.conf
    """
    try:
        abs_path = _validate_path(path)

        if not abs_path.exists():
            return f"Error: File not found: {path}"

        if not abs_path.is_file():
            return f"Error: Not a file: {path}"

        # Check if file is binary
        with open(abs_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return f"Error: Cannot read binary file: {path}\nUse find_function_definition or find_function_references for binary analysis."

        # Read text file
        with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        # Apply line range filter
        if start_line is not None or end_line is not None:
            start = (start_line - 1) if start_line else 0
            end = end_line if end_line else len(lines)
            lines = lines[start:end]
            line_info = f" (lines {start_line or 1}-{end_line or len(lines)})"
        else:
            line_info = ""

        content = ''.join(lines)
        return f"File: {path}{line_info}\n{'=' * 60}\n{content}"

    except UnicodeDecodeError:
        return f"Error: File encoding issue. File may be binary: {path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"

# ============================================================================
# 3. BINARY ANALYSIS
# ============================================================================

# FIXME: Not working well. Not finding that upscli_connect is defined in libupsclient.so.
@tool
def find_function_definition(function_name: str) -> str:
    """
    Find the binary where a function is defined.

    Use this to:
    - Locate where functions are implemented

    Args:
        function_name: Name of the function to search for

    Returns:
        Binary path where function is defined

    Examples:
        find_function_definition("SSL_CTX_set_verify") - Find SSL_CTX_set_verify implementation
    """
    for root, _, files in os.walk(FIRMWARE_ROOT):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path) or not is_elf_file(file_path):
                continue
            exported_functions = get_exported_function_list(file_path)
            if function_name in exported_functions:
                rel_path = Path(file_path).relative_to(FIRMWARE_ROOT)
                return f"Function '{function_name}' is defined in binary: {rel_path}"

    return f"Function '{function_name}' not found in any binaries."

@tool
def find_function_references(function_name: str) -> str:
    """
    Find all references to a function within binaries.

    Use this to:
    - Identify where SSL/TLS functions are called
    - Trace usage of custom verification callbacks
    - Understand function call relationships

    Args:
        function_name: Name of the function to search for

    Returns:
        List of binaries and addresses referencing the function

    Examples:
        find_function_references("SSL_connect") - Find all calls to SSL_connect
        find_function_references("custom_verify_callback") - Trace custom callback usage
    """
    results = []

    for root, _, files in os.walk(FIRMWARE_ROOT):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path) or not is_elf_file(file_path):
                continue
            imported_functions = get_imported_function_list(file_path)
            if function_name in imported_functions:
                rel_path = Path(file_path).relative_to(FIRMWARE_ROOT)
                results.append(str(rel_path))

    if results:
        return f"Function '{function_name}' is referenced in {len(results)} binaries:\n" + "\n".join(results)

    return f"Function '{function_name}' not found in any binaries."
