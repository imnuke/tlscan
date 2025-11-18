import os
import subprocess
import re
from pathlib import Path
from typing import Optional
from langchain_core.tools import tool

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

    Use this to find files matching a name pattern, such as:
    - Configuration files: "*.conf", "ssl.conf", "openssl.cnf"
    - Scripts: "*.sh", "init.d/*", "startup*"
    - Binaries: "httpd", "libssl*", "*.so"

    Args:
        pattern: Filename pattern (glob or regex). Examples: "*.conf", "ssl", "lib*.so"
        max_results: Maximum number of results to return (default: 50)

    Returns:
        List of matching file paths (relative to firmware root), one per line

    Examples:
        search_files_by_name("*.conf") - Find all .conf files
        search_files_by_name("libssl") - Find files with "libssl" in name
        search_files_by_name("startup") - Find startup scripts
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

    Use this to find files containing:
    - SSL/TLS keywords: "SSL_CTX_set_verify", "verify_mode", "CERT_NONE"
    - Configuration options: "ssl_verify", "check_certificate"
    - Function calls: "SSL_connect", "curl_easy_setopt"

    Args:
        pattern: Text or regex to search for. Use regex for advanced patterns.
        file_pattern: Optional glob to filter file types (e.g., "*.conf", "*.sh")
        max_results: Maximum number of matching lines to return (default: 100)

    Returns:
        Matching lines with file paths and line numbers (format: path:line:content)

    Examples:
        search_files_by_content("SSL_CTX_set_verify") - Find SSL verification code
        search_files_by_content("verify.*=.*0", "*.conf") - Find verify disabled in configs
        search_files_by_content("curl_easy_setopt", "*.c") - Find curl options in C files
    """
    try:
        cmd = [
            "rg",
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
                return f"Error: Cannot read binary file: {path}\nUse list_binary_symbols or find_binary_strings instead."

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

@tool
def list_binary_symbols(path: str, symbol_filter: Optional[str] = None) -> str:
    """
    List functions and symbols in a binary using nm (names tool).

    Use this to:
    - Find what SSL/TLS functions a binary defines or imports
    - Check if a binary implements a specific function
    - List all exported functions from a library

    Args:
        path: Binary file path (executable or shared library)
        symbol_filter: Optional regex filter for symbol names (e.g., "SSL_", "verify")

    Returns:
        List of symbols with type indicators:
        T = defined function (text), U = undefined (imported), D = initialized data

    Examples:
        list_binary_symbols("usr/lib/libssl.so") - List all libssl symbols
        list_binary_symbols("usr/bin/httpd", "SSL_") - Find SSL functions in httpd
        list_binary_symbols("lib/libcrypto.so", "verify") - Find verify functions
    """
    try:
        abs_path = _validate_path(path)

        if not abs_path.exists():
            return f"Error: File not found: {path}"

        # Use nm to list symbols
        cmd = ["nm", "-D", str(abs_path)]  # -D for dynamic symbols

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            # Try without -D (for static binaries)
            cmd = ["nm", str(abs_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return f"Error: nm command failed: {result.stderr}\nFile may not be a binary: {path}"

        if not result.stdout.strip():
            return f"No symbols found in: {path}"

        # Parse nm output and filter
        symbols = []
        for line in result.stdout.strip().split('\n'):
            # Format: [address] type name
            # Example: "0000000000001234 T SSL_connect"
            parts = line.split()
            if len(parts) >= 2:
                # Handle lines without address (undefined symbols)
                if len(parts) == 3:
                    addr, sym_type, name = parts
                else:
                    sym_type, name = parts
                    addr = ""

                # Apply filter if provided
                if symbol_filter and not re.search(symbol_filter, name, re.IGNORECASE):
                    continue

                symbols.append(f"{sym_type} {name}")

        if not symbols:
            filter_msg = f" matching '{symbol_filter}'" if symbol_filter else ""
            return f"No symbols found{filter_msg} in: {path}"

        header = f"Symbols in {path}:\n" + "=" * 60 + "\n"
        header += "Legend: T=defined, U=imported, D=data, W=weak\n" + "=" * 60 + "\n"

        return header + "\n".join(symbols[:500])  # Limit output

    except subprocess.TimeoutExpired:
        return "Error: nm command timed out"
    except Exception as e:
        return f"Error analyzing binary: {str(e)}"

@tool
def find_binaries_with_symbol(symbol_name: str, binary_pattern: str = "*") -> str:
    """
    Find all binaries that define or import a specific function/symbol.

    Use this for cross-binary analysis:
    - Which binary implements SSL_verify_callback?
    - Which binaries import SSL_CTX_set_verify?
    - Where is a custom function defined?

    Args:
        symbol_name: Function/symbol name to search for (supports regex)
        binary_pattern: Glob pattern for binaries to search (default: all files)

    Returns:
        List of binaries with the symbol, showing if it's defined (T) or imported (U)

    Examples:
        find_binaries_with_symbol("SSL_verify") - Find all binaries with SSL_verify
        find_binaries_with_symbol("curl_easy_setopt", "usr/bin/*") - Search in /usr/bin
        find_binaries_with_symbol("custom_verify_callback") - Find custom function
    """
    try:
        # First, find all potential binary files
        cmd = [
            "fd",
            "--glob",  # Enable glob-based pattern matching (usr/bin/*, lib*.so, etc.)
            "--type", "f",
            binary_pattern,
            str(FIRMWARE_ROOT)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return f"Error finding binaries: {result.stderr}"

        files = result.stdout.strip().split('\n')
        if not files or files == ['']:
            return f"No files found matching pattern: {binary_pattern}"

        # Check each file for the symbol
        matches = []
        for file_path in files[:500]:  # Limit to avoid too many nm calls
            try:
                # Quick check if file is binary
                with open(file_path, 'rb') as f:
                    magic = f.read(4)
                    # Check for ELF magic number
                    if magic[:4] != b'\x7fELF':
                        continue

                # Run nm on the binary
                result = subprocess.run(
                    ["nm", "-D", file_path],
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                # Search for symbol in output
                for line in result.stdout.split('\n'):
                    if re.search(symbol_name, line, re.IGNORECASE):
                        rel_path = Path(file_path).relative_to(FIRMWARE_ROOT)
                        parts = line.split()
                        if len(parts) >= 2:
                            sym_type = parts[-2] if len(parts) == 3 else parts[0]
                            sym_name = parts[-1]
                            matches.append(f"{rel_path}: [{sym_type}] {sym_name}")
                            break  # Only report first match per file

            except Exception:
                continue  # Skip files that can't be processed

        if not matches:
            return f"No binaries found with symbol: {symbol_name}"

        return f"Found symbol '{symbol_name}' in {len(matches)} binaries:\n" + "\n".join(matches)

    except subprocess.TimeoutExpired:
        return "Error: Search timed out"
    except Exception as e:
        return f"Error searching binaries: {str(e)}"

# ============================================================================
# 5. CROSS-REFERENCE TOOLS
# ============================================================================

@tool
def find_function_references(function_name: str) -> str:
    """
    Find all references to a function across firmware (scripts, configs, binaries).

    Use this to trace where a function is:
    - Called in shell scripts
    - Referenced in configuration files
    - Imported/exported in binaries

    Args:
        function_name: Function name to search for

    Returns:
        All references with file paths, types, and context

    Examples:
        find_function_references("SSL_verify_callback") - Find custom callback usage
        find_function_references("SSL_CTX_set_verify") - Trace verification setup
        find_function_references("curl_setopt") - Find CURL configuration
    """
    try:
        results = []

        # 1. Search in text files (scripts, configs)
        text_result = search_files_by_content(function_name, max_results=50)
        if not text_result.startswith("No matches"):
            results.append("=== Text Files (scripts/configs) ===")
            results.append(text_result)

        # 2. Search in binaries
        binary_result = find_binaries_with_symbol(function_name)
        if not binary_result.startswith("No binaries"):
            results.append("\n=== Binary Files (executables/libraries) ===")
            results.append(binary_result)

        if not results:
            return f"No references found for function: {function_name}"

        return f"References to '{function_name}':\n\n" + "\n".join(results)

    except Exception as e:
        return f"Error finding references: {str(e)}"
