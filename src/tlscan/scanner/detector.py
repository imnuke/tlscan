"""Library detection and scoring for network clients.

Provides functions to detect SSL/TLS library usage in binary files
using symbol and string analysis.
"""

import os
import stat
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

from .indicators import (
    DEFAULT_IGNORE_FILES,
    LIBRARY_FILE_TYPES,
    PRINTABLE,
    # OpenSSL
    OPENSSL_STRONG, OPENSSL_CLIENT_METHODS, OPENSSL_GENERIC_METHODS,
    OPENSSL_STATE, OPENSSL_WEAK,
    # libcurl
    LIBCURL_STRONG, LIBCURL_INIT, LIBCURL_SETOPT, LIBCURL_INFO, LIBCURL_WEAK,
    # GnuTLS
    GNUTLS_STRONG, GNUTLS_INIT, GNUTLS_CLIENT_CONFIG, GNUTLS_VERIFICATION, GNUTLS_WEAK,
    # mbedTLS
    MBEDTLS_STRONG, MBEDTLS_INIT, MBEDTLS_CLIENT_CONFIG, MBEDTLS_VERIFICATION,
    MBEDTLS_CRYPTO, MBEDTLS_WEAK,
    # curl/wget CLI
    CURL_WGET_TOOLS, CURL_WGET_URL_SCHEMES, CURL_WGET_CURL_INSECURE,
    CURL_WGET_WGET_INSECURE, CURL_WGET_CURL_OPTIONS, CURL_WGET_WGET_OPTIONS,
    # PHP curl
    PHP_CURL_FUNCTIONS, PHP_CURL_INTERNAL, PHP_CURL_CURLOPT, PHP_CURL_INSECURE,
)
from .version import detect_library_version, scan_firmware_libraries


# ============================================================================
# Helper functions
# ============================================================================

def is_probably_elf(path: str) -> bool:
    """Check if file is likely an ELF binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception:
        return False


def is_regular_file(path: str) -> bool:
    """Check if path is a regular file."""
    try:
        st = os.lstat(path)
        return stat.S_ISREG(st.st_mode)
    except Exception:
        return False


def extract_symbols(path: str) -> Set[str]:
    """Collect imported (undefined) symbol names from .dynsym and .symtab."""
    names: Set[str] = set()
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    if sym['st_shndx'] == 'SHN_UNDEF':
                        nm = sym.name
                        if nm:
                            names.add(nm)
    except Exception:
        pass
    return names


def extract_strings(path: str, minlen: int = 4, maxsize_mb: int = 64) -> Set[str]:
    """Collect printable ASCII substrings from binary."""
    res: Set[str] = set()
    try:
        size = os.path.getsize(path)
        if size > maxsize_mb * 1024 * 1024:
            return res

        with open(path, "rb") as f:
            buf = f.read()

        cur: List[int] = []
        for b in buf:
            if b in PRINTABLE:
                cur.append(b)
            else:
                if len(cur) >= minlen:
                    try:
                        s = bytes(cur).decode("ascii", errors="ignore")
                        if s:
                            res.add(s)
                    except Exception:
                        pass
                cur = []
        if len(cur) >= minlen:
            try:
                s = bytes(cur).decode("ascii", errors="ignore")
                if s:
                    res.add(s)
            except Exception:
                pass
    except Exception:
        pass
    return res


def contains_substring(corpus: Set[str], target: str) -> bool:
    """Check if any string in corpus contains the target substring."""
    for s in corpus:
        if target in s:
            return True
    return False


def get_file_type(path: str) -> str:
    """Determine file type for appropriate library selection."""
    if is_probably_elf(path):
        return "elf_binary"

    if path.endswith('.php'):
        return "php_script"
    if path.endswith('.sh'):
        return "shell_script"

    try:
        with open(path, 'rb') as f:
            first_bytes = f.read(256)

        try:
            first_line = first_bytes.split(b'\n')[0].decode('utf-8', errors='ignore')
        except:
            return "unknown"

        if first_line.startswith('#!'):
            if 'php' in first_line.lower():
                return "php_script"
            if any(shell in first_line for shell in ['sh', 'bash', 'zsh', 'ksh']):
                return "shell_script"
            return "other_script"

        if b'<?php' in first_bytes[:50]:
            return "php_script"

    except:
        pass

    return "unknown"


def should_ignore_file(path: str) -> bool:
    """Check if file should be ignored based on DEFAULT_IGNORE_FILES."""
    basename = os.path.basename(path)
    for pattern in DEFAULT_IGNORE_FILES:
        if pattern in basename:
            return True
    return False


# ============================================================================
# Scoring functions
# ============================================================================

def score_openssl(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score OpenSSL client usage."""
    hits = {
        "strong": [k for k in OPENSSL_STRONG if k in symbols],
        "client_methods": [k for k in OPENSSL_CLIENT_METHODS if k in symbols],
        "generic_methods": [k for k in OPENSSL_GENERIC_METHODS if k in symbols],
        "state": [k for k in OPENSSL_STATE if k in symbols],
        "weak": [k for k in OPENSSL_WEAK if k in symbols],
    }

    if hits["strong"]:
        return ("high", f"Found strong client connector(s): {', '.join(sorted(hits['strong']))}", hits)
    if hits["generic_methods"] and (hits["state"] or hits["strong"]):
        return ("high", f"Generic method + client state/connect", hits)
    if hits["client_methods"]:
        return ("medium", f"Found client method(s): {', '.join(sorted(hits['client_methods']))}", hits)
    if len(hits["weak"]) >= 2:
        return ("low", f"Multiple weak client-leaning indicators: {', '.join(sorted(hits['weak']))}", hits)
    return ("none", "No sufficient indicators", hits)


def score_libcurl(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score libcurl client usage."""
    hits = {
        "strong": [k for k in LIBCURL_STRONG if k in symbols],
        "init": [k for k in LIBCURL_INIT if k in symbols],
        "setopt": [k for k in LIBCURL_SETOPT if k in symbols],
        "info": [k for k in LIBCURL_INFO if k in symbols],
        "weak": [k for k in LIBCURL_WEAK if k in symbols],
    }

    if hits["strong"]:
        return ("high", f"Found strong client transfer function(s): {', '.join(sorted(hits['strong']))}", hits)
    if hits["init"] and hits["setopt"]:
        return ("high", f"Client setup pattern: init + setopt", hits)
    if hits["init"] and hits["info"]:
        return ("medium", f"Client info retrieval pattern: init + info", hits)
    if hits["init"]:
        return ("low", f"Only initialization found: {', '.join(sorted(hits['init']))}", hits)
    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak libcurl indicators", hits)
    return ("none", "No sufficient indicators", hits)


def score_gnutls(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score GnuTLS client usage."""
    hits = {
        "strong": [k for k in GNUTLS_STRONG if k in symbols],
        "init": [k for k in GNUTLS_INIT if k in symbols],
        "client_config": [k for k in GNUTLS_CLIENT_CONFIG if k in symbols],
        "verification": [k for k in GNUTLS_VERIFICATION if k in symbols],
        "weak": [k for k in GNUTLS_WEAK if k in symbols],
    }

    if hits["strong"]:
        return ("high", f"Found strong TLS handshake/transfer function(s): {', '.join(sorted(hits['strong']))}", hits)
    if hits["init"] and hits["client_config"]:
        return ("high", f"Client setup pattern: init + config", hits)
    if hits["init"] and hits["verification"]:
        return ("high", f"Client verification pattern: init + verify", hits)
    if hits["init"] and hits["weak"]:
        return ("medium", f"Basic GnuTLS usage: init + utilities", hits)
    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak GnuTLS indicators", hits)
    return ("none", "No sufficient indicators", hits)


def score_mbedtls(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score mbed TLS client usage."""
    hits = {
        "strong": [k for k in MBEDTLS_STRONG if k in symbols],
        "init": [k for k in MBEDTLS_INIT if k in symbols],
        "client_config": [k for k in MBEDTLS_CLIENT_CONFIG if k in symbols],
        "verification": [k for k in MBEDTLS_VERIFICATION if k in symbols],
        "crypto": [k for k in MBEDTLS_CRYPTO if k in symbols],
        "weak": [k for k in MBEDTLS_WEAK if k in symbols],
    }

    if hits["strong"]:
        return ("high", f"Found strong TLS handshake/transfer function(s): {', '.join(sorted(hits['strong']))}", hits)
    if hits["init"] and hits["client_config"] and hits["crypto"]:
        return ("high", f"Complete client setup: init + config + crypto", hits)
    if hits["init"] and hits["verification"]:
        return ("high", f"Client verification pattern: init + verify", hits)
    if hits["init"] and hits["crypto"]:
        return ("medium", f"Basic mbed TLS setup: init + crypto initialization", hits)
    if hits["init"]:
        return ("low", f"Only initialization found: {', '.join(sorted(hits['init']))}", hits)
    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak mbed TLS indicators", hits)
    return ("none", "No sufficient indicators", hits)


def score_curl_wget(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score curl/wget CLI tool usage."""
    hits = {
        "tools": [k for k in CURL_WGET_TOOLS if contains_substring(strings, k)],
        "urls": [k for k in CURL_WGET_URL_SCHEMES if contains_substring(strings, k)],
        "curl_insecure": [k for k in CURL_WGET_CURL_INSECURE if contains_substring(strings, k)],
        "wget_insecure": [k for k in CURL_WGET_WGET_INSECURE if contains_substring(strings, k)],
        "curl_options": [k for k in CURL_WGET_CURL_OPTIONS if k in strings],
        "wget_options": [k for k in CURL_WGET_WGET_OPTIONS if k in strings],
    }

    has_tool = len(hits["tools"]) > 0
    has_url = len(hits["urls"]) > 0
    has_insecure = len(hits["curl_insecure"]) > 0 or len(hits["wget_insecure"]) > 0
    has_options = len(hits["curl_options"]) + len(hits["wget_options"]) >= 2

    tool_name = "unknown"
    if any("curl" in t for t in hits["tools"]):
        tool_name = "curl"
    elif any("wget" in t for t in hits["tools"]):
        tool_name = "wget"

    if has_tool and has_url and has_insecure:
        return ("high", f"SECURITY RISK: {tool_name} with URL and insecure flags", hits)
    if has_tool and has_url and has_options:
        return ("high", f"Active {tool_name} usage with URLs and options detected", hits)
    if has_tool and has_url:
        return ("medium", f"Command-line HTTP client usage: {tool_name}", hits)
    if has_tool:
        return ("low", f"Tool command strings found: {', '.join(sorted(hits['tools']))}", hits)
    if has_url:
        return ("low", f"URL schemes found but no tool commands", hits)
    return ("none", "No sufficient indicators", hits)


def score_php_curl(symbols: Set[str], strings: Set[str]) -> Tuple[str, str, Dict[str, List[str]]]:
    """Score PHP curl extension usage."""
    hits = {
        "php_functions": [k for k in PHP_CURL_FUNCTIONS if contains_substring(strings, k)],
        "php_internal": [k for k in PHP_CURL_INTERNAL if k in symbols],
        "curlopt_constants": [k for k in PHP_CURL_CURLOPT if contains_substring(strings, k)],
        "insecure_patterns": [k for k in PHP_CURL_INSECURE if contains_substring(strings, k)],
    }

    has_internal = len(hits["php_internal"]) > 0
    has_functions = len(hits["php_functions"]) >= 2
    has_curlopt = len(hits["curlopt_constants"]) >= 2
    has_insecure = len(hits["insecure_patterns"]) > 0

    if has_internal:
        return ("high", f"PHP curl extension internals detected", hits)
    if has_functions and has_curlopt:
        if has_insecure:
            return ("high", f"SECURITY RISK: PHP curl with insecure patterns", hits)
        return ("high", f"PHP curl usage detected: {len(hits['php_functions'])} functions, {len(hits['curlopt_constants'])} options", hits)
    if has_functions:
        return ("medium", f"PHP curl functions detected: {', '.join(sorted(hits['php_functions'][:3]))}", hits)
    if has_curlopt:
        return ("low", f"CURLOPT constants found but no clear PHP curl usage", hits)
    return ("none", "No sufficient indicators", hits)


# ============================================================================
# Library configuration
# ============================================================================

LIBRARIES = {
    "openssl": {
        "name": "OpenSSL",
        "description": "OpenSSL TLS/SSL client connections",
        "detection_method": "symbols",
        "scorer": score_openssl,
    },
    "libcurl": {
        "name": "libcurl",
        "description": "libcurl HTTP/HTTPS client library",
        "detection_method": "symbols",
        "scorer": score_libcurl,
    },
    "gnutls": {
        "name": "GnuTLS",
        "description": "GnuTLS TLS client library",
        "detection_method": "symbols",
        "scorer": score_gnutls,
    },
    "mbedtls": {
        "name": "mbed TLS",
        "description": "mbed TLS (formerly PolarSSL) client library",
        "detection_method": "symbols",
        "scorer": score_mbedtls,
    },
    "curl_wget": {
        "name": "curl/wget",
        "description": "curl and wget command-line tools",
        "detection_method": "strings",
        "scorer": score_curl_wget,
    },
    "php_curl": {
        "name": "PHP curl",
        "description": "PHP curl extension",
        "detection_method": "both",
        "scorer": score_php_curl,
    },
}


# ============================================================================
# Main scanning logic
# ============================================================================

def scan_file(path: str, libraries: List[str], min_strlen: int) -> Optional[Dict]:
    """Scan a single file for network client usage."""
    if not is_regular_file(path):
        return None

    if should_ignore_file(path):
        return None

    file_type = get_file_type(path)
    if file_type == "unknown":
        return None

    applicable_libraries = []
    for lib_key in libraries:
        if file_type in LIBRARY_FILE_TYPES.get(lib_key, []):
            applicable_libraries.append(lib_key)

    if not applicable_libraries:
        return None

    need_symbols = any(LIBRARIES[lib]["detection_method"] in ("symbols", "both") for lib in applicable_libraries)
    need_strings = any(LIBRARIES[lib]["detection_method"] in ("strings", "both") for lib in applicable_libraries)

    symbols = extract_symbols(path) if need_symbols else set()
    strings = extract_strings(path, minlen=min_strlen) if need_strings else set()

    results = {}
    for lib_key in applicable_libraries:
        lib_config = LIBRARIES[lib_key]
        level, rationale, hits = lib_config["scorer"](symbols, strings)

        if level != "none":
            results[lib_key] = {
                "library": lib_config["name"],
                "level": level,
                "rationale": rationale,
                "hits": hits,
            }

    if not results:
        return None

    version_info = {}
    if file_type == "elf_binary":
        for lib_key in results:
            version_lib_type = lib_key
            if lib_key == "curl_wget":
                continue

            ver = detect_library_version(path, version_lib_type, symbols)
            if ver:
                version_info[lib_key] = ver

    return {
        "path": path,
        "file_type": file_type,
        "libraries": results,
        "versions": version_info if version_info else None,
    }


def walk_and_scan(root: str, libraries: List[str], min_strlen: int) -> Tuple[List[Dict], Dict[str, Dict[str, Any]]]:
    """Recursively scan directory for network clients and library versions."""
    results: List[Dict] = []

    firmware_versions = scan_firmware_libraries(root)

    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            item = scan_file(fp, libraries, min_strlen)
            if item:
                results.append(item)

    return results, firmware_versions
