#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified network client scanner - detects various TLS/HTTP client library usage in ELF binaries.
Combines detection for: OpenSSL, libcurl, GnuTLS, mbed TLS, curl/wget CLI tools, and PHP curl.
"""

import argparse
import json
import os
import stat
from typing import List, Set, Dict, Tuple, Optional, Callable

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

# ============================================================================
# Library-specific indicator sets
# ============================================================================

# OpenSSL indicators
OPENSSL_STRONG: Set[str] = {
    "SSL_connect", "BIO_new_ssl_connect", "BIO_do_connect",
}
OPENSSL_CLIENT_METHODS: Set[str] = {
    "TLS_client_method", "DTLS_client_method", "SSLv23_client_method",
    "TLSv1_client_method", "TLSv1_1_client_method", "TLSv1_2_client_method",
}
OPENSSL_GENERIC_METHODS: Set[str] = {
    "TLS_method", "DTLS_method",
}
OPENSSL_STATE: Set[str] = {
    "SSL_set_connect_state",
}
OPENSSL_WEAK: Set[str] = {
    "SSL_set_tlsext_host_name", "SSL_set1_host", "X509_VERIFY_PARAM_set1_host",
    "SSL_CTX_set_verify", "SSL_set_verify", "SSL_set_fd", "SSL_set_bio",
}

# libcurl indicators
LIBCURL_STRONG: Set[str] = {
    "curl_easy_perform", "curl_multi_perform", "curl_easy_send", "curl_easy_recv",
}
LIBCURL_INIT: Set[str] = {
    "curl_easy_init", "curl_multi_init", "curl_global_init",
}
LIBCURL_SETOPT: Set[str] = {
    "curl_easy_setopt", "curl_multi_setopt", "curl_easy_setopt_array",
}
LIBCURL_INFO: Set[str] = {
    "curl_easy_getinfo", "curl_multi_info_read",
}
LIBCURL_WEAK: Set[str] = {
    "curl_easy_cleanup", "curl_multi_cleanup", "curl_global_cleanup",
    "curl_slist_append", "curl_slist_free_all", "curl_easy_strerror",
    "curl_multi_strerror", "curl_version", "curl_version_info",
    "curl_easy_escape", "curl_easy_unescape", "curl_free",
}

# GnuTLS indicators
GNUTLS_STRONG: Set[str] = {
    "gnutls_handshake", "gnutls_record_send", "gnutls_record_recv",
    "gnutls_record_send_early_data", "gnutls_record_recv_early_data",
}
GNUTLS_INIT: Set[str] = {
    "gnutls_init", "gnutls_global_init", "gnutls_global_init_extra",
}
GNUTLS_CLIENT_CONFIG: Set[str] = {
    "gnutls_credentials_set", "gnutls_certificate_allocate_credentials",
    "gnutls_certificate_set_x509_trust_file", "gnutls_certificate_set_x509_trust_dir",
    "gnutls_certificate_set_x509_system_trust", "gnutls_priority_set_direct",
    "gnutls_priority_init", "gnutls_server_name_set",
}
GNUTLS_VERIFICATION: Set[str] = {
    "gnutls_certificate_verify_peers2", "gnutls_certificate_verify_peers3",
    "gnutls_x509_crt_check_hostname", "gnutls_certificate_get_peers",
    "gnutls_ocsp_status_request_enable_client",
}
GNUTLS_WEAK: Set[str] = {
    "gnutls_deinit", "gnutls_global_deinit", "gnutls_bye", "gnutls_perror",
    "gnutls_strerror", "gnutls_check_version", "gnutls_transport_set_ptr",
    "gnutls_transport_set_int", "gnutls_session_set_data", "gnutls_session_get_data",
    "gnutls_cipher_get", "gnutls_protocol_get_version",
}

# mbed TLS indicators
MBEDTLS_STRONG: Set[str] = {
    "mbedtls_ssl_handshake", "mbedtls_ssl_write", "mbedtls_ssl_read",
    "mbedtls_ssl_send_alert_message",
}
MBEDTLS_INIT: Set[str] = {
    "mbedtls_ssl_init", "mbedtls_ssl_setup", "mbedtls_ssl_config_init",
    "mbedtls_ssl_config_defaults",
}
MBEDTLS_CLIENT_CONFIG: Set[str] = {
    "mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_ca_chain", "mbedtls_ssl_conf_own_cert",
    "mbedtls_ssl_conf_rng", "mbedtls_ssl_conf_min_version", "mbedtls_ssl_conf_max_version",
    "mbedtls_ssl_conf_ciphersuites", "mbedtls_ssl_set_hostname", "mbedtls_ssl_set_bio",
}
MBEDTLS_VERIFICATION: Set[str] = {
    "mbedtls_x509_crt_verify", "mbedtls_x509_crt_verify_with_profile",
    "mbedtls_x509_crt_check_extended_key_usage", "mbedtls_ssl_get_verify_result",
    "mbedtls_x509_crt_parse", "mbedtls_x509_crt_parse_file",
}
MBEDTLS_CRYPTO: Set[str] = {
    "mbedtls_ctr_drbg_init", "mbedtls_ctr_drbg_seed", "mbedtls_entropy_init",
    "mbedtls_entropy_func",
}
MBEDTLS_WEAK: Set[str] = {
    "mbedtls_ssl_free", "mbedtls_ssl_config_free", "mbedtls_ssl_close_notify",
    "mbedtls_ssl_session_reset", "mbedtls_strerror", "mbedtls_version_get_string",
    "mbedtls_x509_crt_init", "mbedtls_x509_crt_free", "mbedtls_ctr_drbg_free",
    "mbedtls_entropy_free",
}

# curl/wget CLI tool indicators (string-based)
CURL_WGET_TOOLS: Set[str] = {
    "curl", "wget", "/usr/bin/curl", "/usr/bin/wget", "/bin/curl", "/bin/wget",
}
CURL_WGET_URL_SCHEMES: Set[str] = {
    "http://", "https://", "ftp://", "ftps://",
}
CURL_WGET_CURL_INSECURE: Set[str] = {
    "-k", "--insecure", "--no-check-certificate", "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
}
CURL_WGET_WGET_INSECURE: Set[str] = {
    "--no-check-certificate", "--no-verify-peer", "--no-host-check",
}
CURL_WGET_CURL_OPTIONS: Set[str] = {
    "-X", "--request", "-d", "--data", "-H", "--header", "-o", "--output",
    "-O", "--remote-name", "-u", "--user",
}
CURL_WGET_WGET_OPTIONS: Set[str] = {
    "-O", "--output-document", "-P", "--directory-prefix", "-q", "--quiet",
    "-c", "--continue", "--user", "--password",
}

# PHP curl indicators (hybrid: symbols + strings)
PHP_CURL_FUNCTIONS: Set[str] = {
    "curl_init", "curl_exec", "curl_setopt", "curl_setopt_array", "curl_close",
    "curl_getinfo", "curl_error", "curl_errno", "curl_multi_init", "curl_multi_exec",
    "curl_multi_add_handle",
}
PHP_CURL_INTERNAL: Set[str] = {
    "php_curl_init", "php_curl_exec", "php_curl_setopt", "php_curl_close",
    "zif_curl_init", "zif_curl_exec", "zif_curl_setopt", "zif_curl_setopt_array",
    "zif_curl_close", "zif_curl_getinfo",
}
PHP_CURL_CURLOPT: Set[str] = {
    "CURLOPT_URL", "CURLOPT_RETURNTRANSFER", "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST", "CURLOPT_CAINFO", "CURLOPT_CAPATH",
    "CURLOPT_SSLVERSION", "CURLOPT_POST", "CURLOPT_POSTFIELDS",
    "CURLOPT_HTTPHEADER", "CURLOPT_FOLLOWLOCATION",
}
PHP_CURL_INSECURE: Set[str] = {
    "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST", "verify_peer", "verify_host",
}

PRINTABLE = set(range(0x20, 0x7F))  # ASCII printable

# ============================================================================
# Helper functions
# ============================================================================

def is_probably_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception:
        return False


def is_regular_file(path: str) -> bool:
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
    """
    Determine file type for appropriate library selection.
    Returns: "elf_binary", "php_script", "shell_script", or "other_script"
    """
    # Check if it's an ELF binary
    if is_probably_elf(path):
        return "elf_binary"

    # Check file extension
    if path.endswith('.php'):
        return "php_script"
    if path.endswith('.sh'):
        return "shell_script"

    # Check shebang for scripts
    try:
        with open(path, 'rb') as f:
            first_bytes = f.read(256)

        # Try to decode as text
        try:
            first_line = first_bytes.split(b'\n')[0].decode('utf-8', errors='ignore')
        except:
            return "unknown"

        # Check for shebangs
        if first_line.startswith('#!'):
            if 'php' in first_line.lower():
                return "php_script"
            if any(shell in first_line for shell in ['sh', 'bash', 'zsh', 'ksh']):
                return "shell_script"
            return "other_script"

        # Check for PHP opening tag
        if b'<?php' in first_bytes[:50]:
            return "php_script"

    except:
        pass

    return "unknown"


# ============================================================================
# Library applicability mapping
# ============================================================================

# Defines which file types each library can be detected in
LIBRARY_FILE_TYPES = {
    "openssl": ["elf_binary"],
    "libcurl": ["elf_binary"],
    "gnutls": ["elf_binary"],
    "mbedtls": ["elf_binary"],
    "curl_wget": ["elf_binary", "php_script", "shell_script", "other_script"],
    "php_curl": ["php_script"],  # ONLY PHP scripts, never ELF binaries
}


# ============================================================================
# Library-specific scoring functions
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
        insecure_flags = hits["curl_insecure"] + hits["wget_insecure"]
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

    # Determine file type to apply appropriate detection methods
    file_type = get_file_type(path)
    if file_type == "unknown":
        return None

    # Filter libraries to only those applicable to this file type
    applicable_libraries = []
    for lib_key in libraries:
        if file_type in LIBRARY_FILE_TYPES.get(lib_key, []):
            applicable_libraries.append(lib_key)

    # Skip if no applicable libraries for this file type
    if not applicable_libraries:
        return None

    # Determine what to extract based on applicable libraries
    need_symbols = any(LIBRARIES[lib]["detection_method"] in ("symbols", "both") for lib in applicable_libraries)
    need_strings = any(LIBRARIES[lib]["detection_method"] in ("strings", "both") for lib in applicable_libraries)

    symbols = extract_symbols(path) if need_symbols else set()
    strings = extract_strings(path, minlen=min_strlen) if need_strings else set()

    # Scan with each applicable library
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

    return {
        "path": path,
        "file_type": file_type,
        "libraries": results,
    }


def walk_and_scan(root: str, libraries: List[str], min_strlen: int) -> List[Dict]:
    """Recursively scan directory for network clients."""
    results: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            item = scan_file(fp, libraries, min_strlen)
            if item:
                results.append(item)
    return results


# ============================================================================
# CLI and output
# ============================================================================

def print_human_readable(findings: List[Dict]):
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


def main():
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
    args = ap.parse_args()

    # Resolve library list
    if 'all' in args.libraries:
        libraries = list(LIBRARIES.keys())
    else:
        libraries = args.libraries

    # Scan
    findings = walk_and_scan(args.root, libraries, args.min_strlen)

    # Output
    if args.json:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    else:
        if not findings:
            print(f"No network clients detected in {args.root}")
        else:
            print(f"Found {len(findings)} file(s) with network client usage:\n")
            print_human_readable(findings)

    # Exit status: 0 if anything found, 1 if nothing
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
