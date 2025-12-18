#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified network client scanner - detects various TLS/HTTP client library usage in ELF binaries.
Combines detection for: OpenSSL, libcurl, GnuTLS, mbed TLS, curl/wget CLI tools, and PHP curl.
"""

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional, Callable, Any

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.gnuversions import GNUVerNeedSection, GNUVerDefSection
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

# ============================================================================
# Default ignore list
# ============================================================================

# Files to ignore - libraries that export functions (not import them) and noisy binaries
DEFAULT_IGNORE_FILES = [
    "busybox",        # Multi-call binary, too noisy
    "wget",           # The wget tool itself
    "curl",           # The curl tool itself
    "openvpn",        # OpenVPN binary
    "openssl",        # OpenSSL binary
    "libssl.so",      # OpenSSL library (exports SSL functions)
    "libcrypto.so",   # OpenSSL crypto library
    "libcurl.so",     # curl library (exports curl functions)
    "libgnutls.so",   # GnuTLS library
    "libmbedtls.so",  # mbed TLS library
    "libmbedcrypto",  # mbed crypto library
    "libc.so",        # Standard C library
    "ld-linux",       # Dynamic linker
]

# ============================================================================
# Version Detection Patterns
# ============================================================================

# Regex patterns for extracting version strings from binaries
VERSION_STRING_PATTERNS: Dict[str, List[Tuple[re.Pattern, str]]] = {
    "openssl": [
        (re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"), "OpenSSL"),
        (re.compile(rb"OpenSSL/(\d+\.\d+\.\d+)"), "OpenSSL"),
    ],
    "libcurl": [
        (re.compile(rb"libcurl/(\d+\.\d+\.\d+)"), "libcurl"),
        (re.compile(rb"curl\s+(\d+\.\d+\.\d+)"), "curl"),
    ],
    "gnutls": [
        (re.compile(rb"GnuTLS\s+(\d+\.\d+\.\d+)"), "GnuTLS"),
        (re.compile(rb"gnutls\s+(\d+\.\d+\.\d+)"), "gnutls"),
    ],
    "mbedtls": [
        (re.compile(rb"mbed\s*TLS\s+(\d+\.\d+\.\d+)", re.IGNORECASE), "mbedTLS"),
        (re.compile(rb"mbedtls[-_](\d+\.\d+\.\d+)"), "mbedTLS"),
    ],
    "curl_cli": [
        (re.compile(rb"curl\s+(\d+\.\d+\.\d+)"), "curl"),
    ],
    "wget_cli": [
        (re.compile(rb"GNU\s+Wget\s+(\d+\.\d+\.\d+)"), "wget"),
        (re.compile(rb"GNU\s+Wget\s+(\d+\.\d+)"), "wget"),
        # Version in build/source path (common in firmware)
        (re.compile(rb"wget-(\d+\.\d+\.\d+)"), "wget"),
    ],
}

# SONAME patterns for library identification and version extraction
SONAME_LIBRARY_MAP: Dict[str, str] = {
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcurl": "libcurl",
    "libgnutls": "gnutls",
    "libmbedtls": "mbedtls",
    "libmbedcrypto": "mbedtls",
}

# Version-specific API indicators (presence implies minimum version)
VERSION_SPECIFIC_APIS: Dict[str, Dict[str, str]] = {
    "openssl": {
        "SSL_CTX_set_min_proto_version": "1.1.0",
        "SSL_CTX_set_max_proto_version": "1.1.0",
        "SSL_set1_host": "1.1.0",
        "TLS_client_method": "1.1.0",
        "SSL_CTX_set_ciphersuites": "1.1.1",
        "SSL_CTX_set_post_handshake_auth": "1.1.1",
    },
    "libcurl": {
        "curl_easy_option_by_id": "7.73.0",
        "curl_easy_option_by_name": "7.73.0",
        "curl_url": "7.62.0",
    },
}

# Library file patterns for firmware scanning
LIBRARY_FILE_PATTERNS: List[Tuple[str, str]] = [
    ("**/libssl.so*", "openssl"),
    ("**/libcrypto.so*", "openssl"),
    ("**/libcurl.so*", "libcurl"),
    ("**/libgnutls.so*", "gnutls"),
    ("**/libmbedtls.so*", "mbedtls"),
    ("**/libmbedcrypto.so*", "mbedtls"),
    # CLI tools
    ("**/bin/curl", "curl_cli"),
    ("**/bin/wget", "wget_cli"),
    ("**/sbin/curl", "curl_cli"),
    ("**/sbin/wget", "wget_cli"),
]


# ============================================================================
# Version Detection Functions
# ============================================================================

def extract_soname(path: str) -> Optional[str]:
    """Extract SONAME from ELF dynamic section.

    Args:
        path: Path to ELF binary

    Returns:
        SONAME string (e.g., 'libssl.so.1.1') or None
    """
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_SONAME':
                            return tag.soname
    except Exception:
        pass
    return None


def extract_verneed_versions(path: str) -> Dict[str, List[str]]:
    """Extract required version symbols from VERNEED section.

    This shows which library versions the binary requires.

    Args:
        path: Path to ELF binary

    Returns:
        Dict mapping library name to list of required version tags
        Example: {'libssl.so.1.1': ['OPENSSL_1_1_0', 'OPENSSL_1_1_1']}
    """
    result: Dict[str, List[str]] = {}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, GNUVerNeedSection):
                    for verneed, vernaux_iter in section.iter_versions():
                        lib_name = verneed.name
                        versions = [vernaux.name for vernaux in vernaux_iter]
                        result[lib_name] = versions
    except Exception:
        pass
    return result


def extract_verdef_versions(path: str) -> List[str]:
    """Extract exported version definitions from VERDEF section.

    This shows which versions the library exports (for library files).

    Args:
        path: Path to ELF library

    Returns:
        List of version definition tags
        Example: ['OPENSSL_1_0_0', 'OPENSSL_1_1_0', 'OPENSSL_1_1_1']
    """
    versions: List[str] = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, GNUVerDefSection):
                    for verdef, verdaux_iter in section.iter_versions():
                        verdaux = next(verdaux_iter)
                        versions.append(verdaux.name)
    except Exception:
        pass
    return versions


def extract_version_string(path: str, lib_type: str) -> Optional[Dict[str, Any]]:
    """Extract version string from binary's string data.

    Args:
        path: Path to binary/library
        lib_type: Library type to search for (e.g., 'openssl', 'libcurl')

    Returns:
        Dict with version info or None
    """
    if lib_type not in VERSION_STRING_PATTERNS:
        return None

    try:
        with open(path, "rb") as f:
            data = f.read()

        for pattern, name in VERSION_STRING_PATTERNS[lib_type]:
            match = pattern.search(data)
            if match:
                version_str = match.group(1).decode('ascii', errors='ignore')
                parsed = parse_version_string(version_str)
                return {
                    "version": version_str,
                    "confidence": "high",
                    "method": "version_string",
                    "details": f"Found: {match.group(0).decode('ascii', errors='ignore')}",
                    **parsed,
                }
    except Exception:
        pass
    return None


def parse_version_string(version: str) -> Dict[str, Any]:
    """Parse version string into components.

    Args:
        version: Version string like '1.1.1k', '7.68.0', '3.6.14'

    Returns:
        Dict with version_major, version_minor, version_patch
    """
    result: Dict[str, Any] = {}
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?([a-z])?", version)
    if match:
        result['version_major'] = int(match.group(1))
        result['version_minor'] = int(match.group(2))
        if match.group(3):
            result['version_patch'] = int(match.group(3))
        if match.group(4):
            result['version_suffix'] = match.group(4)
    return result


def parse_verneed_version(version_tags: List[str], lib_type: str) -> Optional[str]:
    """Parse VERNEED version tags to determine minimum required version.

    Args:
        version_tags: List of version tags like ['OPENSSL_1_1_0', 'OPENSSL_1_1_1']
        lib_type: Library type

    Returns:
        Highest required version string or None
    """
    highest_version: Optional[str] = None

    for tag in version_tags:
        version = None

        if lib_type == "openssl":
            # Parse OPENSSL_1_1_0, OPENSSL_1_0_2, etc.
            match = re.match(r"OPENSSL_(\d+)_(\d+)_(\d+)", tag)
            if match:
                version = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"

        elif lib_type == "gnutls":
            # Parse GNUTLS_3_4, GNUTLS_3_6_0, etc.
            match = re.match(r"GNUTLS_(\d+)_(\d+)(?:_(\d+))?", tag)
            if match:
                if match.group(3):
                    version = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
                else:
                    version = f"{match.group(1)}.{match.group(2)}.0"

        if version:
            if not highest_version or compare_versions(version, highest_version) > 0:
                highest_version = version

    return highest_version


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        >0 if v1 > v2, <0 if v1 < v2, 0 if equal
    """
    def parse(v: str) -> List[int]:
        parts = re.findall(r'\d+', v)
        return [int(p) for p in parts] if parts else [0]

    p1, p2 = parse(v1), parse(v2)
    for a, b in zip(p1, p2):
        if a != b:
            return a - b
    return len(p1) - len(p2)


def confidence_rank(confidence: str) -> int:
    """Rank confidence levels for comparison."""
    return {"high": 3, "medium": 2, "low": 1, "none": 0}.get(confidence, 0)


def identify_library_type(name: str) -> Optional[str]:
    """Identify library type from filename or SONAME.

    Args:
        name: Filename or SONAME (e.g., 'libssl.so.1.1', '/usr/lib/libcurl.so.4')

    Returns:
        Library type ('openssl', 'libcurl', etc.) or None
    """
    basename = Path(name).name.lower()
    for prefix, lib_type in SONAME_LIBRARY_MAP.items():
        if basename.startswith(prefix):
            return lib_type
    return None


def extract_soname_version(soname: str, lib_type: str) -> Optional[Dict[str, Any]]:
    """Extract version from SONAME.

    Args:
        soname: SONAME like 'libssl.so.1.1', 'libcurl.so.4'
        lib_type: Library type

    Returns:
        Version info dict or None
    """
    # Pattern: libname.so.X.Y or libname.so.X
    match = re.search(r"\.so\.(\d+)(?:\.(\d+))?(?:\.(\d+))?", soname)
    if match:
        parts = [g for g in match.groups() if g]
        version = ".".join(parts)

        return {
            "version": version,
            "confidence": "medium",
            "method": "soname",
            "soname": soname,
            "details": f"From SONAME: {soname}",
        }
    return None


def detect_library_version(path: str, lib_type: str, symbols: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
    """Detect library version using multiple methods.

    Priority order:
    1. Version strings (high confidence)
    2. VERNEED sections (medium confidence)
    3. SONAME (medium confidence, for library files)
    4. API inference from imports (low confidence)

    Args:
        path: Path to binary/library
        lib_type: Library type to detect
        symbols: Optional pre-extracted symbols (for API inference)

    Returns:
        Version info dict with best detection result
    """
    # Method 1: Version strings (highest confidence)
    version_info = extract_version_string(path, lib_type)
    if version_info and version_info.get("confidence") == "high":
        return version_info

    # Method 2: VERNEED (for binaries linking against libraries)
    verneed = extract_verneed_versions(path)
    for lib_name, version_tags in verneed.items():
        detected_type = identify_library_type(lib_name)
        if detected_type == lib_type:
            version = parse_verneed_version(version_tags, lib_type)
            if version:
                return {
                    "version": f">={version}",
                    "confidence": "medium",
                    "method": "verneed",
                    "soname": lib_name,
                    "required_symbols": version_tags,
                    "details": f"Required versions: {', '.join(version_tags)}",
                }

    # Method 3: SONAME (for library files)
    soname = extract_soname(path)
    if soname:
        detected_type = identify_library_type(soname)
        if detected_type == lib_type:
            soname_version = extract_soname_version(soname, lib_type)
            if soname_version:
                return soname_version

    # Method 4: API inference from imports (lowest confidence)
    if symbols and lib_type in VERSION_SPECIFIC_APIS:
        api_map = VERSION_SPECIFIC_APIS[lib_type]
        min_version = None
        evidence = []

        for api, version in api_map.items():
            if api in symbols:
                evidence.append(f"{api} (requires {version}+)")
                if not min_version or compare_versions(version, min_version) > 0:
                    min_version = version

        if min_version:
            return {
                "version": f">={min_version}",
                "confidence": "low",
                "method": "api_inference",
                "details": "; ".join(evidence),
            }

    # Return version string result even if not high confidence
    if version_info:
        return version_info

    return None


def scan_firmware_libraries(root: str) -> Dict[str, Dict[str, Any]]:
    """Scan firmware for library files and extract their versions.

    Args:
        root: Firmware root directory

    Returns:
        Dict mapping library type to version info
    """
    result: Dict[str, Dict[str, Any]] = {}
    root_path = Path(root)

    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        for lib_path in root_path.glob(pattern):
            # Skip symlinks to avoid duplicates
            if lib_path.is_symlink():
                continue
            if not lib_path.is_file():
                continue

            # Detect version
            version_info = detect_library_version(str(lib_path), lib_type)
            if version_info:
                # Add source path (relative to firmware root)
                try:
                    version_info["source_path"] = str(lib_path.relative_to(root_path))
                except ValueError:
                    version_info["source_path"] = str(lib_path)

                # Update if higher confidence or not yet present
                if lib_type not in result:
                    result[lib_type] = version_info
                elif confidence_rank(version_info.get("confidence", "none")) > \
                     confidence_rank(result[lib_type].get("confidence", "none")):
                    result[lib_type] = version_info

    # Also check for VERDEF in library files
    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        if lib_type in result:
            continue  # Already have version

        for lib_path in root_path.glob(pattern):
            if lib_path.is_symlink() or not lib_path.is_file():
                continue

            verdef_versions = extract_verdef_versions(str(lib_path))
            if verdef_versions:
                highest = parse_verneed_version(verdef_versions, lib_type)
                if highest:
                    try:
                        source_path = str(lib_path.relative_to(root_path))
                    except ValueError:
                        source_path = str(lib_path)

                    result[lib_type] = {
                        "version": highest,
                        "confidence": "medium",
                        "method": "verdef",
                        "source_path": source_path,
                        "exported_versions": verdef_versions[:10],  # Limit for output
                        "details": f"Exported versions: {', '.join(verdef_versions[:5])}",
                    }
                    break

    return result


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


def should_ignore_file(path: str) -> bool:
    """
    Check if file should be ignored based on DEFAULT_IGNORE_FILES.
    Uses substring matching on the basename.
    """
    basename = os.path.basename(path)
    for pattern in DEFAULT_IGNORE_FILES:
        if pattern in basename:
            return True
    return False


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

    # Skip ignored files (libraries that export functions, not import them)
    if should_ignore_file(path):
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

    # Detect library versions for found libraries (ELF binaries only)
    version_info = {}
    if file_type == "elf_binary":
        for lib_key in results:
            # Map library key to version detection type
            version_lib_type = lib_key
            if lib_key == "curl_wget":
                # For curl/wget CLI detection, skip version detection
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
    """Recursively scan directory for network clients and library versions.

    Args:
        root: Root directory to scan
        libraries: List of library types to scan for
        min_strlen: Minimum string length for string-based detection

    Returns:
        Tuple of (findings, firmware_library_versions)
    """
    results: List[Dict] = []

    # First, scan for firmware library files to get firmware-level versions
    firmware_versions = scan_firmware_libraries(root)

    # Then scan binaries for network client usage
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            item = scan_file(fp, libraries, min_strlen)
            if item:
                results.append(item)

    return results, firmware_versions


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


def save_to_cache(root: str, findings: List[Dict], firmware_versions: Dict[str, Dict[str, Any]]) -> None:
    """Save scan results to firmware cache directory.

    Creates .conn_analyzer/ directory in firmware root and saves:
    - library_versions.json: Library version information
    - network_clients.json: Network client findings

    Args:
        root: Firmware root directory
        findings: List of network client findings
        firmware_versions: Dict of firmware library versions
    """
    from datetime import datetime

    cache_dir = Path(root) / ".conn_analyzer"
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
  %(prog)s /path/to/firmware --save-cache  # Save to .conn_analyzer/
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
                   help="Save results to .conn_analyzer/ directory in firmware root")
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
                print(f"  {lib_type}: {version} ({confidence} confidence, {method})")
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
