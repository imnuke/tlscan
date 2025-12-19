"""Version detection for SSL/TLS libraries.

Provides functions to extract library version information from ELF binaries
using multiple detection methods: version strings, SONAME, VERNEED/VERDEF, and API inference.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Set

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.gnuversions import GNUVerNeedSection, GNUVerDefSection
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

from .backend import detect_ssl_backend

# ============================================================================
# Version Detection Patterns
# ============================================================================

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
        (re.compile(rb"wget-(\d+\.\d+\.\d+)"), "wget"),
    ],
}

SONAME_LIBRARY_MAP: Dict[str, str] = {
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcurl": "libcurl",
    "libgnutls": "gnutls",
    "libmbedtls": "mbedtls",
    "libmbedcrypto": "mbedtls",
}

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

LIBRARY_FILE_PATTERNS: List[Tuple[str, str]] = [
    ("**/libssl.so*", "openssl"),
    ("**/libcrypto.so*", "openssl"),
    ("**/libcurl.so*", "libcurl"),
    ("**/libgnutls.so*", "gnutls"),
    ("**/libmbedtls.so*", "mbedtls"),
    ("**/libmbedcrypto.so*", "mbedtls"),
    ("**/bin/curl", "curl_cli"),
    ("**/bin/wget", "wget_cli"),
    ("**/sbin/curl", "curl_cli"),
    ("**/sbin/wget", "wget_cli"),
]


# ============================================================================
# Version Detection Functions
# ============================================================================

def extract_soname(path: str) -> Optional[str]:
    """Extract SONAME from ELF dynamic section."""
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
    """Extract required version symbols from VERNEED section."""
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
    """Extract exported version definitions from VERDEF section."""
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
    """Extract version string from binary's string data."""
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
    """Parse version string into components."""
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
    """Parse VERNEED version tags to determine minimum required version."""
    highest_version: Optional[str] = None

    for tag in version_tags:
        version = None

        if lib_type == "openssl":
            match = re.match(r"OPENSSL_(\d+)_(\d+)_(\d+)", tag)
            if match:
                version = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"

        elif lib_type == "gnutls":
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
    """Compare two version strings. Returns >0 if v1 > v2, <0 if v1 < v2, 0 if equal."""
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
    """Identify library type from filename or SONAME."""
    basename = Path(name).name.lower()
    for prefix, lib_type in SONAME_LIBRARY_MAP.items():
        if basename.startswith(prefix):
            return lib_type
    return None


def extract_soname_version(soname: str, lib_type: str) -> Optional[Dict[str, Any]]:
    """Extract version from SONAME."""
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

    Priority: version strings (high) > VERNEED (medium) > SONAME (medium) > API inference (low)
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
    """Scan firmware for library files and extract their versions."""
    result: Dict[str, Dict[str, Any]] = {}
    root_path = Path(root)

    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        for lib_path in root_path.glob(pattern):
            if lib_path.is_symlink():
                continue
            if not lib_path.is_file():
                continue

            version_info = detect_library_version(str(lib_path), lib_type)
            if version_info:
                try:
                    version_info["source_path"] = str(lib_path.relative_to(root_path))
                except ValueError:
                    version_info["source_path"] = str(lib_path)

                if lib_type not in result:
                    result[lib_type] = version_info
                elif confidence_rank(version_info.get("confidence", "none")) > \
                     confidence_rank(result[lib_type].get("confidence", "none")):
                    result[lib_type] = version_info

    # Also check for VERDEF in library files
    for pattern, lib_type in LIBRARY_FILE_PATTERNS:
        if lib_type in result:
            continue

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
                        "exported_versions": verdef_versions[:10],
                        "details": f"Exported versions: {', '.join(verdef_versions[:5])}",
                    }
                    break

    # Detect SSL backend for libcurl, curl_cli, and wget_cli
    for lib_type in ["libcurl", "curl_cli", "wget_cli"]:
        if lib_type in result:
            source_path = result[lib_type].get("source_path", "")
            if source_path:
                lib_path = root_path / source_path
                if lib_path.exists():
                    backend = detect_ssl_backend(str(lib_path))
                    if backend:
                        result[lib_type]["backend"] = {
                            "name": backend.name,
                            "version": backend.version,
                            "confidence": backend.confidence,
                            "detection_method": backend.detection_method,
                        }

    # Cross-reference backend versions with detected library versions
    # If backend was detected but version is missing, try to fill from detected libraries
    backend_to_lib = {
        "OpenSSL": "openssl",
        "GnuTLS": "gnutls",
        "mbedTLS": "mbedtls",
        "wolfSSL": "wolfssl",
        "NSS": "nss",
    }

    for lib_type in ["libcurl", "curl_cli", "wget_cli"]:
        if lib_type in result and "backend" in result[lib_type]:
            backend = result[lib_type]["backend"]
            if not backend.get("version"):
                # Try to find version from detected libraries
                backend_name = backend.get("name", "")
                lib_key = backend_to_lib.get(backend_name)
                if lib_key and lib_key in result:
                    backend["version"] = result[lib_key].get("version")

    # Inherit backend for curl_cli from libcurl if not detected
    # (curl binary links to libcurl.so, not directly to SSL library)
    if "curl_cli" in result and "backend" not in result["curl_cli"]:
        if "libcurl" in result and "backend" in result["libcurl"]:
            result["curl_cli"]["backend"] = result["libcurl"]["backend"].copy()

    return result
