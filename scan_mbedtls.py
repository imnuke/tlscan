#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import stat
from typing import List, Set, Dict, Tuple, Optional

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

# ---- Heuristic indicator sets ----
STRONG_API: Set[str] = {
    # Main TLS handshake and data transfer - definitive client usage
    "mbedtls_ssl_handshake",
    "mbedtls_ssl_write",
    "mbedtls_ssl_read",
    "mbedtls_ssl_send_alert_message",
}

INIT_SETUP: Set[str] = {
    # SSL/TLS session initialization
    "mbedtls_ssl_init",
    "mbedtls_ssl_setup",
    "mbedtls_ssl_config_init",
    "mbedtls_ssl_config_defaults",
}

CLIENT_CONFIG: Set[str] = {
    # Client-specific configuration functions
    "mbedtls_ssl_conf_authmode",
    "mbedtls_ssl_conf_ca_chain",
    "mbedtls_ssl_conf_own_cert",
    "mbedtls_ssl_conf_rng",
    "mbedtls_ssl_conf_min_version",
    "mbedtls_ssl_conf_max_version",
    "mbedtls_ssl_conf_ciphersuites",
    "mbedtls_ssl_set_hostname",  # SNI and hostname verification
    "mbedtls_ssl_set_bio",
}

VERIFICATION: Set[str] = {
    # Certificate and hostname verification functions
    "mbedtls_x509_crt_verify",
    "mbedtls_x509_crt_verify_with_profile",
    "mbedtls_x509_crt_check_extended_key_usage",
    "mbedtls_ssl_get_verify_result",
    "mbedtls_x509_crt_parse",
    "mbedtls_x509_crt_parse_file",
}

CRYPTO_INIT: Set[str] = {
    # Cryptographic initialization (required for TLS)
    "mbedtls_ctr_drbg_init",
    "mbedtls_ctr_drbg_seed",
    "mbedtls_entropy_init",
    "mbedtls_entropy_func",
}

WEAK_APIS: Set[str] = {
    # Cleanup and utility functions - seen in clients but not sufficient alone
    "mbedtls_ssl_free",
    "mbedtls_ssl_config_free",
    "mbedtls_ssl_close_notify",
    "mbedtls_ssl_session_reset",
    "mbedtls_strerror",
    "mbedtls_version_get_string",
    "mbedtls_x509_crt_init",
    "mbedtls_x509_crt_free",
    "mbedtls_ctr_drbg_free",
    "mbedtls_entropy_free",
}

ALL_KEYS: Set[str] = STRONG_API | INIT_SETUP | CLIENT_CONFIG | VERIFICATION | CRYPTO_INIT | WEAK_APIS

PRINTABLE = set(range(0x20, 0x7F))  # ASCII printable


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
    """Collect imported (undefined) symbol names from .dynsym and .symtab.

    Only returns symbols with st_shndx == 'SHN_UNDEF' (pyelftools returns this
    as a string, not integer 0). These are external symbols that the binary
    imports/uses but does not define. This prevents flagging libraries like
    libmbedtls.so that export mbed TLS functions.
    """
    names: Set[str] = set()
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    # Only include undefined/imported symbols
                    # Note: pyelftools returns 'SHN_UNDEF' as a string, not integer 0
                    if sym['st_shndx'] == 'SHN_UNDEF':
                        nm = sym.name
                        if nm:
                            names.add(nm)
    except Exception:
        pass
    return names


def match_indicators(corpus: Set[str]) -> Dict[str, List[str]]:
    """
    Return which indicators were found in the provided string set.
    corpus is expected to be a set of candidate tokens (symbols).
    """
    hits: Dict[str, List[str]] = {
        "strong": [],
        "init": [],
        "client_config": [],
        "verification": [],
        "crypto": [],
        "weak": []
    }
    for k in STRONG_API:
        if k in corpus:
            hits["strong"].append(k)
    for k in INIT_SETUP:
        if k in corpus:
            hits["init"].append(k)
    for k in CLIENT_CONFIG:
        if k in corpus:
            hits["client_config"].append(k)
    for k in VERIFICATION:
        if k in corpus:
            hits["verification"].append(k)
    for k in CRYPTO_INIT:
        if k in corpus:
            hits["crypto"].append(k)
    for k in WEAK_APIS:
        if k in corpus:
            hits["weak"].append(k)
    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if any STRONG found (e.g., mbedtls_ssl_handshake)
      - HIGH if INIT + CLIENT_CONFIG + CRYPTO (complete client setup)
      - HIGH if INIT + VERIFICATION (client with security focus)
      - MED  if INIT + CRYPTO (basic SSL setup)
      - LOW  if >=3 WEAK found or INIT only
      - NONE otherwise
    Returns (level, rationale)
    """
    if hits["strong"]:
        return ("high", f"Found strong TLS handshake/transfer function(s): {', '.join(sorted(hits['strong']))}")

    if hits["init"] and hits["client_config"] and hits["crypto"]:
        return ("high", f"Complete client setup: init + config + crypto")

    if hits["init"] and hits["verification"]:
        return ("high", f"Client verification pattern: init={', '.join(sorted(hits['init']))} + verify={', '.join(sorted(hits['verification'][:3]))}")

    if hits["init"] and hits["crypto"]:
        return ("medium", f"Basic mbed TLS setup: init + crypto initialization")

    if hits["init"]:
        return ("low", f"Only initialization found: {', '.join(sorted(hits['init']))}")

    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak mbed TLS indicators: {', '.join(sorted(hits['weak'][:5]))}")

    return ("none", "No sufficient indicators")


def scan_file(path: str) -> Optional[Dict]:
    if not is_regular_file(path):
        return None
    if not is_probably_elf(path):
        return None

    symbols = extract_symbols(path)

    # Use only undefined/imported symbols for detection
    corpus = symbols

    hits = match_indicators(corpus)
    level, rationale = score(hits)

    if level == "none":
        return None

    return {
        "path": path,
        "level": level,
        "rationale": rationale,
        "hits": hits,
        "symbol_sample": sorted(list(symbols & ALL_KEYS))[:15],
    }


def walk_and_scan(root: str) -> List[Dict]:
    results: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            item = scan_file(fp)
            if item:
                results.append(item)
    return results


def main():
    ap = argparse.ArgumentParser(description="Locate probable mbed TLS client usage sites (heuristic, static, ELF-only).")
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument("--json", action="store_true", help="Emit JSON lines (one object per finding)")
    args = ap.parse_args()

    findings = walk_and_scan(args.root)
    if args.json:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    else:
        for f in findings:
            print(f"[{f['level'].upper()}] {f['path']}\n  {f['rationale']}")
            if f["hits"]["strong"]:
                print(f"  strong: {', '.join(sorted(f['hits']['strong']))}")
            if f["hits"]["init"]:
                print(f"  init: {', '.join(sorted(f['hits']['init']))}")
            if f["hits"]["client_config"]:
                print(f"  client_config: {', '.join(sorted(f['hits']['client_config']))}")
            if f["hits"]["verification"]:
                print(f"  verification: {', '.join(sorted(f['hits']['verification']))}")
            if f["hits"]["crypto"]:
                print(f"  crypto: {', '.join(sorted(f['hits']['crypto']))}")
            if f["hits"]["weak"]:
                print(f"  weak: {', '.join(sorted(f['hits']['weak']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
