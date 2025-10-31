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
    "gnutls_handshake",
    "gnutls_record_send",
    "gnutls_record_recv",
    "gnutls_record_send_early_data",
    "gnutls_record_recv_early_data",
}

INIT_SETUP: Set[str] = {
    # Session initialization functions
    "gnutls_init",
    "gnutls_global_init",
    "gnutls_global_init_extra",
}

CLIENT_CONFIG: Set[str] = {
    # Client-specific configuration functions
    "gnutls_credentials_set",
    "gnutls_certificate_allocate_credentials",
    "gnutls_certificate_set_x509_trust_file",
    "gnutls_certificate_set_x509_trust_dir",
    "gnutls_certificate_set_x509_system_trust",
    "gnutls_priority_set_direct",
    "gnutls_priority_init",
    "gnutls_server_name_set",  # SNI - client indicator
}

VERIFICATION: Set[str] = {
    # Certificate and hostname verification - client security functions
    "gnutls_certificate_verify_peers2",
    "gnutls_certificate_verify_peers3",
    "gnutls_x509_crt_check_hostname",
    "gnutls_certificate_get_peers",
    "gnutls_ocsp_status_request_enable_client",
}

WEAK_APIS: Set[str] = {
    # Cleanup and utility functions - seen in clients but not sufficient alone
    "gnutls_deinit",
    "gnutls_global_deinit",
    "gnutls_bye",
    "gnutls_perror",
    "gnutls_strerror",
    "gnutls_check_version",
    "gnutls_transport_set_ptr",
    "gnutls_transport_set_int",
    "gnutls_session_set_data",
    "gnutls_session_get_data",
    "gnutls_cipher_get",
    "gnutls_protocol_get_version",
}

ALL_KEYS: Set[str] = STRONG_API | INIT_SETUP | CLIENT_CONFIG | VERIFICATION | WEAK_APIS

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
    libgnutls.so that export GnuTLS functions.
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
    for k in WEAK_APIS:
        if k in corpus:
            hits["weak"].append(k)
    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if any STRONG found (e.g., gnutls_handshake)
      - HIGH if INIT + CLIENT_CONFIG (typical client setup)
      - HIGH if INIT + VERIFICATION (client with security focus)
      - MED  if INIT + WEAK (basic GnuTLS usage)
      - LOW  if >=3 WEAK found
      - NONE otherwise
    Returns (level, rationale)
    """
    if hits["strong"]:
        return ("high", f"Found strong TLS handshake/transfer function(s): {', '.join(sorted(hits['strong']))}")

    if hits["init"] and hits["client_config"]:
        return ("high", f"Client setup pattern: init={', '.join(sorted(hits['init']))} + config={', '.join(sorted(hits['client_config'][:3]))}")

    if hits["init"] and hits["verification"]:
        return ("high", f"Client verification pattern: init={', '.join(sorted(hits['init']))} + verify={', '.join(sorted(hits['verification'][:3]))}")

    if hits["init"] and hits["weak"]:
        return ("medium", f"Basic GnuTLS usage: init={', '.join(sorted(hits['init']))} + utilities")

    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak GnuTLS indicators: {', '.join(sorted(hits['weak'][:5]))}")

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
    ap = argparse.ArgumentParser(description="Locate probable GnuTLS client usage sites (heuristic, static, ELF-only).")
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
            if f["hits"]["weak"]:
                print(f"  weak: {', '.join(sorted(f['hits']['weak']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
