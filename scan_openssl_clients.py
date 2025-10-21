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
    # direct client handshake / BIO client connectors
    "SSL_connect",
    "BIO_new_ssl_connect",
    "BIO_do_connect",
}

CLIENT_METHODS: Set[str] = {
    # modern and legacy client methods that often appear explicitly
    "TLS_client_method",
    "DTLS_client_method",
    "SSLv23_client_method",
    "TLSv1_client_method",
    "TLSv1_1_client_method",
    "TLSv1_2_client_method",
}

GENERIC_METHODS: Set[str] = {
    # generic (version-flexible) methods: need pairing with connect-state or SSL_connect
    "TLS_method",
    "DTLS_method",
}

STATE_APIS: Set[str] = {
    # force client state without explicit *_client_method
    "SSL_set_connect_state",
}

WEAK_APIS: Set[str] = {
    # often seen in clients but not sufficient alone
    "SSL_set_tlsext_host_name",         # SNI
    "SSL_set1_host",                    # hostname verification (OpenSSL >=1.1.1)
    "X509_VERIFY_PARAM_set1_host",      # hostname verification via param
    "SSL_CTX_set_verify",
    "SSL_set_verify",
    "SSL_set_fd",
    "SSL_set_bio",
}

ALL_KEYS: Set[str] = STRONG_API | CLIENT_METHODS | GENERIC_METHODS | STATE_APIS | WEAK_APIS

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
    """Collect symbol names from .dynsym and .symtab if available."""
    names: Set[str] = set()
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    nm = sym.name
                    if nm:
                        names.add(nm)
    except Exception:
        pass
    return names


def extract_strings(path: str, minlen: int = 4, maxsize_mb: int = 64) -> Set[str]:
    """
    Collect printable ASCII substrings as a fallback when symbols are stripped.
    Limit file size to avoid huge binaries in naive scan.
    """
    res: Set[str] = set()
    try:
        size = os.path.getsize(path)
        if size > maxsize_mb * 1024 * 1024:
            return res  # skip very big files to keep demo simple

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


def match_indicators(corpus: Set[str]) -> Dict[str, List[str]]:
    """
    Return which indicators were found in the provided string set.
    corpus is expected to be a set of candidate tokens (symbols + strings).
    """
    hits: Dict[str, List[str]] = {"strong": [], "client_methods": [], "generic_methods": [], "state": [], "weak": []}
    for k in STRONG_API:
        if k in corpus:
            hits["strong"].append(k)
    for k in CLIENT_METHODS:
        if k in corpus:
            hits["client_methods"].append(k)
    for k in GENERIC_METHODS:
        if k in corpus:
            hits["generic_methods"].append(k)
    for k in STATE_APIS:
        if k in corpus:
            hits["state"].append(k)
    for k in WEAK_APIS:
        if k in corpus:
            hits["weak"].append(k)
    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if any STRONG found (e.g., SSL_connect or BIO_*_connect)
      - HIGH if GENERIC_METHOD + (STATE or STRONG present)
      - MED  if CLIENT_METHODS found (even without others)
      - LOW  if >=2 WEAK found
      - NONE otherwise
    Returns (level, rationale)
    """
    if hits["strong"]:
        return ("high", f"Found strong client connector(s): {', '.join(sorted(hits['strong']))}")
    if hits["generic_methods"] and (hits["state"] or hits["strong"]):
        return ("high", f"Generic method + client state/connect: method={hits['generic_methods']} state={hits['state']} strong={hits['strong']}")
    if hits["client_methods"]:
        return ("medium", f"Found client method(s): {', '.join(sorted(hits['client_methods']))}")
    if len(hits["weak"]) >= 2:
        return ("low", f"Multiple weak client-leaning indicators: {', '.join(sorted(hits['weak']))}")
    return ("none", "No sufficient indicators")


def scan_file(path: str, min_strlen: int) -> Optional[Dict]:
    if not is_regular_file(path):
        return None
    if not is_probably_elf(path):
        return None

    symbols = extract_symbols(path)
    strings = extract_strings(path, minlen=min_strlen)

    # token corpus = exact tokens; to keep demo strict, we do exact matches only
    corpus = set()
    corpus |= symbols
    # also include strings that exactly match indicator keys
    for s in strings:
        if s in ALL_KEYS:
            corpus.add(s)

    hits = match_indicators(corpus)
    level, rationale = score(hits)

    if level == "none":
        return None

    return {
        "path": path,
        "level": level,
        "rationale": rationale,
        "hits": hits,
        "symbol_sample": sorted(list(symbols & ALL_KEYS))[:10],
        "string_sample": sorted([s for s in strings if s in ALL_KEYS])[:10],
    }


def walk_and_scan(root: str, min_strlen: int) -> List[Dict]:
    results: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            item = scan_file(fp, min_strlen)
            if item:
                results.append(item)
    return results


def main():
    ap = argparse.ArgumentParser(description="Locate probable OpenSSL client connection sites (heuristic, static, ELF-only).")
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument("--min-strlen", type=int, default=6, help="Minimum printable-string length for fallback scan (default: 6)")
    ap.add_argument("--json", action="store_true", help="Emit JSON lines (one object per finding)")
    args = ap.parse_args()

    findings = walk_and_scan(args.root, args.min_strlen)
    if args.json:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    else:
        for f in findings:
            print(f"[{f['level'].upper()}] {f['path']}\n  {f['rationale']}")
            if f["hits"]["strong"]:
                print(f"  strong: {', '.join(sorted(f['hits']['strong']))}")
            if f["hits"]["client_methods"]:
                print(f"  client_methods: {', '.join(sorted(f['hits']['client_methods']))}")
            if f["hits"]["generic_methods"]:
                print(f"  generic_methods: {', '.join(sorted(f['hits']['generic_methods']))}")
            if f["hits"]["state"]:
                print(f"  state: {', '.join(sorted(f['hits']['state']))}")
            if f["hits"]["weak"]:
                print(f"  weak: {', '.join(sorted(f['hits']['weak']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
