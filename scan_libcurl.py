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
    # Main transfer execution functions - definitive client usage
    "curl_easy_perform",
    "curl_multi_perform",
    "curl_easy_send",
    "curl_easy_recv",
}

INIT_SETUP: Set[str] = {
    # Initialization functions - required for any curl operation
    "curl_easy_init",
    "curl_multi_init",
    "curl_global_init",
}

SETOPT_FUNCTIONS: Set[str] = {
    # Configuration functions - essential for setting up requests
    "curl_easy_setopt",
    "curl_multi_setopt",
    "curl_easy_setopt_array",
}

INFO_FUNCTIONS: Set[str] = {
    # Information retrieval - often used in HTTP clients
    "curl_easy_getinfo",
    "curl_multi_info_read",
}

WEAK_APIS: Set[str] = {
    # Cleanup and utility functions - seen in clients but not sufficient alone
    "curl_easy_cleanup",
    "curl_multi_cleanup",
    "curl_global_cleanup",
    "curl_slist_append",
    "curl_slist_free_all",
    "curl_easy_strerror",
    "curl_multi_strerror",
    "curl_version",
    "curl_version_info",
    "curl_easy_escape",
    "curl_easy_unescape",
    "curl_free",
}

ALL_KEYS: Set[str] = STRONG_API | INIT_SETUP | SETOPT_FUNCTIONS | INFO_FUNCTIONS | WEAK_APIS

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
    libcurl.so that export curl functions.
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
        "setopt": [],
        "info": [],
        "weak": []
    }
    for k in STRONG_API:
        if k in corpus:
            hits["strong"].append(k)
    for k in INIT_SETUP:
        if k in corpus:
            hits["init"].append(k)
    for k in SETOPT_FUNCTIONS:
        if k in corpus:
            hits["setopt"].append(k)
    for k in INFO_FUNCTIONS:
        if k in corpus:
            hits["info"].append(k)
    for k in WEAK_APIS:
        if k in corpus:
            hits["weak"].append(k)
    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if any STRONG found (e.g., curl_easy_perform)
      - HIGH if INIT + SETOPT (typical client setup pattern)
      - MED  if INIT + INFO (may be checking curl capabilities)
      - LOW  if >=3 WEAK found or INIT only
      - NONE otherwise
    Returns (level, rationale)
    """
    if hits["strong"]:
        return ("high", f"Found strong client transfer function(s): {', '.join(sorted(hits['strong']))}")

    if hits["init"] and hits["setopt"]:
        return ("high", f"Client setup pattern: init={', '.join(sorted(hits['init']))} + setopt={', '.join(sorted(hits['setopt']))}")

    if hits["init"] and hits["info"]:
        return ("medium", f"Client info retrieval pattern: init={', '.join(sorted(hits['init']))} + info={', '.join(sorted(hits['info']))}")

    if hits["init"]:
        return ("low", f"Only initialization found: {', '.join(sorted(hits['init']))}")

    if len(hits["weak"]) >= 3:
        return ("low", f"Multiple weak libcurl indicators: {', '.join(sorted(hits['weak']))}")

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
    ap = argparse.ArgumentParser(description="Locate probable libcurl client usage sites (heuristic, static, ELF-only).")
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
            if f["hits"]["setopt"]:
                print(f"  setopt: {', '.join(sorted(f['hits']['setopt']))}")
            if f["hits"]["info"]:
                print(f"  info: {', '.join(sorted(f['hits']['info']))}")
            if f["hits"]["weak"]:
                print(f"  weak: {', '.join(sorted(f['hits']['weak']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
