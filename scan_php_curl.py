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

# PHP userland curl functions (as strings in binaries)
PHP_CURL_FUNCTIONS: Set[str] = {
    "curl_init",
    "curl_exec",
    "curl_setopt",
    "curl_setopt_array",
    "curl_close",
    "curl_getinfo",
    "curl_error",
    "curl_errno",
    "curl_multi_init",
    "curl_multi_exec",
    "curl_multi_add_handle",
}

# PHP curl extension internal symbols (C functions in extension)
PHP_CURL_INTERNAL: Set[str] = {
    "php_curl_init",
    "php_curl_exec",
    "php_curl_setopt",
    "php_curl_close",
    "zif_curl_init",
    "zif_curl_exec",
    "zif_curl_setopt",
    "zif_curl_setopt_array",
    "zif_curl_close",
    "zif_curl_getinfo",
}

# CURLOPT constants (often appear as strings)
CURLOPT_CONSTANTS: Set[str] = {
    "CURLOPT_URL",
    "CURLOPT_RETURNTRANSFER",
    "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
    "CURLOPT_CAINFO",
    "CURLOPT_CAPATH",
    "CURLOPT_SSLVERSION",
    "CURLOPT_POST",
    "CURLOPT_POSTFIELDS",
    "CURLOPT_HTTPHEADER",
    "CURLOPT_FOLLOWLOCATION",
}

# Security-relevant strings indicating insecure usage
INSECURE_PATTERNS: Set[str] = {
    "CURLOPT_SSL_VERIFYPEER", # Often set to false
    "CURLOPT_SSL_VERIFYHOST", # Often set to 0
    "verify_peer",
    "verify_host",
}

ALL_KEYS: Set[str] = (PHP_CURL_FUNCTIONS | PHP_CURL_INTERNAL |
                       CURLOPT_CONSTANTS | INSECURE_PATTERNS)

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
    imports/uses but does not define.
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


def extract_strings(path: str, minlen: int = 4, maxsize_mb: int = 64) -> Set[str]:
    """
    Collect printable ASCII substrings from binary.
    Limit file size to avoid huge binaries in naive scan.
    """
    res: Set[str] = set()
    try:
        size = os.path.getsize(path)
        if size > maxsize_mb * 1024 * 1024:
            return res  # skip very big files

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


def match_indicators(symbols: Set[str], strings: Set[str]) -> Dict[str, List[str]]:
    """
    Return which indicators were found in symbols and strings.
    """
    hits: Dict[str, List[str]] = {
        "php_functions": [],
        "php_internal": [],
        "curlopt_constants": [],
        "insecure_patterns": []
    }

    # Check symbols for PHP internal functions
    for k in PHP_CURL_INTERNAL:
        if k in symbols:
            hits["php_internal"].append(k)

    # Check strings for PHP userland functions
    for k in PHP_CURL_FUNCTIONS:
        if contains_substring(strings, k):
            hits["php_functions"].append(k)

    # Check for CURLOPT constants
    for k in CURLOPT_CONSTANTS:
        if contains_substring(strings, k):
            hits["curlopt_constants"].append(k)

    # Check for insecure patterns
    for k in INSECURE_PATTERNS:
        if contains_substring(strings, k):
            hits["insecure_patterns"].append(k)

    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if PHP internal symbols + functions (PHP extension binary)
      - HIGH if multiple PHP functions + CURLOPT constants (embedded PHP code)
      - MED  if PHP functions found (basic usage)
      - LOW  if only CURLOPT constants (possible false positive)
      - NONE otherwise
    Returns (level, rationale)
    """
    has_internal = len(hits["php_internal"]) > 0
    has_functions = len(hits["php_functions"]) >= 2
    has_curlopt = len(hits["curlopt_constants"]) >= 2
    has_insecure = len(hits["insecure_patterns"]) > 0

    if has_internal:
        return ("high", f"PHP curl extension internals detected: {', '.join(sorted(hits['php_internal'][:3]))}")

    if has_functions and has_curlopt:
        if has_insecure:
            return ("high", f"SECURITY RISK: PHP curl with insecure patterns: {', '.join(sorted(hits['insecure_patterns'][:2]))}")
        return ("high", f"PHP curl usage detected: {len(hits['php_functions'])} functions, {len(hits['curlopt_constants'])} options")

    if has_functions:
        funcs = ', '.join(sorted(hits['php_functions'][:3]))
        return ("medium", f"PHP curl functions detected: {funcs}")

    if has_curlopt:
        return ("low", f"CURLOPT constants found but no clear PHP curl usage")

    return ("none", "No sufficient indicators")


def scan_file(path: str, min_strlen: int) -> Optional[Dict]:
    if not is_regular_file(path):
        return None
    if not is_probably_elf(path):
        return None

    # Extract both symbols and strings for PHP curl detection
    symbols = extract_symbols(path)
    strings = extract_strings(path, minlen=min_strlen)

    hits = match_indicators(symbols, strings)
    level, rationale = score(hits)

    if level == "none":
        return None

    # Collect samples
    all_hits = []
    for category in ["php_internal", "php_functions", "curlopt_constants", "insecure_patterns"]:
        all_hits.extend(hits[category])

    return {
        "path": path,
        "level": level,
        "rationale": rationale,
        "hits": hits,
        "indicator_sample": sorted(all_hits)[:10],
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
    ap = argparse.ArgumentParser(description="Locate probable PHP curl extension usage (heuristic, static, ELF-only).")
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument("--min-strlen", type=int, default=6, help="Minimum printable-string length (default: 6)")
    ap.add_argument("--json", action="store_true", help="Emit JSON lines (one object per finding)")
    args = ap.parse_args()

    findings = walk_and_scan(args.root, args.min_strlen)
    if args.json:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    else:
        for f in findings:
            print(f"[{f['level'].upper()}] {f['path']}\n  {f['rationale']}")
            if f["hits"]["php_internal"]:
                print(f"  php_internal: {', '.join(sorted(f['hits']['php_internal']))}")
            if f["hits"]["php_functions"]:
                print(f"  php_functions: {', '.join(sorted(f['hits']['php_functions']))}")
            if f["hits"]["curlopt_constants"]:
                print(f"  curlopt_constants: {', '.join(sorted(f['hits']['curlopt_constants']))}")
            if f["hits"]["insecure_patterns"]:
                print(f"  insecure_patterns: {', '.join(sorted(f['hits']['insecure_patterns']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
