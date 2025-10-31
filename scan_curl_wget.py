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

# Command strings that indicate curl/wget usage
TOOL_COMMANDS: Set[str] = {
    "curl",
    "wget",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/bin/curl",
    "/bin/wget",
}

# URL scheme patterns
URL_SCHEMES: Set[str] = {
    "http://",
    "https://",
    "ftp://",
    "ftps://",
}

# Insecure flags for curl
CURL_INSECURE_FLAGS: Set[str] = {
    "-k",
    "--insecure",
    "--no-check-certificate",  # wget flag, but sometimes confused
    "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
}

# Insecure flags for wget
WGET_INSECURE_FLAGS: Set[str] = {
    "--no-check-certificate",
    "--no-verify-peer",
    "--no-host-check",
}

# Common curl options
CURL_OPTIONS: Set[str] = {
    "-X",
    "--request",
    "-d",
    "--data",
    "-H",
    "--header",
    "-o",
    "--output",
    "-O",
    "--remote-name",
    "-u",
    "--user",
}

# Common wget options
WGET_OPTIONS: Set[str] = {
    "-O",
    "--output-document",
    "-P",
    "--directory-prefix",
    "-q",
    "--quiet",
    "-c",
    "--continue",
    "--user",
    "--password",
}

ALL_KEYS: Set[str] = (TOOL_COMMANDS | URL_SCHEMES | CURL_INSECURE_FLAGS |
                       WGET_INSECURE_FLAGS | CURL_OPTIONS | WGET_OPTIONS)

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


def extract_strings(path: str, minlen: int = 4, maxsize_mb: int = 64) -> Set[str]:
    """
    Collect printable ASCII substrings from binary.
    Limit file size to avoid huge binaries in naive scan.
    """
    res: Set[str] = set()
    try:
        size = os.path.getsize(path)
        if size > maxsize_mb * 1024 * 1024:
            return res  # skip very big files to keep scan reasonable

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


def match_indicators(corpus: Set[str]) -> Dict[str, List[str]]:
    """
    Return which indicators were found in the provided string set.
    corpus is expected to be a set of strings extracted from the binary.
    """
    hits: Dict[str, List[str]] = {
        "tools": [],
        "urls": [],
        "curl_insecure": [],
        "wget_insecure": [],
        "curl_options": [],
        "wget_options": []
    }

    # Check for tool commands (substring match)
    for k in TOOL_COMMANDS:
        if contains_substring(corpus, k):
            hits["tools"].append(k)

    # Check for URL schemes
    for k in URL_SCHEMES:
        if contains_substring(corpus, k):
            hits["urls"].append(k)

    # Check for insecure flags
    for k in CURL_INSECURE_FLAGS:
        if contains_substring(corpus, k):
            hits["curl_insecure"].append(k)

    for k in WGET_INSECURE_FLAGS:
        if contains_substring(corpus, k):
            hits["wget_insecure"].append(k)

    # Check for options
    for k in CURL_OPTIONS:
        if k in corpus:  # Exact match for flags
            hits["curl_options"].append(k)

    for k in WGET_OPTIONS:
        if k in corpus:  # Exact match for flags
            hits["wget_options"].append(k)

    return hits


def score(hits: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Simple heuristic scoring:
      - HIGH if tool + URL + insecure flags (security risk)
      - HIGH if tool + URL + multiple options (active usage)
      - MED  if tool + URL (basic usage)
      - LOW  if tool only or URL only
      - NONE otherwise
    Returns (level, rationale)
    """
    has_tool = len(hits["tools"]) > 0
    has_url = len(hits["urls"]) > 0
    has_insecure = len(hits["curl_insecure"]) > 0 or len(hits["wget_insecure"]) > 0
    has_options = len(hits["curl_options"]) + len(hits["wget_options"]) >= 2

    # Determine which tool
    tool_name = "unknown"
    if any("curl" in t for t in hits["tools"]):
        tool_name = "curl"
    elif any("wget" in t for t in hits["tools"]):
        tool_name = "wget"

    if has_tool and has_url and has_insecure:
        insecure_flags = hits["curl_insecure"] + hits["wget_insecure"]
        return ("high", f"SECURITY RISK: {tool_name} with URL and insecure flags: {', '.join(sorted(insecure_flags[:3]))}")

    if has_tool and has_url and has_options:
        return ("high", f"Active {tool_name} usage with URLs and options detected")

    if has_tool and has_url:
        tools = ', '.join(sorted(hits["tools"][:2]))
        urls = ', '.join(sorted(hits["urls"][:2]))
        return ("medium", f"Command-line HTTP client usage: tools={tools}, schemes={urls}")

    if has_tool:
        tools = ', '.join(sorted(hits["tools"]))
        return ("low", f"Tool command strings found: {tools}")

    if has_url:
        return ("low", f"URL schemes found but no tool commands")

    return ("none", "No sufficient indicators")


def scan_file(path: str, min_strlen: int) -> Optional[Dict]:
    if not is_regular_file(path):
        return None
    if not is_probably_elf(path):
        return None

    # Extract strings for command-line tool detection
    strings = extract_strings(path, minlen=min_strlen)

    hits = match_indicators(strings)
    level, rationale = score(hits)

    if level == "none":
        return None

    # Collect sample strings for debugging
    sample_strings = []
    for category in ["tools", "urls", "curl_insecure", "wget_insecure"]:
        sample_strings.extend(hits[category])

    return {
        "path": path,
        "level": level,
        "rationale": rationale,
        "hits": hits,
        "string_sample": sorted(sample_strings)[:10],
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
    ap = argparse.ArgumentParser(description="Locate probable curl/wget command-line tool usage (heuristic, string-based, ELF-only).")
    ap.add_argument("root", help="Directory to recursively scan")
    ap.add_argument("--min-strlen", type=int, default=4, help="Minimum printable-string length (default: 4)")
    ap.add_argument("--json", action="store_true", help="Emit JSON lines (one object per finding)")
    args = ap.parse_args()

    findings = walk_and_scan(args.root, args.min_strlen)
    if args.json:
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    else:
        for f in findings:
            print(f"[{f['level'].upper()}] {f['path']}\n  {f['rationale']}")
            if f["hits"]["tools"]:
                print(f"  tools: {', '.join(sorted(f['hits']['tools']))}")
            if f["hits"]["urls"]:
                print(f"  urls: {', '.join(sorted(f['hits']['urls']))}")
            if f["hits"]["curl_insecure"]:
                print(f"  curl_insecure: {', '.join(sorted(f['hits']['curl_insecure']))}")
            if f["hits"]["wget_insecure"]:
                print(f"  wget_insecure: {', '.join(sorted(f['hits']['wget_insecure']))}")
            if f["hits"]["curl_options"]:
                print(f"  curl_options: {', '.join(sorted(f['hits']['curl_options']))}")
            if f["hits"]["wget_options"]:
                print(f"  wget_options: {', '.join(sorted(f['hits']['wget_options']))}")
            print()
    # Exit status hint (optional): non-zero if nothing found
    raise SystemExit(0 if findings else 1)


if __name__ == "__main__":
    main()
