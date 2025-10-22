#!/usr/bin/env python3

# Locate network connection establishing code in firmware.
#
# Input:
#   - Domain name
#   - Port number
# 
# Output:
#   - Binary(File) name
#   - Code snippet location (line number)

import os
import subprocess
from pathlib import Path

common_tlds = [
    ".com", ".org", ".net", ".int", ".edu", ".gov", ".mil",
    ".arpa", ".biz", ".info", ".pro", ".name", ".coop", ".aero",
    ".museum", ".io", ".tech", ".dev", ".ai", ".app", ".xyz",
    ".site", ".online", ".top", ".club", ".shop", ".blog", ".me",
    ".us", ".uk", ".ca", ".de", ".fr", ".au", ".jp", ".cn",
    ".in", ".ru", ".br", ".za", ".kr", ".se", ".nl", ".es", ".it"
]

ignore_files = [
    '*.js', '*.html', '*.css', '*.scss', '*.tar*', '*.log', '*.i64', '*.id0'
]

def is_elf_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            return header == b'\x7fELF'
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False

def search_in_firmware(firmware, search_pattern):
    # Use ripgrep to do the search
    firmware_path = Path(os.path.expanduser(firmware))
    if not firmware_path.exists():
        print(f"Firmware path not found: {firmware_path}")
        return []

    # Enable PCRE to support lookarounds and treat binaries as text so embedded strings are detected.
    command = ['rg', '-n', '-P', '--binary', search_pattern]
    for pattern in ignore_files:
        command.extend(['--glob', f'!{pattern}'])

    command.append(str(firmware_path))

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            matches: list[tuple[str, int, str]] = []
            for raw_line in result.stdout.splitlines():
                parts = raw_line.split(':', 2)
                if len(parts) < 3:
                    # `rg --binary` reports matches inside binary blobs without a line number.
                    if 'binary file matches' in raw_line:
                        path = parts[0]
                        message = parts[1].strip() if len(parts) > 1 else 'binary file matches'
                        matches.append((path, 0, message))
                    else:
                        print(f"Skipping unexpected ripgrep output: {raw_line}")
                    continue

                path, line_no, content = parts
                try:
                    matches.append((path, int(line_no), content))
                except ValueError:
                    print(f"Skipping ripgrep line with non-integer line number: {raw_line}")
            return matches
        if result.returncode == 1:
            return []
        else:
            return []
    except FileNotFoundError:
        print("ripgrep (rg) is not installed or not found in PATH.")
        return []

# 尽可能排除不相关的结果
def filter_results(results):
    ignore_contents = [
        'copyright', 'license', 'version', 'author', 'maintainer', 'readme', 'changelog', 'llc', 'inc',
        'href', 'xmlns', '!DOCTYPE', 'openxmlformats'
    ]
    filtered = []
    for filepath, line_no, content in results:
        content_lower = content.lower()
        content_stripped = content.lstrip()
        if content_stripped.startswith(('#', '//', '*')):
            continue
        if any(ign in content_lower for ign in ignore_contents):
            continue
        filtered.append((filepath, line_no, content))
    return filtered

def main():
    domain_name_pattern = r'(?<!@)\b(?:[a-zA-Z0-9-]+\.)+(?:' + '|'.join(tld.lstrip('.') for tld in common_tlds) + r')\b(?!-)'
    ip_addr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    print(f"Searching for domain names matching pattern: {domain_name_pattern}")

    firmware = "~/MyWorkspace/firmwares/mydataset/Asustor/AS3204T_4.3.3_RKD2"
    # firmware = "~/MyWorkspace/firmwares/mydataset/QNAP/TS251D_5.2.0.2860/rootfs2.bz_extract/lzma.uncompressed_extract"
    # firmware = "/home/peng/MyWorkspace/firmwares/mydataset/Asus/RTN66U_3.0.0.4_382_52734"
    results = search_in_firmware(firmware, domain_name_pattern)
    filtered_results = filter_results(results)

    checked_files: dict[str, bool] = {}
    for filepath, line_no, content in filtered_results:
        print(f"Found in {filepath} at line {line_no}: {content.strip()}")
        if filepath not in checked_files:
            checked_files[filepath] = is_elf_file(filepath)

    total_matches = len(filtered_results)
    unique_files = len(checked_files)
    binary_files = sum(1 for is_binary in checked_files.values() if is_binary)
    print(
        f"Summary: {total_matches} matches across {unique_files} files; "
        f"{binary_files} file(s) appear to be ELF binaries."
    )


if __name__ == "__main__":
    main()
