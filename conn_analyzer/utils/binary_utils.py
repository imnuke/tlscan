import re
import subprocess
from enum import Enum
from typing import Optional


class FileType(str, Enum):
    """Detected file type for analysis routing."""
    ELF_BINARY = "elf_binary"
    SHELL_SCRIPT = "shell_script"
    PHP_SCRIPT = "php_script"
    PYTHON_SCRIPT = "python_script"
    PERL_SCRIPT = "perl_script"
    TEXT_FILE = "text_file"
    UNKNOWN = "unknown"


def detect_file_type(file_path: str) -> FileType:
    """
    Detect file type based on content/magic bytes.

    Detection order:
    1. ELF magic bytes (binary)
    2. Shebang (#!) for shell, python, perl scripts
    3. PHP opening tag (<?php)
    4. Text file detection (no null bytes)
    5. Unknown

    Args:
        file_path: Path to file to analyze

    Returns:
        FileType enum indicating how the file should be analyzed
    """
    # Check for ELF first (binary)
    if is_elf_file(file_path):
        return FileType.ELF_BINARY

    # Read first bytes for script detection
    try:
        with open(file_path, 'rb') as f:
            header = f.read(512)
    except Exception:
        return FileType.UNKNOWN

    # Check for script shebangs
    if header.startswith(b'#!'):
        first_line = header.split(b'\n')[0].decode('utf-8', errors='ignore').lower()
        if 'bash' in first_line or '/sh' in first_line or 'dash' in first_line:
            return FileType.SHELL_SCRIPT
        if 'python' in first_line:
            return FileType.PYTHON_SCRIPT
        if 'php' in first_line:
            return FileType.PHP_SCRIPT
        if 'perl' in first_line:
            return FileType.PERL_SCRIPT
        # Unknown shebang - treat as shell script (most common)
        return FileType.SHELL_SCRIPT

    # Check for PHP opening tag (without shebang)
    if b'<?php' in header or header.startswith(b'<?'):
        return FileType.PHP_SCRIPT

    # Check if readable as text (no null bytes in first 8KB)
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' not in chunk:
                return FileType.TEXT_FILE
    except Exception:
        pass

    return FileType.UNKNOWN


def is_elf_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            return header == b'\x7fELF'
    except Exception as e:
        return False

def get_imported_function_list(binary_path: str) -> list[str]:
    try:
        output = subprocess.check_output(
            ['readelf', '-a', '--wide', binary_path], stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        # Ignore binaries that are not ELF
        return []

    patterns = [
        # 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND upscli_connect
        r'FUNC.*UND\s+([^\s@]+)',

        # 0x0000000000000000     0 R_ARM_JUMP_SLOT   upscli_connect
        # NOTE: Temporarily disable this pattern due to false positives
        # NOTE: Maybe make this pattern better in the future.
        # r'(?:R_ARM_JUMP_SLOT|R_X86_64_JUMP_SLOT)\s+\d+\s+([^\s@]+)'
    ]
    merged_pattern = re.compile('|'.join(patterns), re.MULTILINE)

    imported_functions = []
    for match in re.finditer(merged_pattern, output):
        imported_functions.append(match.group(1) or match.group(2))

    return imported_functions

def get_exported_function_list(binary_path: str) -> list[str]:
    try:
        output = subprocess.check_output(
            ['readelf', '-s', '--wide', binary_path], stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        # Ignore binaries that are not ELF
        return []

    pattern = re.compile(r'^\s*\d+\s+FUNC\s+GLOBAL\s+\d+\s+([^\s@]+)')
    exported_functions = []
    for match in re.finditer(pattern, output):
        exported_functions.append(match.group(1))

    return exported_functions
