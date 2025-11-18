import re
import subprocess

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
        r'(?:R_ARM_JUMP_SLOT|R_X86_64_JUMP_SLOT)\s+\d+\s+([^\s@]+)'
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
