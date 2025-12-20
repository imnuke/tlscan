"""ELF binary analysis utilities.

Provides functions for extracting symbols and library dependencies
from ELF binary files.
"""

import logging
from typing import Set, List

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    raise SystemExit("Missing dependency: pyelftools\nInstall with: pip install pyelftools")

logger = logging.getLogger(__name__)


def is_probably_elf(path: str) -> bool:
    """Check if file is likely an ELF binary by reading magic bytes.

    Args:
        path: Path to the file to check

    Returns:
        True if the file starts with ELF magic bytes, False otherwise
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception as e:
        logger.debug(f"Error checking ELF magic for {path}: {e}")
        return False


def extract_symbols(path: str) -> Set[str]:
    """Extract imported (undefined) symbol names from ELF binary.

    Collects undefined symbols from both .dynsym and .symtab sections.
    These are typically functions the binary imports from shared libraries.

    Args:
        path: Path to the ELF binary

    Returns:
        Set of symbol name strings
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
                    if sym["st_shndx"] == "SHN_UNDEF":
                        nm = sym.name
                        if nm:
                            names.add(nm)
        logger.debug(f"Extracted {len(names)} symbols from {path}")
    except Exception as e:
        logger.debug(f"Error extracting symbols from {path}: {e}")
    return names


def extract_needed_libs(path: str) -> List[str]:
    """Extract DT_NEEDED entries from ELF dynamic section.

    These are the shared libraries that the binary depends on.

    Args:
        path: Path to the ELF binary

    Returns:
        List of library names (e.g., ['libssl.so.1.1', 'libc.so.6'])
    """
    needed: List[str] = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
        logger.debug(f"Extracted {len(needed)} NEEDED libs from {path}")
    except Exception as e:
        logger.debug(f"Error extracting NEEDED libs from {path}: {e}")
    return needed
