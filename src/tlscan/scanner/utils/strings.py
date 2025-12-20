"""String extraction utilities.

Provides functions for extracting printable ASCII strings from binary files.
"""

import logging
from typing import Set, List

from ..config import PRINTABLE, ExtractionConfig, DEFAULT_CONFIG

logger = logging.getLogger(__name__)


def extract_strings(
    path: str,
    config: ExtractionConfig = DEFAULT_CONFIG.extraction,
) -> Set[str]:
    """Extract printable ASCII substrings from a binary file.

    Scans the file for sequences of printable ASCII characters
    and returns those meeting the minimum length requirement.

    Args:
        path: Path to the binary file
        config: Extraction configuration with min_string_length and max_file_size_mb

    Returns:
        Set of extracted string values
    """
    res: Set[str] = set()
    try:
        import os

        size = os.path.getsize(path)
        max_size = config.max_file_size_mb * 1024 * 1024

        if size > max_size:
            logger.debug(f"Skipping {path}: file size {size} exceeds max {max_size}")
            return res

        with open(path, "rb") as f:
            buf = f.read()

        cur: List[int] = []
        for b in buf:
            if b in PRINTABLE:
                cur.append(b)
            else:
                if len(cur) >= config.min_string_length:
                    try:
                        s = bytes(cur).decode("ascii", errors="ignore")
                        if s:
                            res.add(s)
                    except Exception:
                        pass
                cur = []

        # Handle trailing string
        if len(cur) >= config.min_string_length:
            try:
                s = bytes(cur).decode("ascii", errors="ignore")
                if s:
                    res.add(s)
            except Exception:
                pass

        logger.debug(f"Extracted {len(res)} strings from {path}")
    except Exception as e:
        logger.debug(f"Error extracting strings from {path}: {e}")
    return res


def contains_substring(corpus: Set[str], target: str) -> bool:
    """Check if any string in corpus contains the target substring.

    Used for string-based detection where exact matches are not required.

    Args:
        corpus: Set of strings to search within
        target: Substring to search for

    Returns:
        True if any string in corpus contains target, False otherwise
    """
    for s in corpus:
        if target in s:
            return True
    return False
