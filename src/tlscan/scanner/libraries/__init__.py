"""Library registry for network client detection.

Provides a central registry of all supported library definitions
and helper functions for library lookup.
"""

from typing import Dict, List, Optional

from .base import LibraryDefinition
from .openssl import OPENSSL
from .libcurl import LIBCURL
from .gnutls import GNUTLS
from .mbedtls import MBEDTLS
from .curl_wget import CURL_WGET
from .php_curl import PHP_CURL

# Central registry of all library definitions
LIBRARY_REGISTRY: Dict[str, LibraryDefinition] = {
    "openssl": OPENSSL,
    "libcurl": LIBCURL,
    "gnutls": GNUTLS,
    "mbedtls": MBEDTLS,
    "curl_wget": CURL_WGET,
    "php_curl": PHP_CURL,
}


def get_library(library_id: str) -> Optional[LibraryDefinition]:
    """Get a library definition by ID.

    Args:
        library_id: Library identifier (e.g., 'openssl', 'libcurl')

    Returns:
        LibraryDefinition if found, None otherwise
    """
    return LIBRARY_REGISTRY.get(library_id)


def get_libraries_for_file_type(file_type: str) -> List[LibraryDefinition]:
    """Get all libraries applicable to a file type.

    Args:
        file_type: File type string (e.g., 'elf_binary', 'php_script')

    Returns:
        List of LibraryDefinition objects applicable to the file type
    """
    return [
        lib for lib in LIBRARY_REGISTRY.values()
        if file_type in lib.applicable_file_types
    ]


def list_library_ids() -> List[str]:
    """List all registered library IDs.

    Returns:
        List of library ID strings
    """
    return list(LIBRARY_REGISTRY.keys())


def get_library_info() -> Dict[str, Dict[str, str]]:
    """Get information about all registered libraries.

    Returns:
        Dict mapping library IDs to info dicts with 'name' and 'description'
    """
    return {
        lib_id: {
            "name": lib.name,
            "description": lib.description,
            "detection_method": lib.detection_method,
        }
        for lib_id, lib in LIBRARY_REGISTRY.items()
    }


# Re-export commonly used items
__all__ = [
    "LIBRARY_REGISTRY",
    "get_library",
    "get_libraries_for_file_type",
    "list_library_ids",
    "get_library_info",
    "LibraryDefinition",
]
