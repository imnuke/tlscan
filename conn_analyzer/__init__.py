"""
conn_analyzer - SSL/TLS Security Analysis Tool for Firmware Binaries.

This package provides multi-agent analysis of SSL/TLS security in firmware binaries
using IDA Pro and LangChain agents.
"""

__version__ = "0.1.0"
__author__ = "Peng"

# Convenience imports for external use
from conn_analyzer.config import (
    TOKEN_WARNING_THRESHOLD,
    IDA_SERVER_HOST,
    PORT_RANGE_START,
    PORT_RANGE_END,
    PORT_LOCK_TIMEOUT,
    TEMP_FILES_DIR,
    SECURITY_RULES_DIR,
)

__all__ = [
    "__version__",
    "__author__",
    "TOKEN_WARNING_THRESHOLD",
    "IDA_SERVER_HOST",
    "PORT_RANGE_START",
    "PORT_RANGE_END",
    "PORT_LOCK_TIMEOUT",
    "TEMP_FILES_DIR",
    "SECURITY_RULES_DIR",
]
