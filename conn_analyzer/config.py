"""
Configuration constants for conn_analyzer.

This module centralizes all configuration constants used throughout the application.
"""

from pathlib import Path

# ============================================================================
# Token Management
# ============================================================================

TOKEN_WARNING_THRESHOLD = 8000
"""Threshold for warning about large token counts in agent messages."""

# ============================================================================
# IDA Integration
# ============================================================================

IDA_SERVER_HOST = "localhost"
"""Host for headless IDA server."""

IDA_SERVER_STARTUP_TIMEOUT = 300
"""Timeout in seconds for IDA server to start."""

IDA_SERVER_READINESS_CHECK_INTERVAL = 0.5
"""Interval in seconds between IDA server readiness checks."""

# ============================================================================
# Port Allocation
# ============================================================================

PORT_RANGE_START = 8800
"""Start of port range for dynamic MCP server allocation."""

PORT_RANGE_END = 8900
"""End of port range for dynamic MCP server allocation."""

PORT_LOCK_TIMEOUT = 3600
"""Timeout in seconds for port locks (1 hour). Locks older than this are considered stale."""

# ============================================================================
# File Paths
# ============================================================================

TEMP_FILES_DIR = Path("/tmp/conn_analyzer")
"""Directory for temporary files."""

PORT_LOCK_DIR = TEMP_FILES_DIR / "port_locks"
"""Directory for port lock files used in multi-instance coordination."""

IDA_SERVER_LOGS_DIR = TEMP_FILES_DIR / "ida_server_logs"
"""Directory for IDA MCP server log files."""

TEMP_BINARIES_DIR = TEMP_FILES_DIR / "binaries"
"""Directory for temporary binary copies used during analysis."""

SECURITY_RULES_DIR = Path("security_rules")
"""Directory containing security rule markdown files."""

# ============================================================================
# Logging Configuration
# ============================================================================

# Suppress verbose HTTP logs from MCP client (SSE transport)
LOG_LEVEL_HTTPX = "WARNING"
LOG_LEVEL_HTTPCORE = "WARNING"
LOG_LEVEL_MCP = "WARNING"

# ============================================================================
# LLM Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
"""Root directory of the project."""

LLM_CONFIG_FILE = PROJECT_ROOT / "llm_config.yaml"
"""Path to the LLM API configuration file."""

LLM_CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "llm_config.example.yaml"
"""Path to the example LLM configuration file."""
