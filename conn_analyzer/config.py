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

IDA_SERVER_PORT = 3002
"""Port for headless IDA server."""

IDA_SERVER_STARTUP_TIMEOUT = 30
"""Timeout in seconds for IDA server to start."""

IDA_SERVER_READINESS_CHECK_INTERVAL = 0.5
"""Interval in seconds between IDA server readiness checks."""

# ============================================================================
# Call Graph Configuration
# ============================================================================

DEFAULT_MAX_HOPS = 3
"""Maximum hops from SSL functions to keep when trimming call graphs."""

TRIM_THRESHOLD_NODES = 100
"""Auto-trim call graph if it exceeds this many nodes."""

CENTRALITY_PERCENTILE = 0.80
"""Keep nodes in top 20% by betweenness centrality when trimming."""

# ============================================================================
# File Paths
# ============================================================================

TEMP_FILES_DIR = Path("temp_files")
"""Directory for temporary files (call graphs, etc.)."""

SECURITY_RULES_DIR = Path("security_rules")
"""Directory containing security rule markdown files."""

# ============================================================================
# Logging Configuration
# ============================================================================

# Suppress verbose HTTP logs from MCP client (SSE transport)
LOG_LEVEL_HTTPX = "WARNING"
LOG_LEVEL_HTTPCORE = "WARNING"
LOG_LEVEL_MCP = "WARNING"
