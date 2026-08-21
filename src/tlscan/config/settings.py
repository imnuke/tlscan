"""
Configuration constants for tlscan.

This module centralizes all configuration constants used throughout the application.
"""

import os
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

PORT_RANGE_START = int(os.environ.get("TLSCAN_PORT_START", "8800"))
"""Start of port range for dynamic MCP server allocation.

Override with env TLSCAN_PORT_START to give concurrent tlscan instances
disjoint port sub-ranges (prevents cross-instance server collisions)."""

PORT_RANGE_END = int(os.environ.get("TLSCAN_PORT_END", "8900"))
"""End of port range for dynamic MCP server allocation.

Override with env TLSCAN_PORT_END (see TLSCAN_PORT_START)."""

PORT_LOCK_TIMEOUT = 3600
"""Timeout in seconds for port locks (1 hour). Locks older than this are considered stale."""

# ============================================================================
# Analysis Timeout
# ============================================================================

ANALYSIS_TOTAL_TIMEOUT = 3600
"""Total timeout in seconds for the entire analysis workflow (default: 20 minutes)."""

# ============================================================================
# File Paths
# ============================================================================

TEMP_FILES_DIR = Path(os.environ.get("TLSCAN_TEMP_DIR", "/tmp/tlscan"))
"""Directory for temporary files.

Override with env TLSCAN_TEMP_DIR so concurrent tlscan instances keep separate
port-lock, IDB and log namespaces (port_locks/, idb/, ida_server_logs/ all
derive from this). Combined with disjoint TLSCAN_PORT_START/END, this makes two
parallel runs fully isolated."""

PORT_LOCK_DIR = TEMP_FILES_DIR / "port_locks"
"""Directory for port lock files used in multi-instance coordination."""

IDA_SERVER_LOGS_DIR = TEMP_FILES_DIR / "ida_server_logs"
"""Directory for IDA MCP server log files."""

TEMP_IDB_DIR = TEMP_FILES_DIR / "idb"
"""Directory for IDB session directories used during analysis."""

# Rules directory - default to bundled rules, allow override via environment
SECURITY_RULES_DIR = Path(__file__).parent.parent / "rules"
"""Directory containing security rule markdown files."""

if custom_rules := os.environ.get("TLSCAN_RULES_DIR"):
    SECURITY_RULES_DIR = Path(custom_rules)

# Signatures directory — bundled per-library function signature YAML files
SIGNATURES_DIR = Path(__file__).parent.parent / "signatures"
"""Directory containing per-library function signature YAML files."""

if custom_sigs := os.environ.get("TLSCAN_SIGNATURES_DIR"):
    SIGNATURES_DIR = Path(custom_sigs)

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

# Project root is now 3 levels up from config/settings.py (src/tlscan/config -> project root)
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
"""Root directory of the project."""

LLM_CONFIG_FILE = PROJECT_ROOT / "llm_config.yaml"
"""Path to the LLM API configuration file."""

LLM_CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "llm_config.example.yaml"
"""Path to the example LLM configuration file."""

# ============================================================================
# Call Graph Pre-Analysis
# ============================================================================

CALL_GRAPH_MAX_DEPTH = 5
"""Maximum BFS depth when walking callers upward from API functions."""

CALL_GRAPH_MAX_NODES_PER_LEVEL = 50
"""Maximum number of nodes to expand per BFS level."""

CALL_GRAPH_MAX_TEXT_LENGTH = 4000
"""Maximum character length for the formatted call graph text passed to the agent."""
