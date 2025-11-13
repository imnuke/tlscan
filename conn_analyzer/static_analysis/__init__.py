"""Static analysis infrastructure.

This module provides the infrastructure layer for managing IDA Pro MCP servers
and obtaining static analysis tools. It is separate from agent creation.
"""

from conn_analyzer.static_analysis.engine import (
    MCPSession,
    StaticAnalysisEngine,
)

__all__ = [
    "MCPSession",
    "StaticAnalysisEngine",
]
