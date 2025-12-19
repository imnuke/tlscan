"""Static analysis infrastructure.

This module provides the infrastructure layer for managing IDA Pro MCP servers
and obtaining static analysis tools. It is separate from agent creation.
"""

from tlscan.analyzer.static_engine.engine import (
    MCPSession,
    StaticAnalysisEngine,
)

__all__ = [
    "MCPSession",
    "StaticAnalysisEngine",
]
