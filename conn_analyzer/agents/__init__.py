"""
Agent system.

Provides multi-agent SSL/TLS security analysis infrastructure.
"""

from conn_analyzer.agents.factory import create_agents_for_binary

__all__ = [
    "create_agents_for_binary",
]
