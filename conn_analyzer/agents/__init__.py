"""
Agent system.

Provides multi-agent SSL/TLS security analysis infrastructure.
"""

from conn_analyzer.agents.factory import create_all_agents

__all__ = [
    "create_all_agents",
]
