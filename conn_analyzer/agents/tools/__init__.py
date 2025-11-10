"""
Agent tool wrappers.

Provides wrapper functions for inter-agent communication.
"""

from conn_analyzer.agents.tools.agent_wrappers import (
    call_dataflow_agent,
    call_ssl_agent,
    call_firmware_agent,
)

__all__ = [
    "call_dataflow_agent",
    "call_ssl_agent",
    "call_firmware_agent",
]
