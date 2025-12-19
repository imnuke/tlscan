"""
Agent system prompts.

Provides system prompts for all agents in the tlscan system.
"""

from tlscan.analyzer.agents.prompts.dataflow import DATAFLOW_SYSTEM_PROMPT
from tlscan.analyzer.agents.prompts.ssl import get_ssl_system_prompt
from tlscan.analyzer.agents.prompts.firmware import get_firmware_system_prompt

__all__ = [
    "DATAFLOW_SYSTEM_PROMPT",
    "get_ssl_system_prompt",
    "get_firmware_system_prompt",
]
