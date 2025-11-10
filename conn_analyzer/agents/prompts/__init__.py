"""
Agent system prompts.

Provides system prompts for all agents in the conn_analyzer system.
"""

from conn_analyzer.agents.prompts.dataflow_prompt import DATAFLOW_SYSTEM_PROMPT
from conn_analyzer.agents.prompts.ssl_prompt import get_ssl_system_prompt
from conn_analyzer.agents.prompts.firmware_prompt import get_firmware_system_prompt
from conn_analyzer.agents.prompts.supervisor_prompt import get_supervisor_system_prompt

__all__ = [
    "DATAFLOW_SYSTEM_PROMPT",
    "get_ssl_system_prompt",
    "get_firmware_system_prompt",
    "get_supervisor_system_prompt",
]
