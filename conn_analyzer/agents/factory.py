"""
Agent factory.

Creates and initializes agents for binary analysis.
"""

import sys
from pathlib import Path
from langchain.agents import create_agent

# Add project root to path to import firmware_tools
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from conn_analyzer.agents.core.middleware import handle_tool_errors
from conn_analyzer.agents.prompts import (
    DATAFLOW_SYSTEM_PROMPT,
    get_ssl_system_prompt,
)


async def create_agents_for_binary(
    tools: list,
    binary_path: str,
    llm: any,
    security_rules_content: str = ""
) -> dict:
    """
    Create agents for a specific binary (dataflow + SSL only).

    This function is used by BinaryRegistry to create agents for dynamically
    discovered binaries. Each binary gets its own set of agents with its own
    MCP tools.

    Args:
        tools: List of IDA tools from MCP client
        binary_path: Path to the binary file
        llm: Language model instance to use
        security_rules_content: Security rules content (optional)

    Returns:
        Dictionary with agent instances: {
            'dataflow': dataflow_agent,
            'ssl': ssl_analyzing_agent
        }
    """

    # Create dataflow agent
    dataflow_agent = create_agent(
        model=llm,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=DATAFLOW_SYSTEM_PROMPT
    )

    # Create SSL analyzing agent
    ssl_analyzing_agent = create_agent(
        model=llm,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=get_ssl_system_prompt(security_rules_content)
    )

    return {
        'dataflow': dataflow_agent,
        'ssl': ssl_analyzing_agent
    }
