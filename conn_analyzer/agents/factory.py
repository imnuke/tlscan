"""
Agent factory.

Creates and initializes all agents with proper configuration.
"""

import sys
from pathlib import Path
from langchain.agents import create_agent

# Add project root to path to import firmware_tools
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import firmware_tools

from conn_analyzer.agents.core.middleware import handle_tool_errors
from conn_analyzer.agents.prompts import (
    DATAFLOW_SYSTEM_PROMPT,
    get_ssl_system_prompt,
    get_firmware_system_prompt,
    get_supervisor_system_prompt,
)
import conn_analyzer.agents.tools.agent_wrappers as agent_wrappers


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


def create_all_agents(
    model: str,
    tools: list,
    security_rules_content: str = "",
    firmware_path: str | None = None
) -> dict:
    """
    Create all agents with proper configuration.

    Args:
        model: Model name to use for agents
        tools: List of IDA Pro MCP tools
        security_rules_content: Security rules content (optional)
        firmware_path: Path to firmware root (optional)

    Returns:
        Dictionary with agent instances: {
            'dataflow': dataflow_agent,
            'ssl': ssl_analyzing_agent,
            'firmware': firmware_traverse_agent (if firmware_path provided),
            'supervisor': supervisor_agent
        }
    """
    # Create dataflow agent
    dataflow_agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=DATAFLOW_SYSTEM_PROMPT
    )

    # Create SSL analyzing agent
    ssl_analyzing_agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=get_ssl_system_prompt(security_rules_content)
    )

    # Create firmware agent if path provided
    firmware_traverse_agent = None
    if firmware_path:
        # Initialize firmware tools
        firmware_tools.set_firmware_root(firmware_path)

        # Get firmware analysis tools
        fw_tools = [
            firmware_tools.search_files_by_name,
            firmware_tools.search_files_by_content,
            firmware_tools.read_file,
            firmware_tools.list_binary_symbols,
            firmware_tools.find_binaries_with_symbol,
            firmware_tools.find_function_references
        ]

        firmware_traverse_agent = create_agent(
            model=model,
            tools=fw_tools,
            middleware=[handle_tool_errors],
            system_prompt=get_firmware_system_prompt(firmware_path)
        )

    # Set global agent references in agent_wrappers module
    agent_wrappers.dataflow_agent = dataflow_agent
    agent_wrappers.ssl_analyzing_agent = ssl_analyzing_agent
    agent_wrappers.firmware_traverse_agent = firmware_traverse_agent

    # Build supervisor tools
    supervisor_tools = tools + [
        agent_wrappers.call_ssl_agent,
        agent_wrappers.call_dataflow_agent
    ]
    if firmware_traverse_agent is not None:
        supervisor_tools.append(agent_wrappers.call_firmware_agent)

    # Create supervisor agent
    supervisor_agent = create_agent(
        model=model,
        tools=supervisor_tools,
        middleware=[handle_tool_errors],
        system_prompt=get_supervisor_system_prompt(
            firmware_available=(firmware_path is not None)
        )
    )

    return {
        'dataflow': dataflow_agent,
        'ssl': ssl_analyzing_agent,
        'firmware': firmware_traverse_agent,
        'supervisor': supervisor_agent
    }
