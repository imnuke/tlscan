"""Unified analysis request tools for supervisor agent.

This module provides a unified interface for the supervisor to request analysis
from specialized agents. All tools follow the `request_*` naming pattern and
support both main binary analysis and dynamic binary analysis.
"""

from langchain.tools import tool
from rich.console import Console

from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.utils.formatting import count_tokens, format_token_count

# Initialize console
console = Console()


def create_request_binary_analysis_tool(binary_registry):
    """Create the request_binary_analysis tool with access to the binary registry.

    Args:
        binary_registry: BinaryRegistry instance

    Returns:
        Tool function with registry bound via closure
    """

    @tool
    async def request_binary_analysis(
        binary_path: str,
        agent_type: str,
        task_description: str
    ) -> str:
        """Request analysis from a specialized agent for a specific binary.

        This tool enables the supervisor to request analysis of any binary (main or
        dynamically discovered). The binary registry handles:
        - Checking if binary is already registered
        - If not: allocating port, starting MCP server, creating agents
        - Retrieving the appropriate agent (dataflow or ssl)
        - Executing the agent with the task description

        Use this tool when:
        - Analyzing the main binary (SSL security analysis, dataflow tracing)
        - Analyzing related binaries found by firmware agent
        - Tracing dataflow across multiple binaries

        Args:
            binary_path: Path to binary (can be relative to firmware or absolute)
            agent_type: Type of agent to use ("dataflow" or "ssl")
            task_description: What to analyze (e.g., "Trace variable X", "Check SSL security")

        Returns:
            Analysis results from the requested agent

        Examples:
            # Analyze main binary SSL security
            request_binary_analysis("/usr/bin/client", "ssl", "Analyze SSL/TLS security")

            # Trace dataflow in related binary
            request_binary_analysis("/lib/libssl.so", "dataflow", "Trace parameter mode to SSL_CTX_set_verify")
        """
        # Validate agent_type
        if agent_type not in ["dataflow", "ssl"]:
            return f"ERROR: Invalid agent_type '{agent_type}'. Must be 'dataflow' or 'ssl'."

        try:
            console.print(f"\n[cyan]📊 Requesting {agent_type} analysis for: {binary_path}[/cyan]")

            # Get or create binary entry
            entry = binary_registry.get_binary_entry(binary_path)

            if entry is None:
                # Binary not registered yet - register it
                console.print(f"[dim]  ├─ Binary not registered, initializing...[/dim]")
                entry = await binary_registry.register_binary(binary_path)

            # Get the requested agent
            agent = entry.agents.get(agent_type)

            if agent is None:
                return f"ERROR: Agent type '{agent_type}' not found for binary {binary_path}"

            # Log request
            request_tokens = count_tokens(task_description)
            console.print(f"[dim]  ├─ Request: {format_token_count(request_tokens)} tokens[/dim]")
            console.print()

            # Execute agent
            emoji_map = {"dataflow": "🔍", "ssl": "🔐"}
            result = await stream_and_log_agent(
                agent=agent,
                messages=[{"role": "user", "content": task_description}],
                agent_name=f"{agent_type.upper()} Agent ({binary_path})",
                agent_emoji=emoji_map.get(agent_type, "📊")
            )

            # Log response
            response_tokens = count_tokens(result)
            console.print(f"\n[dim]  └─ Response: {format_token_count(response_tokens)} tokens[/dim]")

            return result

        except FileNotFoundError as e:
            error_msg = f"ERROR: Binary file not found: {binary_path}\n{str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            return error_msg
        except Exception as e:
            error_msg = f"ERROR: Failed to analyze binary {binary_path}: {str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            return error_msg

    return request_binary_analysis


def create_request_firmware_explore_tool(firmware_agent):
    """Create the request_firmware_explore tool with access to firmware agent.

    Args:
        firmware_agent: Firmware agent instance (or None if no firmware)

    Returns:
        Tool function with firmware agent bound via closure
    """

    @tool
    async def request_firmware_explore(task_description: str) -> str:
        """Request filesystem exploration from the firmware agent.

        This tool enables the supervisor to search and analyze the firmware filesystem:
        - Find binaries by name or symbol
        - Search for strings/patterns in files
        - Read configuration files and scripts
        - Trace cross-binary function calls
        - Find which binaries import/export functions

        Use this tool when:
        - SSL agent needs to find caller binaries (STATUS: NEED_CROSS_BINARY_ANALYSIS)
        - Need to read config files (STATUS: NEED_CONFIG_ANALYSIS)
        - Need to understand cross-binary relationships
        - Searching for how binaries interact

        Args:
            task_description: What to search/analyze in firmware

        Returns:
            Firmware analysis results

        Examples:
            # Find caller binaries
            request_firmware_explore("Find which binaries call SSL_connect")

            # Read config file
            request_firmware_explore("Read /etc/ssl.conf and find the default verify_mode setting")

            # Find binary symbols
            request_firmware_explore("List all exported functions in /lib/libssl.so")
        """
        if firmware_agent is None:
            return "ERROR: Firmware agent not available. Firmware path not provided at startup."

        try:
            console.print(f"\n[cyan]🗂️  Firmware exploration request[/cyan]")

            # Log request
            request_tokens = count_tokens(task_description)
            console.print(f"[dim]  ├─ Request: {format_token_count(request_tokens)} tokens[/dim]")
            console.print()

            # Execute firmware agent
            result = await stream_and_log_agent(
                agent=firmware_agent,
                messages=[{"role": "user", "content": task_description}],
                agent_name="Firmware Explorer Agent",
                agent_emoji="🗂️"
            )

            # Log response
            response_tokens = count_tokens(result)
            console.print(f"\n[dim]  └─ Response: {format_token_count(response_tokens)} tokens[/dim]")

            return result

        except Exception as e:
            error_msg = f"ERROR: Firmware exploration failed: {str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            return error_msg

    return request_firmware_explore


def create_cleanup_binary_analysis_tool(binary_registry):
    """Create the cleanup_binary_analysis tool with access to binary registry.

    Args:
        binary_registry: BinaryRegistry instance

    Returns:
        Tool function with registry bound via closure
    """

    @tool
    def cleanup_binary_analysis(binary_path: str) -> str:
        """Clean up resources for a binary when analysis is complete.

        This tool allows the supervisor to explicitly free resources (MCP server,
        port allocation) for a binary that's no longer needed. This is optional -
        all resources will be cleaned up automatically at shutdown.

        Use this tool when:
        - Finished analyzing a related binary and won't need it again
        - Want to free up ports for other binaries (resource management)
        - Analysis is complete and cleanup is desired

        Args:
            binary_path: Path to binary to cleanup

        Returns:
            Success or error message

        Example:
            # After tracing dataflow in libssl.so, clean up
            cleanup_binary_analysis("/lib/libssl.so")
        """
        try:
            success = binary_registry.cleanup_binary(binary_path)

            if success:
                return f"SUCCESS: Cleaned up resources for {binary_path}"
            else:
                return f"WARNING: Binary {binary_path} was not registered (nothing to cleanup)"

        except Exception as e:
            error_msg = f"ERROR: Failed to cleanup {binary_path}: {str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            return error_msg

    return cleanup_binary_analysis
