"""
Agent tool wrappers.

Provides wrapper functions for calling specialized agents.
"""

from langchain_core.tools import tool
from rich.console import Console

from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.utils.formatting import count_tokens, format_token_count
from conn_analyzer.config import TOKEN_WARNING_THRESHOLD

# Initialize console for output
console = Console()

# Global agent references - will be set by factory
dataflow_agent = None
ssl_analyzing_agent = None
firmware_traverse_agent = None


@tool
async def call_dataflow_agent(request: str, context: str = "") -> str:
    """
    Perform dataflow analysis (forward/backward slicing, inter-procedural).

    Use this tool to trace:
    - Where a variable's value flows TO (forward slicing)
    - Where a variable's value comes FROM (backward slicing)
    - Dataflow across function boundaries (inter-procedural analysis)

    Args:
        request: Specific dataflow analysis question
        context: Relevant code/function information from IDA for analysis

    Returns:
        Dataflow analysis results with sources, sinks, and paths
    """
    full_request = f"{request}\n\nContext:\n{context}" if context else request

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 Dataflow Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=dataflow_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Dataflow Analysis Agent",
        agent_emoji="🔍"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 Dataflow Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total Dataflow Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

    return result

@tool
async def call_ssl_agent(request: str, call_graph_context: str = "") -> str:
    """
    Perform SSL/TLS security analysis on the binary.

    Use this tool to:
    - Validate binary contains client-side SSL/TLS code
    - Check compliance with SSL/TLS security rules
    - Identify conditional security behavior
    - Get rule-by-rule security analysis results

    The SSL agent can request help (dataflow tracing or firmware analysis) if needed.
    It will return one of these statuses:
    - STATUS: COMPLETE - Full analysis results ready
    - STATUS: NEED_DATAFLOW - Needs variable tracing
    - STATUS: NEED_FIRMWARE - Needs config/script analysis
    - STATUS: NOT_APPLICABLE - Binary doesn't contain client SSL code

    Args:
        request: SSL analysis request (usually "Analyze SSL/TLS security")
        call_graph_context: Call graph summary to guide analysis

    Returns:
        SSL security analysis results or help request
    """
    full_request = f"{request}\n\nCall Graph Context:\n{call_graph_context}" if call_graph_context else request

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 SSL Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=ssl_analyzing_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="SSL Security Analyzing Agent",
        agent_emoji="🔐"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 SSL Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total SSL Analysis Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

    return result

@tool
async def call_firmware_agent(request: str, context: str = "") -> str:
    """
    Analyze firmware filesystem: config files, cross-binary relationships, scripts.

    Use this tool to:
    - Find which binary defines/calls a function (cross-binary analysis)
    - Read configuration files that might affect SSL/TLS behavior
    - Search for strings/patterns in firmware files
    - Analyze startup scripts or shell scripts that configure services

    Args:
        request: Firmware analysis question (what to find/analyze)
        context: Relevant context from IDA analysis (function names, addresses, etc.)

    Returns:
        Analysis results from firmware filesystem exploration
    """
    full_request = f"{request}\n\nContext:\n{context}" if context else request

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 Firmware Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=firmware_traverse_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Firmware Filesystem Agent",
        agent_emoji="📁"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 Firmware Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total Firmware Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

    return result

