"""
Main orchestrator for conn_analyzer.

Coordinates IDA integration, agent creation, and analysis execution.
"""

import os
import sys
import json
import time
import logging
import subprocess
from pathlib import Path

# Add project root to path for importing project modules
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console
from rich.panel import Panel

from conn_analyzer.config import (
    LOG_LEVEL_HTTPX,
    LOG_LEVEL_HTTPCORE,
    LOG_LEVEL_MCP,
    DEFAULT_MAX_HOPS,
    TRIM_THRESHOLD_NODES,
)
from conn_analyzer.utils.file_utils import (
    compute_call_graph_path,
    resolve_binary_path,
    load_security_rules,
    requires_binary_analysis,
)
from conn_analyzer.utils.formatting import format_duration
from conn_analyzer.ida_integration import (
    start_headless_ida_server,
    generate_call_graph_for_binary,
)
from conn_analyzer.agents.factory import create_all_agents
from conn_analyzer.agents.core.execution import stream_and_log_agent

# Configure logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("mcp").setLevel(logging.WARNING)

# Initialize console
console = Console()


async def main(file_path: str, model: str = "deepseek-chat", conn_type: str = "plugin", call_graph_path: str = None, firmware_path: str = None, rules: str = "openssl", port: int = 8800, max_hops: int = DEFAULT_MAX_HOPS, trim_threshold: int = TRIM_THRESHOLD_NODES, disable_trim: bool = False):
    """
    Main function to analyze SSL/TLS connections using multi-agent system.

    Args:
        model: LLM model to use (default: "deepseek-chat")
        call_graph_path: Path to call graph JSON file (default: auto-generated based on binary hash)
        firmware_path: Path to firmware filesystem root (optional, enables firmware agent)
        rules: SSL/TLS library rules to use (default: "openssl")
        max_hops: Maximum hops from SSL functions when trimming (default: DEFAULT_MAX_HOPS)
        trim_threshold: Auto-trim if graph exceeds this many nodes (default: TRIM_THRESHOLD_NODES)
        disable_trim: Disable automatic call graph trimming (default: False)
    """
    total_start_time = time.perf_counter()

    # Resolve binary path (handles relative paths against firmware_path or CWD)
    file_path = resolve_binary_path(file_path, firmware_path)

    # Auto-generate unique call graph path if not provided
    if call_graph_path is None:
        call_graph_path = compute_call_graph_path(file_path)
        console.print(f"[dim]📊 Call graph path: {call_graph_path}[/dim]")

    # Load security rules for the specified library
    start_time = time.perf_counter()
    security_rules_content = load_security_rules(rules)
    elapsed = time.perf_counter() - start_time
    console.print(f"[dim]⏱  Security rules loading: {format_duration(elapsed)}[/dim]")
    console.print()

    # Generate or load call graph based on connection type
    call_graph_data = None
    server_process = None  # Track server process for cleanup
    server_script = '/home/peng/Projects/others/ida-pro-mcp/src/ida_pro_mcp/server.py'

    # Check if library requires binary analysis (call graph generation)
    needs_call_graph = requires_binary_analysis(rules)
    if not needs_call_graph:
        console.print(f"[cyan]ℹ[/cyan]  Library '{rules}' is script-based, skipping call graph generation")
        console.print()

    try:
        # Generate call graph BEFORE starting MCP server (only for binary libraries)
        # (Both use idalib and can't run simultaneously)
        if needs_call_graph:
            try:
                call_graph_data = generate_call_graph_for_binary(
                    binary_path=file_path,
                    output_json_path=call_graph_path,
                    library=rules,
                    enable_ida_msg=False,
                    max_hops=max_hops,
                    trim_threshold=trim_threshold,
                    disable_trim=disable_trim
                )
            except Exception as e:
                console.print(f"[bold red]✗[/bold red] Cannot continue without call graph. Exiting.")
                raise

        # Now start headless IDA server (database is closed from graph generation)
        # Auto-start headless IDA server
        server_process = start_headless_ida_server(file_path, port=port)

        server_config = {
            "idapro": {
                "transport": "sse",
                "url": f"http://localhost:{port}/sse"
            }
        }

        start_time = time.perf_counter()
        client = MultiServerMCPClient(server_config)
        tools = await client.get_tools()
        elapsed = time.perf_counter() - start_time
        console.print(f"[green]✓[/green] Successfully loaded [bold]{len(tools)}[/bold] tools from MCP server ({format_duration(elapsed)})")

    except Exception as e:
        if server_process:
            console.print("[yellow]⚠[/yellow]  Terminating headless server due to error...")
            server_process.terminate()
            server_process.wait()
        console.print(f"[bold red]✗[/bold red] Failed to connect to MCP server: {e}")
        console.print("[bold red]✗[/bold red] Cannot continue without MCP tools. Exiting.")
        raise  # Re-raise exception to terminate

    # Format call graph context (currently disabled - can be enabled if needed)
    call_graph_context = ""
    # if call_graph_data:
    #     call_graph_text = format_call_graph(call_graph_data)
    #     call_graph_context = (
    #         "\n\nCALL GRAPH CONTEXT:\n"
    #         "Below is the call graph extracted from the binary showing SSL/TLS function usage and call relationships. "
    #         "Use this to guide your analysis and avoid unnecessary exploration.\n\n"
    #         + call_graph_text
    #     )

    # Create all agents using factory
    agents = create_all_agents(
        model=model,
        tools=tools,
        security_rules_content=security_rules_content,
        firmware_path=firmware_path,
        call_graph_context=call_graph_context
    )
    
    dataflow_agent = agents['dataflow']
    ssl_analyzing_agent = agents['ssl']
    firmware_traverse_agent = agents['firmware']
    supervisor_agent = agents['supervisor']

    # Define user prompt for supervisor agent
    user_prompt = (
        "Orchestrate SSL/TLS security analysis for this binary.\n\n"
        "YOUR FIRST ACTION: Call call_ssl_agent with the call graph context from your system prompt.\n"
        "Do this IMMEDIATELY - do not gather information yourself first.\n\n"
        "After calling the SSL agent:\n"
        "- If STATUS: COMPLETE → Validate results and synthesize final report\n"
        "- If STATUS: NEED_DATAFLOW → Call dataflow agent, pass results back to SSL agent\n"
        "- If STATUS: NEED_CROSS_BINARY_ANALYSIS → Find caller binaries, analyze each, aggregate results\n"
        "- If STATUS: NEED_CONFIG_ANALYSIS → Read config/script, parse it, pass results back\n"
        "- If STATUS: NEED_FIRMWARE → Call firmware agent, pass results back to SSL agent\n"
        "- If STATUS: NOT_APPLICABLE → Report to user that binary is not applicable\n\n"
        "Final report must have EXACTLY these 3 sections:\n"
        "SECTION 1 - Client Summary\n"
        "SECTION 2 - Rule Checking Results (PASS/FAIL/CONDITIONAL with evidence)\n"
        "SECTION 3 - Dataflow Analysis\n\n"
        "Remember: The SSL agent analyzes. You orchestrate."
    )

    # Execute supervisor agent
    try:
        await stream_and_log_agent(
            agent=supervisor_agent,
            messages=[{"role": "user", "content": user_prompt}],
            agent_name="Supervisor Agent",
            agent_emoji="🎯"
        )
    finally:
        # Clean up headless server
        if server_process:
            console.print()
            console.print("[cyan]🛑[/cyan]  Shutting down headless IDA server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
                console.print("[green]✓[/green] Server terminated successfully")
            except subprocess.TimeoutExpired:
                console.print("[yellow]⚠[/yellow]  Server did not terminate, forcing kill...")
                server_process.kill()

        # Display total elapsed time
        total_elapsed = time.perf_counter() - total_start_time
        console.print()
        console.print(Panel.fit(
            f"[bold blue]⏱  Total Analysis Time: {format_duration(total_elapsed)}[/bold blue]",
            border_style="blue"
        ))
        console.print()

