"""
Main orchestrator for conn_analyzer.

Coordinates IDA integration, agent creation, and analysis execution with
support for dynamic multi-binary analysis.
"""

import os
import sys
import time
import logging
from pathlib import Path

# Add project root to path for importing project modules
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from rich.console import Console
from rich.panel import Panel

from conn_analyzer.config import (
    LOG_LEVEL_HTTPX,
    LOG_LEVEL_HTTPCORE,
    LOG_LEVEL_MCP,
)
from conn_analyzer.utils.file_utils import (
    resolve_binary_path,
    load_security_rules,
)
from conn_analyzer.utils.formatting import format_duration
from conn_analyzer.ida_integration.port_manager import PortManager
from conn_analyzer.ida_integration.binary_manager import BinaryRegistry
from conn_analyzer.agents.factory import create_all_agents
from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.agents.tools.analysis_requests import (
    create_request_binary_analysis_tool,
    create_request_firmware_explore_tool,
    create_cleanup_binary_analysis_tool,
)

import firmware_tools

# Configure logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("mcp").setLevel(logging.WARNING)

# Initialize console
console = Console()


def parse_model_string(model: str):
    """Parse model string to get provider and model name.

    Args:
        model: Model string (e.g., "deepseek-chat", "openai:gpt-4", "anthropic:claude-sonnet-4")

    Returns:
        Tuple of (llm_instance, model_name)
    """
    if ":" in model:
        provider, model_name = model.split(":", 1)
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=model_name), model_name
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model_name), model_name
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek
            return ChatDeepSeek(model=model_name), model_name
        else:
            raise ValueError(f"Unknown provider: {provider}")
    else:
        raise ValueError("Model string must be in format 'provider:model_name'")


async def main(
    file_path: str,
    model: str = "deepseek-chat",
    conn_type: str = "headless_ida",
    firmware_path: str = None,
    rules: str = "openssl"
):
    """
    Main function to analyze SSL/TLS connections using multi-agent system.

    This function implements a unified architecture where all binaries (main and
    dynamically discovered) are treated uniformly through a BinaryRegistry.

    Args:
        file_path: Path to binary file to analyze
        model: LLM model to use (default: "deepseek-chat")
        conn_type: Connection type (currently unused, always headless_ida)
        firmware_path: Path to firmware filesystem root (optional)
        rules: SSL/TLS library rules to use (default: "openssl")
    """
    total_start_time = time.perf_counter()

    console.print()
    console.print(Panel.fit(
        "[bold cyan]🔍 conn-analyzer - Dynamic Multi-Binary SSL/TLS Security Analysis[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    # 1. Load config and resolve paths
    file_path = resolve_binary_path(file_path, firmware_path)
    console.print(f"[cyan]📁 Analyzing binary:[/cyan] {file_path}")
    console.print(f"[cyan]📚 Library rules:[/cyan] {rules}")
    if firmware_path:
        console.print(f"[cyan]🗂️  Firmware root:[/cyan] {firmware_path}")
    console.print()

    # Load security rules
    start_time = time.perf_counter()
    security_rules_content = load_security_rules(rules)
    elapsed = time.perf_counter() - start_time
    console.print(f"[dim]⏱  Security rules loading: {format_duration(elapsed)}[/dim]")
    console.print()

    # Parse model
    llm, model_name = parse_model_string(model)
    console.print(f"[cyan]🤖 LLM Model:[/cyan] {model_name}")
    console.print()

    # 2. Initialize port manager
    console.print("[cyan]🔧 Initializing port manager...[/cyan]")
    port_manager = PortManager()
    stale_count = port_manager.cleanup_stale_locks()
    if stale_count > 0:
        console.print(f"[dim]  └─ Cleaned up {stale_count} stale port locks[/dim]")
    console.print()

    # 3. Initialize binary registry
    console.print("[cyan]📦 Initializing binary registry...[/cyan]")
    binary_registry = BinaryRegistry(
        firmware_path=firmware_path,
        llm=llm,
        port_manager=port_manager
    )
    console.print()

    try:
        # 4. Register main binary (unified handling)
        console.print(f"[cyan]🚀 Registering main binary:[/cyan] {file_path}")
        main_entry = await binary_registry.register_binary(file_path)
        console.print()

        # 5. Create firmware agent (if firmware provided)
        firmware_agent = None
        if firmware_path:
            console.print("[cyan]🗂️  Initializing firmware agent...[/cyan]")
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

            # Import here to avoid circular dependency
            from langchain.agents import create_agent
            from conn_analyzer.agents.core.middleware import handle_tool_errors
            from conn_analyzer.agents.prompts import get_firmware_system_prompt

            firmware_agent = create_agent(
                model=llm,
                tools=fw_tools,
                middleware=[handle_tool_errors],
                system_prompt=get_firmware_system_prompt(firmware_path)
            )
            console.print("[green]✓ Firmware agent ready[/green]")
            console.print()

        # 6. Create supervisor agent with unified tools
        console.print("[cyan]🎯 Creating supervisor agent...[/cyan]")

        # Create unified supervisor tools
        request_binary_analysis = create_request_binary_analysis_tool(binary_registry)
        request_firmware_explore = create_request_firmware_explore_tool(firmware_agent)
        cleanup_binary_analysis = create_cleanup_binary_analysis_tool(binary_registry)

        supervisor_tools = [
            request_binary_analysis,
            request_firmware_explore,
            cleanup_binary_analysis,
        ]

        # Import supervisor prompt
        from langchain.agents import create_agent
        from conn_analyzer.agents.core.middleware import handle_tool_errors
        from conn_analyzer.agents.prompts import get_supervisor_system_prompt

        supervisor_agent = create_agent(
            model=llm,
            tools=supervisor_tools,
            middleware=[handle_tool_errors],
            system_prompt=get_supervisor_system_prompt(
                firmware_available=(firmware_path is not None)
            )
        )
        console.print("[green]✓ Supervisor agent ready[/green]")
        console.print()

        # 7. Define user prompt for supervisor
        user_prompt = (
            f"Orchestrate SSL/TLS security analysis for this binary: {file_path}\n\n"
            f"Main binary path: {file_path}\n"
            f"Library: {rules}\n\n"
            "YOUR FIRST ACTION: Call request_binary_analysis('{main_binary_path}', 'ssl', 'Analyze SSL/TLS security for this binary')\n"
            f"Use main_binary_path = '{file_path}'\n\n"
            "Do this IMMEDIATELY - do not gather information yourself first.\n\n"
            "After calling the SSL agent:\n"
            "- If STATUS: COMPLETE → Validate results and synthesize final report\n"
            "- If STATUS: NEED_DATAFLOW → Call request_binary_analysis with 'dataflow' agent type\n"
            "- If STATUS: NEED_CROSS_BINARY_ANALYSIS → Use request_firmware_explore to find callers, then request_binary_analysis for each\n"
            "- If STATUS: NEED_CONFIG_ANALYSIS → Use request_firmware_explore to read configs\n"
            "- If STATUS: NEED_FIRMWARE → Use request_firmware_explore as needed\n"
            "- If STATUS: NOT_APPLICABLE → Report that binary is not applicable\n\n"
            "Final report must have EXACTLY these 3 sections:\n"
            "SECTION 1 - Client Summary\n"
            "SECTION 2 - Rule Checking Results (PASS/FAIL/CONDITIONAL with evidence)\n"
            "SECTION 3 - Dataflow Analysis\n\n"
            "Remember: The SSL and dataflow agents analyze. You orchestrate."
        )

        # 8. Execute supervisor agent
        console.print()
        console.print(Panel.fit(
            "[bold green]🚀 Starting Security Analysis[/bold green]",
            border_style="green"
        ))
        console.print()

        await stream_and_log_agent(
            agent=supervisor_agent,
            messages=[{"role": "user", "content": user_prompt}],
            agent_name="Supervisor Agent",
            agent_emoji="🎯"
        )

    except Exception as e:
        console.print()
        console.print(f"[bold red]✗ Analysis failed: {e}[/bold red]")
        raise

    finally:
        # 9. Cleanup all resources
        console.print()
        console.print("[cyan]🧹 Cleaning up resources...[/cyan]")

        if 'binary_registry' in locals():
            binary_registry.cleanup_all()

        if 'port_manager' in locals():
            port_manager.cleanup_stale_locks()

        console.print("[green]✓ Cleanup complete[/green]")

        # Display total elapsed time
        total_elapsed = time.perf_counter() - total_start_time
        console.print()
        console.print(Panel.fit(
            f"[bold blue]⏱  Total Analysis Time: {format_duration(total_elapsed)}[/bold blue]",
            border_style="blue"
        ))
        console.print()
