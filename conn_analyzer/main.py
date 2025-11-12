"""
Main orchestrator for conn_analyzer.

Coordinates IDA integration, agent creation, and analysis execution using
LangGraph-based workflow with support for dynamic multi-binary analysis.
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
from conn_analyzer.graph.state import create_initial_state
from conn_analyzer.graph.workflow import create_analysis_graph, run_analysis

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
    from conn_analyzer.config_loader import get_config, ConfigurationError

    if ":" in model:
        provider, model_name = model.split(":", 1)

        # Load provider configuration from YAML
        try:
            config = get_config()
            provider_config = config.get_provider_config(provider)
        except ConfigurationError as e:
            console.print(f"[red]Configuration Error:[/red] {e}")
            raise

        api_key = provider_config['api_key']
        api_base = provider_config.get('api_base')

        if provider == "openai":
            from langchain_openai import ChatOpenAI
            kwargs = {"model": model_name, "api_key": api_key}
            if api_base:
                kwargs["base_url"] = api_base
            return ChatOpenAI(**kwargs), model_name
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model_name, api_key=api_key), model_name
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek
            kwargs = {"model": model_name, "api_key": api_key}
            if api_base:
                kwargs["base_url"] = api_base
            return ChatDeepSeek(**kwargs), model_name
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
    Main function to analyze SSL/TLS connections using LangGraph-based multi-agent system.

    This function implements a graph-based workflow architecture where all analysis
    steps are orchestrated through LangGraph's StateGraph.

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
        "[bold cyan]🔍 conn-analyzer - LangGraph-Based SSL/TLS Security Analysis[/bold cyan]",
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
    security_rules_content = load_security_rules(rules)
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
        port_manager=port_manager,
        security_rules_content=security_rules_content
    )
    console.print()

    try:
        # 4. Register main binary
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

        # 6. Create LangGraph workflow
        console.print("[cyan]🎯 Building analysis workflow graph...[/cyan]")
        graph = create_analysis_graph(
            binary_registry=binary_registry,
            firmware_agent=firmware_agent
        )
        console.print("[green]✓ Workflow graph ready[/green]")
        console.print()

        # 7. Create initial state
        initial_state = create_initial_state(
            binary_path=file_path,
            security_rules=security_rules_content
        )

        # 8. Execute workflow
        console.print()
        console.print(Panel.fit(
            "[bold green]🚀 Starting Graph-Based Security Analysis[/bold green]",
            border_style="green"
        ))
        console.print()

        final_state = await run_analysis(
            graph=graph,
            initial_state=initial_state,
            config={"recursion_limit": 100}
        )

        # 9. Display final report
        console.print()
        console.print(Panel.fit(
            "[bold green]✓ Analysis Complete[/bold green]",
            border_style="green"
        ))
        console.print()

        final_report = final_state.get("final_report")
        if final_report:
            console.print("[bold cyan]📊 Final Security Report:[/bold cyan]")
            console.print()
            console.print(final_report)
        else:
            console.print("[yellow]⚠ No final report generated[/yellow]")

    except Exception as e:
        console.print()
        console.print(f"[bold red]✗ Analysis failed: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        raise

    finally:
        # 10. Cleanup all resources
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
