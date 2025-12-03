"""
Main orchestrator for conn_analyzer v2.

Coordinates IDA integration, agent creation, and analysis execution using
LangGraph-based workflow with new architecture:
- StaticAnalysisEngine: Manages MCP servers
- AgentFactory: Creates agents with structured output
- Clean separation of concerns
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
from conn_analyzer.static_analysis.engine import StaticAnalysisEngine
from conn_analyzer.agents.factory import AgentFactory
from conn_analyzer.graph.state import create_initial_state
from conn_analyzer.graph.workflow import create_analysis_graph, run_analysis

from conn_analyzer.static_analysis import firmware_tools

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
        Tuple of (llm_instance, model_name, config)
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
            return ChatOpenAI(**kwargs), model_name, config
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model_name, api_key=api_key), model_name, config
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek
            kwargs = {"model": model_name, "api_key": api_key}
            if api_base:
                kwargs["base_url"] = api_base
            return ChatDeepSeek(**kwargs), model_name, config
        else:
            raise ValueError(f"Unknown provider: {provider}")
    else:
        raise ValueError("Model string must be in format 'provider:model_name'")


async def main(
    file_path: str,
    model: str = None,
    conn_type: str = "headless_ida",
    firmware_path: str = None,
    rules: str = "openssl",
    save_checkpoints: bool = False,
    thread_id: str = None,
    fork_checkpoint_id: str = None
):
    """
    Main function to analyze SSL/TLS connections using LangGraph v2 architecture.

    New architecture features:
    - StaticAnalysisEngine: Manages MCP servers independently
    - AgentFactory: Creates agents with structured Pydantic output
    - State-driven workflow: No context passing through agents
    - Optional checkpointing for state persistence and resumability

    Args:
        file_path: Path to binary file to analyze
        model: LLM model to use (required if not resuming with saved model)
        conn_type: Connection type (currently unused, always headless_ida)
        firmware_path: Path to firmware filesystem root (optional)
        rules: SSL/TLS library rules to use (default: "openssl")
        save_checkpoints: Enable automatic state checkpointing (default: False)
        thread_id: Resume from this thread ID (optional)
        fork_checkpoint_id: Fork from specific checkpoint with fresh execution (requires thread_id)
    """
    total_start_time = time.perf_counter()

    console.print()
    console.print(Panel.fit(
        "[bold cyan]🔍 conn-analyzer v2 - Structured SSL/TLS Security Analysis[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    # 1. Handle resume mode
    checkpointer = None
    run_thread_id = thread_id
    checkpoint_manager = None

    if thread_id:
        # Resume mode - load metadata
        from conn_analyzer.persistence import CheckpointManager
        checkpoint_manager = CheckpointManager()
        metadata = checkpoint_manager.get_thread_metadata(thread_id)

        if not metadata:
            console.print(f"[red]Error: Thread ID '{thread_id}' not found[/red]")
            return

        # Override parameters from metadata
        file_path = metadata['binary_path']
        rules = metadata['rules']
        firmware_path = metadata.get('firmware_path')

        # Use saved model only if user didn't provide --model
        if model is None:
            # User didn't provide --model, use saved metadata
            model = metadata.get('model')
            if not model:
                console.print(f"[red]Error: No model specified and no model in saved metadata[/red]")
                return
        # else: keep the CLI model parameter (user explicitly provided it)

        if fork_checkpoint_id:
            console.print(f"[cyan]🔀 Forking from thread:[/cyan] {thread_id}")
            console.print(f"[dim]  └─ From checkpoint: {fork_checkpoint_id}[/dim]")
            console.print(f"[yellow]  └─ Creating NEW thread with fresh execution[/yellow]")
        else:
            console.print(f"[cyan]🔄 Resuming latest checkpoint from thread:[/cyan] {thread_id}")
        console.print()

    # 2. Load config and resolve paths
    file_path = resolve_binary_path(file_path, firmware_path)
    console.print(f"[cyan]📁 Analyzing binary:[/cyan] {file_path}")
    console.print(f"[cyan]📚 Library rules:[/cyan] {rules}")
    if firmware_path:
        console.print(f"[cyan]🗂️  Firmware root:[/cyan] {firmware_path}")
    console.print()

    # Load security rules
    security_rules_content = load_security_rules(rules)
    console.print()

    # Parse model and load config
    llm, model_name, config = parse_model_string(model)
    console.print(f"[cyan]🤖 LLM Model:[/cyan] {model_name}")
    console.print(f"[cyan]🌡️  Temperature:[/cyan] {config.get_default_temperature()} (default)")
    console.print()

    # 3. Initialize checkpointing (if requested or resuming)
    if save_checkpoints or thread_id:
        from conn_analyzer.persistence import CheckpointManager

        if not checkpoint_manager:
            checkpoint_manager = CheckpointManager()

        # Initialize the async checkpointer
        await checkpoint_manager.initialize()

        checkpointer = checkpoint_manager.get_checkpointer()

        if not thread_id:
            # New run - generate thread ID and save metadata
            run_thread_id = checkpoint_manager.create_thread_id(file_path)
            checkpoint_manager.save_metadata(
                run_thread_id,
                file_path,
                rules,
                model,
                firmware_path
            )
            console.print(f"[cyan]💾 Checkpointing enabled[/cyan]")
            console.print(f"[cyan]📌 Thread ID:[/cyan] {run_thread_id}")
            console.print()

    # 4. Initialize port manager
    console.print("[cyan]🔧 Initializing port manager...[/cyan]")
    port_manager = PortManager()
    stale_count = port_manager.cleanup_stale_locks()
    if stale_count > 0:
        console.print(f"[dim]  └─ Cleaned up {stale_count} stale port locks[/dim]")
    console.print()

    # 5. Initialize Static Analysis Engine (v2 architecture)
    console.print("[cyan]🔬 Initializing Static Analysis Engine...[/cyan]")
    static_engine = StaticAnalysisEngine(
        firmware_path=firmware_path,
        port_manager=port_manager
    )
    console.print("[green]✓ Static Analysis Engine ready[/green]")
    console.print()

    # 6. Initialize Agent Factory (v2 architecture)
    console.print("[cyan]🏭 Initializing Agent Factory...[/cyan]")
    agent_factory = AgentFactory(llm=llm, config=config)
    console.print("[green]✓ Agent Factory ready (structured output enabled)[/green]")
    console.print(f"[dim]  └─ Per-agent temperatures: SSL={config.get_agent_temperature('ssl_analysis')}, "
                 f"Dataflow={config.get_agent_temperature('dataflow')}, "
                 f"Firmware={config.get_agent_temperature('firmware_exploration')}[/dim]")
    console.print()

    try:
        # 7. Pre-start MCP session for main binary
        console.print(f"[cyan]🚀 Starting MCP session for:[/cyan] {file_path}")
        await static_engine.get_tools(file_path)
        console.print()

        # 8. Prepare firmware tools (if firmware provided)
        firmware_tools_list = None
        if firmware_path:
            console.print("[cyan]🗂️  Initializing firmware tools...[/cyan]")
            firmware_tools.set_firmware_root(firmware_path)

            # Get firmware analysis tools
            firmware_tools_list = [
                firmware_tools.search_files_by_name,
                firmware_tools.search_files_by_content,
                firmware_tools.read_file,
                firmware_tools.find_function_definition,
                firmware_tools.find_function_references
            ]
            console.print(f"[green]✓ Firmware tools ready ({len(firmware_tools_list)} tools)[/green]")
            console.print()

        # 9. Create LangGraph workflow with dependency injection and checkpointing
        console.print("[cyan]🎯 Building analysis workflow graph...[/cyan]")
        graph = create_analysis_graph(
            static_engine=static_engine,
            agent_factory=agent_factory,
            firmware_tools=firmware_tools_list,
            firmware_path=firmware_path,
            checkpointer=checkpointer
        )
        console.print("[green]✓ Workflow graph ready (v2 architecture)[/green]")
        console.print()

        # 10. Create initial state
        initial_state = create_initial_state(
            binary_path=file_path,
            security_rules=security_rules_content
        )

        # If fork_checkpoint_id is provided, load that checkpoint's state for forking
        if fork_checkpoint_id and checkpointer:
            console.print(f"[cyan]🔀 Loading state from checkpoint...[/cyan]")
            try:
                # Load checkpoint state from the original thread
                checkpoint_tuple = await checkpointer.aget_tuple({
                    "configurable": {"thread_id": run_thread_id, "checkpoint_id": fork_checkpoint_id}
                })

                if checkpoint_tuple:
                    # Extract state from checkpoint
                    fork_state = checkpoint_tuple.checkpoint['channel_values']
                    initial_state = fork_state  # Use checkpoint state as initial state

                    # Create NEW thread ID for fresh execution
                    original_thread_id = run_thread_id
                    run_thread_id = checkpoint_manager.create_thread_id(file_path)

                    # Save metadata for forked thread
                    checkpoint_manager.save_metadata(
                        run_thread_id,
                        file_path,
                        rules,
                        model,
                        firmware_path
                    )

                    console.print(f"[green]✓ Loaded checkpoint state[/green]")
                    console.print(f"[cyan]📌 New thread ID:[/cyan] {run_thread_id}")
                    console.print(f"[cyan]💾 Checkpointing enabled for forked thread[/cyan]")
                    console.print(f"[dim]  └─ Fresh execution will start from checkpoint state[/dim]")
                    console.print()
                else:
                    console.print(f"[red]Error: Checkpoint {fork_checkpoint_id} not found in thread {original_thread_id}[/red]")
                    return
            except Exception as e:
                console.print(f"[red]Error loading checkpoint: {e}[/red]")
                import traceback
                traceback.print_exc()
                return

        # 11. Execute workflow with checkpointing
        console.print()
        console.print(Panel.fit(
            "[bold green]🚀 Starting Structured Security Analysis[/bold green]",
            border_style="green"
        ))
        console.print()

        # Build config with thread_id
        workflow_config = {"recursion_limit": 100}
        if run_thread_id:
            workflow_config["configurable"] = {"thread_id": run_thread_id}

        # Always use fresh execution (no replay mode)
        is_resuming = False

        final_state = await run_analysis(
            graph=graph,
            initial_state=initial_state,
            config=workflow_config,
            show_checkpoints=save_checkpoints or (thread_id is not None),
            is_resuming=is_resuming
        )

        # 12. Display final report
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

        # Display analysis details
        console.print()
        console.print("[bold cyan]📈 Analysis Statistics:[/bold cyan]")
        console.print(f"  - Client Type: {final_state.get('client_type', 'N/A')}")
        console.print(f"  - Rules Analyzed: {len(final_state.get('rules', {}))}")
        console.print(f"  - Variables Traced: {len(final_state.get('variable_traces', {}))}")
        console.print(f"  - Binaries Analyzed: {len(final_state.get('analyzed_binaries', set())) + 1}")  # +1 for main
        if final_state.get('errors'):
            console.print(f"  - Errors Encountered: {len(final_state['errors'])}")

    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]⚠ Analysis interrupted by user[/yellow]")
        # Re-raise to be caught by CLI handler
        raise
    except Exception as e:
        console.print()
        console.print(f"[bold red]✗ Analysis failed: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        raise

    finally:
        # 13. Cleanup all resources
        console.print()
        console.print("[cyan]🧹 Cleaning up resources...[/cyan]")

        if 'static_engine' in locals():
            static_engine.cleanup_all()

        # Close checkpointer connection to allow process to exit
        if 'checkpoint_manager' in locals() and checkpoint_manager:
            await checkpoint_manager.close()
            console.print("[dim]  └─ Checkpoint connection closed[/dim]")

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
