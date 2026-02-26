"""
Main orchestrator for tlscan analyzer.

Coordinates IDA integration, agent creation, and analysis execution using
LangGraph-based workflow with new architecture:
- StaticAnalysisEngine: Manages MCP servers
- AgentFactory: Creates agents with structured output
- Clean separation of concerns
"""

import asyncio
import time
import logging

from rich.console import Console
from rich.panel import Panel

from tlscan.config import (
    LOG_LEVEL_HTTPX,
    LOG_LEVEL_HTTPCORE,
    LOG_LEVEL_MCP,
    ANALYSIS_TOTAL_TIMEOUT,
)
from tlscan.analyzer.utils.files import (
    resolve_binary_path,
    load_security_rules,
)
from tlscan.analyzer.utils.binary import detect_file_type, FileType
from tlscan.analyzer.utils.formatting import format_duration
from tlscan.analyzer.static_engine.ida.ports import PortManager
from tlscan.analyzer.static_engine.engine import StaticAnalysisEngine
from tlscan.analyzer.agents.factory import AgentFactory
from tlscan.analyzer.workflow.state import create_initial_state
from tlscan.analyzer.workflow.graph import create_analysis_graph, run_analysis
from tlscan.analyzer.workflow.formatter import format_and_display_report
from tlscan.analyzer.workflow.models import LibraryVersions
from tlscan.analyzer.utils.logging import display_final_state
from tlscan.analyzer.cache import FirmwareCache

from tlscan.analyzer.static_engine import firmware

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
    from tlscan.config.loader import get_config, ConfigurationError

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
        elif provider == "qwen":
            from langchain_qwq import ChatQwen
            kwargs = {"model": model_name, "api_key": api_key}
            if api_base:
                kwargs["base_url"] = api_base
            return ChatQwen(**kwargs), model_name, config
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
    no_rules: bool = False,
    save_checkpoints: bool = False,
    thread_id: str = None,
    fork_checkpoint_id: str = None,
    total_timeout: int = None
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
        no_rules: Run ablation study without security rules (default: False)
        save_checkpoints: Enable automatic state checkpointing (default: False)
        thread_id: Resume from this thread ID (optional)
        fork_checkpoint_id: Fork from specific checkpoint with fresh execution (requires thread_id)
        total_timeout: Total timeout in seconds (default: 1200 = 20 minutes, 0 to disable)
    """
    total_start_time = time.perf_counter()

    # Resolve timeout (None means use default, 0 means disabled)
    if total_timeout is None:
        total_timeout = ANALYSIS_TOTAL_TIMEOUT

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
    recovered_state = None  # Loaded checkpoint state for resume/fork

    if thread_id:
        # Resume mode - load metadata
        from tlscan.analyzer.persistence import CheckpointManager
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

        # Initialize checkpointer early to load and display recovered state
        await checkpoint_manager.initialize()
        checkpointer = checkpoint_manager.get_checkpointer()

        # Load checkpoint state for display
        checkpoint_config = {"configurable": {"thread_id": thread_id}}
        if fork_checkpoint_id:
            checkpoint_config["configurable"]["checkpoint_id"] = fork_checkpoint_id

        checkpoint_tuple = await checkpointer.aget_tuple(checkpoint_config)
        if checkpoint_tuple and checkpoint_tuple.checkpoint:
            recovered_state = checkpoint_tuple.checkpoint.get('channel_values', {})
            from tlscan.analyzer.utils.logging import display_recovered_state
            display_recovered_state(recovered_state, metadata, console)
        else:
            console.print(f"[yellow]⚠ No checkpoint state found for thread {thread_id}[/yellow]")
            console.print()
            recovered_state = None

    # 2. Load config and resolve paths
    file_path = resolve_binary_path(file_path, firmware_path)

    # 2.5 Detect file type
    file_type = detect_file_type(file_path)

    if file_type == FileType.ELF_BINARY:
        console.print(f"[cyan]📁 Analyzing binary:[/cyan] {file_path}")
    else:
        console.print(f"[cyan]📄 Analyzing script ({file_type.value}):[/cyan] {file_path}")

    console.print(f"[cyan]📚 Library rules:[/cyan] {rules}")
    if firmware_path:
        console.print(f"[cyan]🗂️  Firmware root:[/cyan] {firmware_path}")
    console.print()

    # Load security rules (or skip for ablation study)
    if no_rules:
        security_rules_content = ""
        console.print("[yellow]⚠️  Ablation mode: Running without security rules[/yellow]")
    else:
        security_rules_content = load_security_rules(rules)
    console.print()

    # Parse model and load config
    llm, model_name, config = parse_model_string(model)
    console.print(f"[cyan]🤖 LLM Model:[/cyan] {model_name}")
    console.print(f"[cyan]🌡️  Temperature:[/cyan] {config.get_default_temperature()} (default)")
    console.print()

    # 3. Initialize checkpointing (if requested and not already done during resume)
    if save_checkpoints and not checkpointer:
        # New run with checkpointing - initialize checkpoint manager
        from tlscan.analyzer.persistence import CheckpointManager

        if not checkpoint_manager:
            checkpoint_manager = CheckpointManager()

        # Initialize the async checkpointer
        await checkpoint_manager.initialize()

        checkpointer = checkpoint_manager.get_checkpointer()

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
        # 7. Pre-start MCP session for main binary (only for ELF binaries)
        if file_type == FileType.ELF_BINARY:
            console.print(f"[cyan]🚀 Starting MCP session for:[/cyan] {file_path}")
            await static_engine.get_tools(file_path)
            console.print()
        else:
            console.print(f"[cyan]📝 Script analysis mode - skipping IDA MCP server[/cyan]")
            # Initialize script tools
            static_engine.get_script_tools(file_path)
            console.print()

        # 7.5 Apply function signature repair (ELF binaries only)
        if file_type == FileType.ELF_BINARY:
            from tlscan.analyzer.static_engine.signatures import (
                apply_function_signatures,
                display_repair_result,
            )
            console.print(
                f"[cyan]🔧 Applying function signatures:[/cyan] {rules}"
            )
            ida_tools = await static_engine.get_tools(file_path)
            repair_result = await apply_function_signatures(
                tools=ida_tools,
                library_name=rules,
            )
            display_repair_result(console, repair_result)
            console.print()

        # 8. Prepare firmware tools (if firmware provided)
        firmware_tools_list = None
        if firmware_path:
            console.print("[cyan]🗂️  Initializing firmware tools...[/cyan]")
            firmware.set_firmware_root(firmware_path)

            # Get firmware analysis tools
            firmware_tools_list = [
                firmware.search_files_by_name,
                firmware.search_files_by_content,
                firmware.read_file,
                firmware.find_function_definition,
                firmware.find_function_references
            ]
            console.print(f"[green]✓ Firmware tools ready ({len(firmware_tools_list)} tools)[/green]")
            console.print()

        # 8.5 Load library versions from firmware cache (if firmware provided)
        library_versions = None
        if firmware_path:
            cache = FirmwareCache(firmware_path)
            if cache.exists():
                console.print("[cyan]📦 Loading cached library versions...[/cyan]")
                cached_data = cache.load_versions()
                if cached_data:
                    library_versions = LibraryVersions.from_cache(cached_data, file_path)

                    # Display detected versions
                    if library_versions.firmware_libraries:
                        console.print("[dim]  Firmware libraries:[/dim]")
                        for lib_id, ver in sorted(library_versions.firmware_libraries.items()):
                            if ver.version:
                                source = f" from {ver.source_path}" if ver.source_path else ""
                                line = f"    └─ {lib_id}: {ver.version} ({ver.confidence.value}){source}"
                                console.print(f"[dim]{line}[/dim]")

                    if library_versions.libraries:
                        console.print("[dim]  Binary requirements:[/dim]")
                        for lib_id, ver in sorted(library_versions.libraries.items()):
                            if ver.version:
                                line = f"    └─ {lib_id}: {ver.version} ({ver.confidence.value})"
                                console.print(f"[dim]{line}[/dim]")

                    console.print("[green]✓ Library versions loaded[/green]")
                else:
                    console.print("[yellow]⚠ Cache exists but could not be loaded[/yellow]")
            else:
                console.print("[yellow]⚠ No version cache found. Run 'tlscan-detect --save-cache' first.[/yellow]")
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
            security_rules=security_rules_content,
            file_type=file_type,
            library_versions=library_versions,
            library_name=rules,
            firmware_path=firmware_path,
            no_rules=no_rules,
        )

        # If fork_checkpoint_id is provided, use already-loaded state for forking
        if fork_checkpoint_id and recovered_state:
            # Use already-loaded checkpoint state as initial state
            initial_state = recovered_state

            # Create NEW thread ID for fresh execution
            run_thread_id = checkpoint_manager.create_thread_id(file_path)

            # Save metadata for forked thread
            checkpoint_manager.save_metadata(
                run_thread_id,
                file_path,
                rules,
                model,
                firmware_path
            )

            console.print(f"[cyan]📌 New thread ID:[/cyan] {run_thread_id}")
            console.print(f"[cyan]💾 Checkpointing enabled for forked thread[/cyan]")
            console.print(f"[dim]  └─ Fresh execution will start from checkpoint state[/dim]")
            console.print()
        elif fork_checkpoint_id and not recovered_state:
            console.print(f"[red]Error: Could not load checkpoint state for forking[/red]")
            return

        # 11. Execute workflow with checkpointing
        console.print()
        console.print(Panel.fit(
            "[bold green]🚀 Starting Structured Security Analysis[/bold green]",
            border_style="green"
        ))
        if total_timeout > 0:
            console.print(f"[dim]  ⏱  Timeout: {total_timeout / 60:.0f} minutes[/dim]")
        else:
            console.print("[dim]  ⏱  Timeout: disabled[/dim]")
        console.print()

        # Build config with thread_id
        workflow_config = {"recursion_limit": 100}
        if run_thread_id:
            workflow_config["configurable"] = {"thread_id": run_thread_id}

        # Always use fresh execution (no replay mode)
        is_resuming = False

        # Execute workflow with optional timeout
        analysis_coro = run_analysis(
            graph=graph,
            initial_state=initial_state,
            config=workflow_config,
            show_checkpoints=save_checkpoints or (thread_id is not None),
            is_resuming=is_resuming
        )

        if total_timeout > 0:
            try:
                final_state = await asyncio.wait_for(analysis_coro, timeout=total_timeout)
            except asyncio.TimeoutError:
                console.print()
                console.print(Panel.fit(
                    f"[bold red]✗ Analysis timed out after {total_timeout / 60:.1f} minutes[/bold red]",
                    border_style="red"
                ))
                console.print("[yellow]Tip: Use --total-timeout to increase the limit, or 0 to disable[/yellow]")
                raise
        else:
            # Timeout disabled
            final_state = await analysis_coro

        # 12. Display final report
        console.print()
        console.print(Panel.fit(
            "[bold green]✓ Analysis Complete[/bold green]",
            border_style="green"
        ))
        console.print()

        # Debug: Display full state before report
        display_final_state(final_state, output_console=console)

        # Display report using Rich widgets
        report_data = final_state.get("report_data")
        if report_data:
            format_and_display_report(console, report_data)
        else:
            console.print("[yellow]⚠ No report data generated[/yellow]")

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
