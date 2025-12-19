"""Routing logic for LangGraph-based SSL analysis workflow v2.

This module implements all routing functions based on state analysis.
Routing decisions are made by inspecting state fields (current_phase,
pending tasks, etc.) rather than parsing agent responses.
"""

from typing import Literal

from tlscan.analyzer.workflow.state import AnalysisState, AnalysisPhase
from tlscan.analyzer.workflow.models import TaskType


# Maximum recursion depth for cross-binary analysis
MAX_DEPTH = 50


def route_after_ssl_analysis(
    state: AnalysisState
) -> Literal["dataflow_analysis", "synthesis", "__end__"]:
    """Route after SSL analysis completes.

    The SSL agent runs ONCE and determines:
    - If applicable=false → end workflow
    - If has pending_dataflow_tasks → go to dataflow
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "dataflow_analysis", "synthesis", or "__end__"
    """
    # If not applicable, end immediately
    if not state.get("applicable", True):
        return "__end__"

    # If dataflow tasks pending, route to dataflow
    if state.get("pending_dataflow_tasks"):
        return "dataflow_analysis"

    # Otherwise, proceed to synthesis
    return "synthesis"


def route_after_dataflow(
    state: AnalysisState
) -> Literal["firmware_explore", "synthesis"]:
    """Route after dataflow analysis completes.

    Dataflow analysis determines:
    - If caller discovery tasks created → go to firmware explore
    - If config fetch tasks created → go to firmware explore
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "firmware_explore" or "synthesis"
    """
    # Check if any pending dataflow tasks need caller discovery
    pending_tasks = state.get("pending_dataflow_tasks", [])
    needs_firmware = any(
        task.type == TaskType.NEEDS_CALLER_DISCOVERY for task in pending_tasks
    )

    if needs_firmware:
        return "firmware_explore"

    # If config fetching needed, go to firmware explore to fetch values
    if state.get("pending_config_fetch_tasks"):
        return "firmware_explore"

    # Otherwise, proceed to synthesis
    return "synthesis"


def route_after_firmware(
    state: AnalysisState
) -> Literal["binary_analysis_sequential", "firmware_explore", "synthesis"]:
    """Route after firmware exploration completes.

    Firmware exploration determines:
    - If cross-binary tasks exist (tasks with binary_path set) → sequential analysis
    - If discovery tasks remain (needs_caller_discovery, needs_script_discovery) → loop back
    - If config fetch tasks remain → loop back
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "binary_analysis_sequential", "firmware_explore", or "synthesis"
    """
    from rich.console import Console
    console = Console()

    pending_tasks = state.get("pending_dataflow_tasks", [])
    config_tasks = state.get("pending_config_fetch_tasks", [])

    # DEBUG: Log routing decision
    console.print()
    console.print(f"[cyan]🔀 Routing After Firmware Exploration:[/cyan]")
    console.print(f"   - pending_dataflow_tasks: {len(pending_tasks)}")
    console.print(f"   - pending_config_fetch_tasks: {len(config_tasks)}")

    # Priority 1: Check for cross-binary tasks (analyze discovered binaries)
    has_cross_binary = any(
        task.binary_path is not None for task in pending_tasks
    )

    if has_cross_binary:
        cross_binary_count = sum(1 for t in pending_tasks if t.binary_path is not None)
        console.print(f"[green]   → Routing to binary_analysis_sequential ({cross_binary_count} cross-binary tasks)[/green]")
        console.print()
        return "binary_analysis_sequential"

    # Priority 2: Check for remaining discovery tasks
    has_caller_discovery = any(
        task.type == TaskType.NEEDS_CALLER_DISCOVERY for task in pending_tasks
    )

    has_script_discovery = any(
        task.type == TaskType.NEEDS_SCRIPT_DISCOVERY for task in pending_tasks
    )

    if has_caller_discovery or has_script_discovery:
        discovery_count = sum(
            1 for t in pending_tasks
            if t.type in [TaskType.NEEDS_CALLER_DISCOVERY, TaskType.NEEDS_SCRIPT_DISCOVERY]
        )
        console.print(f"[green]   → Routing to firmware_explore ({discovery_count} discovery tasks remaining)[/green]")
        console.print()
        return "firmware_explore"

    # Priority 3: Check for config fetch tasks
    if config_tasks:
        console.print(f"[green]   → Routing to firmware_explore ({len(config_tasks)} config fetch tasks)[/green]")
        console.print()
        return "firmware_explore"

    # No pending tasks - proceed to synthesis
    console.print(f"[yellow]   → Routing to synthesis (no pending tasks)[/yellow]")
    console.print()
    return "synthesis"


def route_after_cross_binary(
    state: AnalysisState
) -> Literal["firmware_explore", "synthesis"]:
    """Route after cross-binary analysis completes.

    Checks if cross-binary traces created new tasks:
    - Config fetch tasks → firmware_explore
    - Caller discovery tasks → firmware_explore
    - Script discovery tasks → firmware_explore
    - Otherwise → synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "firmware_explore" or "synthesis"
    """
    from rich.console import Console
    console = Console()

    pending_tasks = state.get("pending_dataflow_tasks", [])
    config_tasks = state.get("pending_config_fetch_tasks", [])

    console.print()
    console.print(f"[cyan]🔀 Routing After Cross-Binary Analysis:[/cyan]")
    console.print(f"   - pending_dataflow_tasks: {len(pending_tasks)}")
    console.print(f"   - pending_config_fetch_tasks: {len(config_tasks)}")

    # Check for caller discovery or script discovery tasks
    needs_firmware = any(
        task.type in [TaskType.NEEDS_CALLER_DISCOVERY, TaskType.NEEDS_SCRIPT_DISCOVERY]
        for task in pending_tasks
    )

    if needs_firmware or config_tasks:
        console.print(f"[green]   → Routing to firmware_explore (new tasks found)[/green]")
        console.print()
        return "firmware_explore"

    # Otherwise, go to synthesis
    console.print(f"[yellow]   → Routing to synthesis (no new tasks)[/yellow]")
    console.print()
    return "synthesis"


def route_from_synthesis(
    state: AnalysisState
) -> Literal["__end__"]:
    """Route from synthesis node.

    Synthesis is the final node - always ends workflow.

    Args:
        state: Current analysis state

    Returns:
        "__end__" to terminate workflow
    """
    return "__end__"
