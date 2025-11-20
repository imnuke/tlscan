"""Routing logic for LangGraph-based SSL analysis workflow v2.

This module implements all routing functions based on state analysis.
Routing decisions are made by inspecting state fields (current_phase,
pending tasks, etc.) rather than parsing agent responses.
"""

from typing import Literal

from conn_analyzer.graph.state import AnalysisState, AnalysisPhase


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
        task.get("type") == "needs_caller_discovery" for task in pending_tasks
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
) -> Literal["binary_analysis_sequential", "synthesis"]:
    """Route after firmware exploration completes.

    Firmware exploration determines:
    - If found binaries for cross-binary analysis (tasks with binary_path set) → sequential analysis
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "binary_analysis_sequential" or "synthesis"
    """
    pending_tasks = state.get("pending_dataflow_tasks", [])

    # Check if any tasks have binary_path set (indicates caller binaries were found)
    has_cross_binary = any(
        task.get("binary_path") is not None for task in pending_tasks
    )

    if has_cross_binary:
        return "binary_analysis_sequential"
    else:
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
