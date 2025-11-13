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
    - If cross-binary tasks created → go to firmware explore
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "firmware_explore" or "synthesis"
    """
    # If cross-binary analysis needed, go to firmware explore to find binaries
    if state.get("pending_cross_binary_tasks"):
        return "firmware_explore"

    # Otherwise, proceed to synthesis
    return "synthesis"


def route_after_firmware(
    state: AnalysisState
) -> Literal["binary_analysis_dispatch", "synthesis"]:
    """Route after firmware exploration completes.

    Firmware exploration determines:
    - If found binaries for cross-binary analysis → dispatch parallel analysis
    - Otherwise → go to synthesis

    Args:
        state: Current analysis state

    Returns:
        Next node: "binary_analysis_dispatch" or "synthesis"
    """
    cross_binary_tasks = state.get("pending_cross_binary_tasks", [])

    if not cross_binary_tasks:
        return "synthesis"

    # Check if first task has binaries to analyze
    task = cross_binary_tasks[0]
    caller_binaries = task.get("caller_binaries", [])

    if caller_binaries:
        return "binary_analysis_dispatch"
    else:
        return "synthesis"


def route_after_aggregation(
    state: AnalysisState
) -> Literal["synthesis"]:
    """Route after aggregating cross-binary results.

    Always proceeds to synthesis after cross-binary analysis completes.

    Args:
        state: Current analysis state

    Returns:
        "synthesis"
    """
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
