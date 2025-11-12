"""Routing logic for LangGraph-based SSL analysis workflow."""

from typing import Literal

from conn_analyzer.graph.state import AnalysisState, AnalysisStatus, AnalysisPhase


# Maximum recursion depth for cross-binary analysis
MAX_DEPTH = 50


def route_from_ssl_analysis(
    state: AnalysisState
) -> Literal["dataflow_analysis", "firmware_explore", "synthesis", "end"]:
    """
    Route from SSL analysis based on status.

    Determines the next node based on the SSL agent's status response.

    Args:
        state: Current analysis state

    Returns:
        Next node name: "dataflow_analysis", "firmware_explore", "synthesis", or "end"
    """
    ssl_status = state.get("ssl_status")
    depth = state.get("depth", 0)

    # Check depth limit
    if depth >= MAX_DEPTH:
        print(f"⚠️  Max depth reached ({MAX_DEPTH}), ending analysis")
        return "end"

    # Route based on status
    if ssl_status == AnalysisStatus.COMPLETE:
        return "synthesis"

    elif ssl_status == AnalysisStatus.NOT_APPLICABLE:
        return "end"

    elif ssl_status == AnalysisStatus.NEED_DATAFLOW:
        return "dataflow_analysis"

    elif ssl_status == AnalysisStatus.NEED_CROSS_BINARY_ANALYSIS:
        return "firmware_explore"

    elif ssl_status == AnalysisStatus.NEED_CONFIG_ANALYSIS:
        return "firmware_explore"

    elif ssl_status == AnalysisStatus.NEED_FIRMWARE:
        return "firmware_explore"

    else:
        # Unknown status or no status - default to synthesis
        print(f"⚠️  Unknown SSL status: {ssl_status}, routing to synthesis")
        return "synthesis"


def route_after_dataflow(
    state: AnalysisState
) -> Literal["ssl_analysis"]:
    """
    Route after dataflow analysis.

    Always returns to SSL analysis to process dataflow results.

    Args:
        state: Current analysis state

    Returns:
        "ssl_analysis" - always return to SSL agent
    """
    return "ssl_analysis"


def route_after_firmware(
    state: AnalysisState
) -> Literal["binary_analysis_dispatch", "ssl_analysis"]:
    """
    Route after firmware exploration.

    Determines whether to:
    - Dispatch parallel binary analysis (if binaries discovered for cross-binary analysis)
    - Return to SSL analysis (if config analysis or no binaries found)

    Args:
        state: Current analysis state

    Returns:
        "binary_analysis_dispatch" or "ssl_analysis"
    """
    ssl_status = state.get("ssl_status")
    discovered_binaries = state.get("discovered_binaries", [])
    analyzed_binaries = state.get("analyzed_binaries", set())

    # If cross-binary analysis and we found new binaries, dispatch parallel analysis
    if ssl_status == AnalysisStatus.NEED_CROSS_BINARY_ANALYSIS:
        # Filter out already-analyzed binaries
        new_binaries = [b for b in discovered_binaries if b not in analyzed_binaries]

        if new_binaries:
            return "binary_analysis_dispatch"

    # Otherwise, return to SSL analysis (e.g., for config analysis results)
    return "ssl_analysis"


def route_after_binary_analysis(
    state: AnalysisState
) -> Literal["aggregate_results"]:
    """
    Route after binary analysis (parallel execution complete).

    Always aggregates results from multiple binary analyses.

    Args:
        state: Current analysis state

    Returns:
        "aggregate_results"
    """
    return "aggregate_results"


def route_after_aggregation(
    state: AnalysisState
) -> Literal["ssl_analysis"]:
    """
    Route after aggregating cross-binary results.

    Returns to SSL analysis with aggregated findings.

    Args:
        state: Current analysis state

    Returns:
        "ssl_analysis"
    """
    return "ssl_analysis"


def should_end(
    state: AnalysisState
) -> Literal["__end__"]:
    """
    Determine if workflow should end.

    Called from synthesis node.

    Args:
        state: Current analysis state

    Returns:
        "__end__" to terminate workflow
    """
    return "__end__"
