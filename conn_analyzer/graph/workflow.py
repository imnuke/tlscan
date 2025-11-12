"""LangGraph workflow construction for SSL analysis."""

from functools import partial
from typing import Any

from langgraph.graph import StateGraph, END

from conn_analyzer.graph.state import AnalysisState
from conn_analyzer.graph import nodes
from conn_analyzer.graph import routing
from conn_analyzer.ida_integration.binary_manager import BinaryRegistry


def create_analysis_graph(
    binary_registry: BinaryRegistry,
    firmware_agent: Any = None
) -> StateGraph:
    """
    Create the SSL analysis workflow graph.

    This graph coordinates:
    1. SSL analysis (initial and iterative)
    2. Dataflow analysis (when variables need tracing)
    3. Firmware exploration (for cross-binary and config analysis)
    4. Parallel binary analysis (for discovered binaries)
    5. Result aggregation
    6. Final synthesis

    Args:
        binary_registry: Binary registry for managing binaries and agents
        firmware_agent: Firmware agent instance (optional)

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create state graph
    graph = StateGraph(AnalysisState)

    # ========================================================================
    # Add nodes with partial application for dependencies
    # ========================================================================

    # SSL analysis node (needs binary_registry)
    graph.add_node(
        "ssl_analysis",
        partial(nodes.ssl_analysis_node, binary_registry=binary_registry)
    )

    # Dataflow analysis node (needs binary_registry)
    graph.add_node(
        "dataflow_analysis",
        partial(nodes.dataflow_analysis_node, binary_registry=binary_registry)
    )

    # Firmware exploration node (needs firmware_agent)
    if firmware_agent:
        graph.add_node(
            "firmware_explore",
            partial(nodes.firmware_explore_node, firmware_agent=firmware_agent)
        )

    # Binary analysis dispatch (parallel)
    graph.add_node(
        "binary_analysis_dispatch",
        nodes.binary_analysis_dispatch_node
    )

    # Single binary analysis (needs binary_registry)
    graph.add_node(
        "binary_analysis",
        partial(nodes.binary_analysis_node, binary_registry=binary_registry)
    )

    # Aggregate results
    graph.add_node(
        "aggregate_results",
        nodes.aggregate_results_node
    )

    # Synthesis (final report) - needs binary_registry
    graph.add_node(
        "synthesis",
        partial(nodes.synthesis_node, binary_registry=binary_registry)
    )

    # ========================================================================
    # Define workflow edges
    # ========================================================================

    # Set entry point
    graph.set_entry_point("ssl_analysis")

    # Conditional routing from SSL analysis
    if firmware_agent:
        # With firmware agent - full routing
        graph.add_conditional_edges(
            "ssl_analysis",
            routing.route_from_ssl_analysis,
            {
                "dataflow_analysis": "dataflow_analysis",
                "firmware_explore": "firmware_explore",
                "synthesis": "synthesis",
                "end": END,
            }
        )

        # After firmware exploration
        graph.add_conditional_edges(
            "firmware_explore",
            routing.route_after_firmware,
            {
                "binary_analysis_dispatch": "binary_analysis_dispatch",
                "ssl_analysis": "ssl_analysis",
            }
        )

        # After binary analysis dispatch → aggregate
        graph.add_edge("binary_analysis_dispatch", "aggregate_results")

        # After aggregation → back to SSL
        graph.add_edge("aggregate_results", "ssl_analysis")

    else:
        # Without firmware agent - limited routing (dataflow only)
        graph.add_conditional_edges(
            "ssl_analysis",
            routing.route_from_ssl_analysis,
            {
                "dataflow_analysis": "dataflow_analysis",
                "firmware_explore": "synthesis",  # Fallback if firmware requested
                "synthesis": "synthesis",
                "end": END,
            }
        )

    # After dataflow → back to SSL
    graph.add_edge("dataflow_analysis", "ssl_analysis")

    # After synthesis → end
    graph.add_edge("synthesis", END)

    # ========================================================================
    # Compile graph
    # ========================================================================

    compiled_graph = graph.compile()

    return compiled_graph


async def run_analysis(
    graph: StateGraph,
    initial_state: AnalysisState,
    config: dict = None
) -> AnalysisState:
    """
    Run the SSL analysis workflow.

    Args:
        graph: Compiled state graph
        initial_state: Initial analysis state
        config: Optional configuration (e.g., recursion_limit)

    Returns:
        Final state after workflow completion
    """
    config = config or {"recursion_limit": 100}

    # Execute graph
    final_state = await graph.ainvoke(initial_state, config=config)

    return final_state
