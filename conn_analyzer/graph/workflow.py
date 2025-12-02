"""LangGraph workflow construction for SSL analysis v2.

This module builds the analysis workflow graph using:
- StaticAnalysisEngine for MCP server management
- AgentFactory for agent creation with structured output
- Dependency injection via functools.partial
"""

from functools import partial
from typing import Any, List, Optional

from langgraph.graph import StateGraph, END

from conn_analyzer.graph.state import AnalysisState
from conn_analyzer.graph import nodes
from conn_analyzer.graph import routing
from conn_analyzer.static_analysis.engine import StaticAnalysisEngine
from conn_analyzer.agents.factory import AgentFactory


def create_analysis_graph(
    static_engine: StaticAnalysisEngine,
    agent_factory: AgentFactory,
    firmware_tools: Optional[List[Any]] = None,
    firmware_path: Optional[str] = None,
    checkpointer = None
) -> StateGraph:
    """
    Create the SSL analysis workflow graph v2.

    New architecture features:
    - Uses StaticAnalysisEngine for MCP management
    - Uses AgentFactory for structured output agents
    - Dependency injection with functools.partial
    - Simplified routing based on state
    - Optional checkpointing for state persistence

    This graph coordinates:
    1. SSL analysis (runs ONCE, returns structured output)
    2. Dataflow analysis (processes all pending tasks)
    3. Firmware exploration (finds binaries, fetches configs)
    4. Parallel binary analysis (analyzes discovered binaries)
    5. Result aggregation (combines parallel results)
    6. Final synthesis (generates report)

    Args:
        static_engine: Static Analysis Engine for MCP servers
        agent_factory: Agent Factory for creating agents
        firmware_tools: Firmware file system tools (optional)
        firmware_path: Path to firmware root (optional)
        checkpointer: Optional checkpointer for state persistence

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create state graph
    graph = StateGraph(AnalysisState)

    # ========================================================================
    # Add nodes with dependency injection
    # ========================================================================

    # Node 1: SSL Analysis (runs ONCE with structured output)
    graph.add_node(
        "ssl_analysis",
        partial(
            nodes.ssl_analysis_node,
            static_engine=static_engine,
            agent_factory=agent_factory
        )
    )

    # Node 2: Dataflow Analysis (processes all pending dataflow tasks)
    graph.add_node(
        "dataflow_analysis",
        partial(
            nodes.dataflow_analysis_node,
            static_engine=static_engine,
            agent_factory=agent_factory,
            firmware_tools=firmware_tools or []
        )
    )

    # Node 3: Firmware Exploration (if firmware tools available)
    if firmware_tools and firmware_path:
        graph.add_node(
            "firmware_explore",
            partial(
                nodes.firmware_explore_node,
                agent_factory=agent_factory,
                firmware_tools=firmware_tools,
                firmware_path=firmware_path
            )
        )

        # Node 4: Binary Analysis Sequential (for cross-binary analysis)
        graph.add_node(
            "binary_analysis_sequential",
            partial(
                nodes.binary_analysis_sequential,
                static_engine=static_engine,
                agent_factory=agent_factory
            )
        )

    # Node 5: Synthesis (final report generation)
    graph.add_node(
        "synthesis",
        nodes.synthesis_node
    )

    # ========================================================================
    # Define workflow edges
    # ========================================================================

    # Set entry point
    graph.set_entry_point("ssl_analysis")

    # Conditional routing from SSL analysis
    graph.add_conditional_edges(
        "ssl_analysis",
        routing.route_after_ssl_analysis,
        {
            "dataflow_analysis": "dataflow_analysis",
            "synthesis": "synthesis",
            "__end__": END,
        }
    )

    # Conditional routing after dataflow
    graph.add_conditional_edges(
        "dataflow_analysis",
        routing.route_after_dataflow,
        {
            "firmware_explore": "firmware_explore",
            "synthesis": "synthesis",
        }
    )

    # Conditional routing after firmware (if firmware tools available)
    if firmware_tools and firmware_path:
        # Route to sequential binary analysis
        graph.add_conditional_edges(
            "firmware_explore",
            routing.route_after_firmware,
            {
                "binary_analysis_sequential": "binary_analysis_sequential",
                "firmware_explore": "firmware_explore",  # Loop back for remaining tasks
                "synthesis": "synthesis",
            }
        )

        # After sequential binary analysis → conditional routing (check for new tasks)
        graph.add_conditional_edges(
            "binary_analysis_sequential",
            routing.route_after_cross_binary,
            {
                "firmware_explore": "firmware_explore",
                "synthesis": "synthesis",
            }
        )

    # After synthesis → end
    graph.add_conditional_edges(
        "synthesis",
        routing.route_from_synthesis,
        {
            "__end__": END,
        }
    )

    # ========================================================================
    # Compile graph
    # ========================================================================

    compiled_graph = graph.compile(checkpointer=checkpointer)

    return compiled_graph


async def run_analysis(
    graph: StateGraph,
    initial_state: AnalysisState,
    config: dict = None,
    show_checkpoints: bool = False
) -> AnalysisState:
    """
    Run the SSL analysis workflow.

    Args:
        graph: Compiled state graph
        initial_state: Initial analysis state
        config: Optional configuration (e.g., recursion_limit)
        show_checkpoints: Whether to display checkpoint IDs in real-time

    Returns:
        Final state after workflow completion
    """
    from rich.console import Console
    console = Console()

    config = config or {"recursion_limit": 100}

    if show_checkpoints:
        # Stream events to show checkpoints in real-time
        final_state = None
        async for event in graph.astream(initial_state, config=config, stream_mode="updates"):
            # event = {node_name: node_output}
            for node_name, node_output in event.items():
                # Display which node just completed
                console.print(f"[dim]✓ {node_name} complete[/dim]")

            # After node completes, checkpoint is auto-saved
            # Get the latest checkpoint
            checkpointer = graph.checkpointer
            if checkpointer:
                thread_id = config.get("configurable", {}).get("thread_id")
                if thread_id:
                    try:
                        checkpoint_tuple = await checkpointer.aget_tuple({"configurable": {"thread_id": thread_id}})
                        if checkpoint_tuple:
                            checkpoint_id = checkpoint_tuple.checkpoint['id']
                            # Display full checkpoint ID
                            console.print(f"[cyan]💾 Checkpoint saved:[/cyan] {checkpoint_id} (after {list(event.keys())[0]})")
                    except Exception:
                        # Checkpoint retrieval may fail, ignore
                        pass

            final_state = node_output

        return final_state
    else:
        # Normal execution without streaming
        final_state = await graph.ainvoke(initial_state, config=config)
        return final_state
