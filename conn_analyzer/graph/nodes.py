"""Graph nodes for LangGraph-based SSL analysis workflow."""

import re
from typing import Dict, Any, Optional, Sequence
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage

from langgraph.types import Send

from conn_analyzer.graph.state import AnalysisState, AnalysisStatus, AnalysisPhase
from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.ida_integration.binary_manager import BinaryRegistry

from rich.console import Console

console = Console()


# ============================================================================
# Helper Functions for Parsing Agent Responses
# ============================================================================

def parse_ssl_status(agent_response: str) -> Optional[AnalysisStatus]:
    """
    Parse the status from SSL agent response.

    Args:
        agent_response: The SSL agent's text response

    Returns:
        AnalysisStatus enum value, or None if no status found
    """
    # Look for "STATUS: <status_value>" pattern
    match = re.search(r"STATUS:\s*(\w+)", agent_response)
    if match:
        status_str = match.group(1)
        try:
            return AnalysisStatus(status_str)
        except ValueError:
            console.print(f"[yellow]⚠ Unknown SSL status: {status_str}[/yellow]")
            return None
    return None


def parse_dataflow_request(agent_response: str) -> Dict[str, Optional[str]]:
    """
    Parse dataflow request details from SSL agent response.

    Extracts:
    - Variable name
    - Context information

    Args:
        agent_response: The SSL agent's text response

    Returns:
        Dict with 'variable', 'context'
    """
    result = {"variable": None, "context": None}

    # Extract variable name
    var_match = re.search(r"Variable:\s*(.+?)(?:\n|$)", agent_response)
    if var_match:
        result["variable"] = var_match.group(1).strip()

    # Extract context
    ctx_match = re.search(r"Context:\s*(.+?)(?:\n|$)", agent_response)
    if ctx_match:
        result["context"] = ctx_match.group(1).strip()

    return result


def parse_cross_binary_request(agent_response: str) -> Dict[str, Optional[str]]:
    """
    Parse cross-binary analysis request from SSL agent response.

    Extracts:
    - Function name
    - Parameter position/name

    Args:
        agent_response: The SSL agent's text response

    Returns:
        Dict with 'function', 'parameter'
    """
    result = {"function": None, "parameter": None}

    # Extract function name
    func_match = re.search(r"Function:\s*(.+?)(?:\n|$)", agent_response)
    if func_match:
        result["function"] = func_match.group(1).strip()

    # Extract parameter
    param_match = re.search(r"Parameter:\s*(.+?)(?:\n|$)", agent_response)
    if param_match:
        result["parameter"] = param_match.group(1).strip()

    return result


def parse_config_request(agent_response: str) -> Dict[str, Optional[str]]:
    """
    Parse config analysis request from SSL agent response.

    Extracts:
    - Source type (CONFIG_FILE, ENVIRONMENT_VARIABLE, COMMAND_LINE_ARG)
    - Source details (file path, var name, arg pattern)
    - Setting name

    Args:
        agent_response: The SSL agent's text response

    Returns:
        Dict with 'source_type', 'source_details', 'setting_name'
    """
    result = {"source_type": None, "source_details": None, "setting_name": None}

    # Extract source type
    type_match = re.search(r"Source Type:\s*(.+?)(?:\n|$)", agent_response)
    if type_match:
        result["source_type"] = type_match.group(1).strip()

    # Extract source details
    details_match = re.search(r"Source Details:\s*(.+?)(?:\n|$)", agent_response)
    if details_match:
        result["source_details"] = details_match.group(1).strip()

    # Extract setting name
    setting_match = re.search(r"Setting:\s*(.+?)(?:\n|$)", agent_response)
    if setting_match:
        result["setting_name"] = setting_match.group(1).strip()

    return result


# ============================================================================
# Node: SSL Analysis
# ============================================================================

async def ssl_analysis_node(
    state: AnalysisState,
    binary_registry: BinaryRegistry
) -> Dict[str, Any]:
    """
    Execute SSL security analysis using SSL agent.

    This node:
    1. Gets the SSL agent for current binary from registry
    2. Calls the agent with current messages
    3. Parses the status from the response
    4. Extracts any request details (dataflow, cross-binary, config)
    5. Returns state update

    Args:
        state: Current analysis state
        binary_registry: Binary registry for accessing agents

    Returns:
        State update dict with ssl_analysis_result, ssl_status, and parsed request details
    """
    binary_path = state["binary_path"]

    # Get binary entry from registry
    entry = binary_registry.get_binary_entry(binary_path)
    if not entry:
        raise ValueError(f"Binary not registered: {binary_path}")

    ssl_agent = entry.agents["ssl"]

    # Build message for SSL agent
    messages = state.get("messages", [])
    if not messages or not any(isinstance(m, HumanMessage) for m in messages):
        # Add initial analysis request
        messages = [
            HumanMessage(
                content=f"Analyze SSL/TLS security for binary: {binary_path}"
            )
        ]

    # Execute SSL agent
    result = await stream_and_log_agent(
        agent=ssl_agent,
        messages=messages,
        agent_name="SSL Agent",
        agent_emoji="🔐"
    )

    # Parse status
    status = parse_ssl_status(result)

    # Build state update
    update: Dict[str, Any] = {
        "ssl_analysis_result": result,
        "ssl_status": status,
        "current_phase": AnalysisPhase.INITIAL_SSL_ANALYSIS,
        "messages": [AIMessage(content=result)],
    }

    # Parse additional request details based on status
    if status == AnalysisStatus.NEED_DATAFLOW:
        dataflow_req = parse_dataflow_request(result)
        update["requested_variable"] = dataflow_req["variable"]
        update["current_phase"] = AnalysisPhase.DATAFLOW_ANALYSIS

    elif status == AnalysisStatus.NEED_CROSS_BINARY_ANALYSIS:
        cross_binary_req = parse_cross_binary_request(result)
        update["requested_function"] = cross_binary_req["function"]
        update["requested_parameter"] = cross_binary_req["parameter"]
        update["current_phase"] = AnalysisPhase.CROSS_BINARY_ANALYSIS

    elif status == AnalysisStatus.NEED_CONFIG_ANALYSIS:
        config_req = parse_config_request(result)
        update["config_source_type"] = config_req["source_type"]
        update["config_source_details"] = config_req["source_details"]
        update["config_setting_name"] = config_req["setting_name"]
        update["current_phase"] = AnalysisPhase.CONFIG_ANALYSIS

    elif status == AnalysisStatus.NEED_FIRMWARE:
        update["current_phase"] = AnalysisPhase.FIRMWARE_EXPLORE

    elif status == AnalysisStatus.COMPLETE:
        update["current_phase"] = AnalysisPhase.SYNTHESIS
        update["final_report"] = result

    elif status == AnalysisStatus.NOT_APPLICABLE:
        update["current_phase"] = AnalysisPhase.COMPLETED
        update["final_report"] = result

    return update


# ============================================================================
# Node: Dataflow Analysis
# ============================================================================

async def dataflow_analysis_node(
    state: AnalysisState,
    binary_registry: BinaryRegistry
) -> Dict[str, Any]:
    """
    Execute dataflow analysis using Dataflow agent.

    This node:
    1. Gets the Dataflow agent for current binary
    2. Analyzes the requested variable
    3. Returns dataflow result

    Args:
        state: Current analysis state
        binary_registry: Binary registry for accessing agents

    Returns:
        State update dict with dataflow_result
    """
    binary_path = state["binary_path"]
    variable = state.get("requested_variable", "unknown")

    # Get binary entry from registry
    entry = binary_registry.get_binary_entry(binary_path)
    if not entry:
        raise ValueError(f"Binary not registered: {binary_path}")

    dataflow_agent = entry.agents["dataflow"]

    # Build dataflow request message
    messages = [
        HumanMessage(
            content=f"Trace the dataflow for variable: {variable}"
        )
    ]

    # Execute dataflow agent
    result = await stream_and_log_agent(
        agent=dataflow_agent,
        messages=messages,
        agent_name="Dataflow Agent",
        agent_emoji="🔍"
    )

    # Store result
    return {
        "dataflow_result": result,
        "messages": [AIMessage(content=result)],
    }


# ============================================================================
# Node: Firmware Exploration
# ============================================================================

async def firmware_explore_node(
    state: AnalysisState,
    firmware_agent: Any
) -> Dict[str, Any]:
    """
    Execute firmware exploration using Firmware agent.

    This node handles:
    - Finding caller binaries (for cross-binary analysis)
    - Reading config files (for config analysis)
    - General firmware exploration requests

    Args:
        state: Current analysis state
        firmware_agent: Firmware agent instance

    Returns:
        State update dict with firmware_findings and discovered_binaries
    """
    # Determine request based on current phase
    phase = state.get("current_phase")
    ssl_status = state.get("ssl_status")

    if ssl_status == AnalysisStatus.NEED_CROSS_BINARY_ANALYSIS:
        # Find caller binaries
        function = state.get("requested_function", "unknown")
        request = f"Find all binaries that call the function: {function}"

    elif ssl_status == AnalysisStatus.NEED_CONFIG_ANALYSIS:
        # Read config files
        source_type = state.get("config_source_type", "unknown")
        source_details = state.get("config_source_details", "unknown")
        setting = state.get("config_setting_name", "unknown")
        request = f"Find config for {source_type}: {source_details}, looking for setting: {setting}"

    else:
        # General firmware exploration
        request = "Explore firmware filesystem"

    # Execute firmware agent
    messages = [HumanMessage(content=request)]

    result = await stream_and_log_agent(
        agent=firmware_agent,
        messages=messages,
        agent_name="Firmware Agent",
        agent_emoji="🗂️"
    )

    # Parse discovered binaries (if cross-binary analysis)
    discovered_binaries = []
    if ssl_status == AnalysisStatus.NEED_CROSS_BINARY_ANALYSIS:
        # Extract binary paths from firmware agent response
        # Look for lines like "/usr/bin/app" or "/usr/sbin/service"
        binary_pattern = r"/[^\s]+"
        matches = re.findall(binary_pattern, result)
        # Filter to only valid-looking paths (contain at least one /)
        discovered_binaries = [m for m in matches if "/" in m and not m.startswith("//")]

    return {
        "firmware_findings": result,
        "discovered_binaries": discovered_binaries,
        "messages": [AIMessage(content=result)],
    }


# ============================================================================
# Node: Binary Analysis Dispatch (Parallel)
# ============================================================================

async def binary_analysis_dispatch_node(
    state: AnalysisState
) -> Sequence[Send]:
    """
    Dispatch parallel binary analysis tasks for discovered binaries.

    Uses LangGraph's Send API to create parallel tasks.

    Args:
        state: Current analysis state

    Returns:
        Sequence of Send objects for parallel execution
    """
    discovered_binaries = state.get("discovered_binaries", [])
    analyzed_binaries = state.get("analyzed_binaries", set())
    depth = state.get("depth", 0)

    # Filter out already-analyzed binaries (circular dependency prevention)
    binaries_to_analyze = [
        b for b in discovered_binaries
        if b not in analyzed_binaries
    ]

    console.print(f"[cyan]🔀 Dispatching parallel analysis for {len(binaries_to_analyze)} binaries[/cyan]")

    # Create parallel tasks using Send API
    return [
        Send(
            "binary_analysis",
            {
                **state,
                "binary_path": binary_path,
                "depth": depth + 1,
            }
        )
        for binary_path in binaries_to_analyze
    ]


# ============================================================================
# Node: Single Binary Analysis
# ============================================================================

async def binary_analysis_node(
    state: AnalysisState,
    binary_registry: BinaryRegistry
) -> Dict[str, Any]:
    """
    Analyze a single discovered binary.

    This node:
    1. Registers the binary (if not already registered)
    2. Runs dataflow analysis for the requested parameter
    3. Stores the result in dataflow_results dict
    4. Adds binary to analyzed_binaries set
    5. Optionally cleans up resources

    Args:
        state: Current analysis state (with binary_path set to target binary)
        binary_registry: Binary registry

    Returns:
        State update dict with updated dataflow_results and analyzed_binaries
    """
    binary_path = state["binary_path"]
    parameter = state.get("requested_parameter", "unknown")

    console.print(f"[cyan]🔬 Analyzing binary: {binary_path}[/cyan]")

    try:
        # Register binary
        await binary_registry.register_binary(binary_path)

        # Get dataflow agent
        entry = binary_registry.get_binary_entry(binary_path)
        if not entry:
            raise ValueError(f"Failed to register binary: {binary_path}")

        dataflow_agent = entry.agents["dataflow"]

        # Execute dataflow analysis
        messages = [
            HumanMessage(
                content=f"Trace argument {parameter} in this binary"
            )
        ]

        result = await stream_and_log_agent(
            agent=dataflow_agent,
            messages=messages,
            agent_name=f"Dataflow Agent ({binary_path})",
            agent_emoji="🔍"
        )

        # Update state
        dataflow_results = state.get("dataflow_results", {})
        dataflow_results[binary_path] = result

        analyzed_binaries = state.get("analyzed_binaries", set())
        analyzed_binaries.add(binary_path)

        return {
            "dataflow_results": dataflow_results,
            "analyzed_binaries": analyzed_binaries,
        }

    finally:
        # Cleanup binary resources
        binary_registry.cleanup_binary(binary_path)


# ============================================================================
# Node: Aggregate Results
# ============================================================================

async def aggregate_results_node(
    state: AnalysisState
) -> Dict[str, Any]:
    """
    Aggregate results from multiple binary analyses.

    This node:
    1. Collects all dataflow_results
    2. Formats them into a comprehensive report
    3. Returns aggregated_findings

    Args:
        state: Current analysis state

    Returns:
        State update dict with aggregated_findings
    """
    dataflow_results = state.get("dataflow_results", {})

    # Build aggregated report
    aggregated = ["Cross-Binary Analysis Results:\n"]

    for binary_path, result in dataflow_results.items():
        aggregated.append(f"\nBinary: {binary_path}")
        aggregated.append(f"Result: {result}")
        aggregated.append("-" * 80)

    aggregated_findings = "\n".join(aggregated)

    console.print(f"[cyan]📊 Aggregated {len(dataflow_results)} binary analysis results[/cyan]")

    return {
        "aggregated_findings": aggregated_findings,
        "current_phase": AnalysisPhase.AGGREGATING_RESULTS,
    }


# ============================================================================
# Node: Synthesis (Final Report)
# ============================================================================

async def synthesis_node(
    state: AnalysisState,
    binary_registry: BinaryRegistry
) -> Dict[str, Any]:
    """
    Synthesize final report.

    This node is called when SSL analysis is complete.
    It can optionally call the SSL agent one more time with
    aggregated findings to generate a comprehensive report.

    Args:
        state: Current analysis state
        binary_registry: Binary registry

    Returns:
        State update dict with final_report
    """
    # Check if we already have a final report
    if state.get("final_report"):
        return {
            "current_phase": AnalysisPhase.COMPLETED,
        }

    # If we have aggregated findings, send them to SSL agent for synthesis
    aggregated_findings = state.get("aggregated_findings")

    if aggregated_findings:
        main_binary_path = state["main_binary_path"]
        entry = binary_registry.get_binary_entry(main_binary_path)
        if not entry:
            raise ValueError(f"Main binary not registered: {main_binary_path}")

        ssl_agent = entry.agents["ssl"]

        # Build synthesis request
        messages = [
            HumanMessage(
                content=f"Synthesize final security report.\n\n{aggregated_findings}"
            )
        ]

        result = await stream_and_log_agent(
            agent=ssl_agent,
            messages=messages,
            agent_name="SSL Agent (Synthesis)",
            agent_emoji="🔐"
        )

        return {
            "final_report": result,
            "current_phase": AnalysisPhase.COMPLETED,
        }

    # Otherwise, use existing SSL analysis result as final report
    return {
        "final_report": state.get("ssl_analysis_result", "Analysis complete"),
        "current_phase": AnalysisPhase.COMPLETED,
    }
