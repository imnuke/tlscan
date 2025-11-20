"""Graph nodes for LangGraph-based SSL analysis workflow v2.

This module implements all graph nodes with:
- Structured output (Pydantic models instead of text parsing)
- State as single source of truth (no context passing through agents)
- Integration with Static Analysis Engine and Agent Factory
- Clean separation of concerns
"""

from typing import Dict, Any, List, Sequence
from langchain_core.messages import HumanMessage

from langgraph.types import Send

from conn_analyzer.graph.state import (
    AnalysisState,
    AnalysisPhase,
    DataflowTask,
)
from conn_analyzer.graph.models import (
    RuleResultStatus,
    SSLAnalysisOutput,
    DataflowAnalysisOutput,
    FirmwareSearchResult,
    VariableTrace,
    RuleResult,
    ConfigFetchTask,
    VariableSourceType,
)
from conn_analyzer.static_analysis.engine import StaticAnalysisEngine
from conn_analyzer.agents.factory import AgentFactory
from conn_analyzer.agents.core.execution import stream_and_log_agent

from rich.console import Console

console = Console()


# ============================================================================
# Node: SSL Analysis (Runs Once)
# ============================================================================

async def ssl_analysis_node(
    state: AnalysisState,
    static_engine: StaticAnalysisEngine,
    agent_factory: AgentFactory,
) -> Dict[str, Any]:
    """Execute SSL security analysis - runs ONCE.

    This node:
    1. Gets IDA tools from Static Analysis Engine
    2. Creates SSL agent with structured output
    3. Calls agent to analyze SSL/TLS security
    4. Processes structured output (SSLAnalysisOutput)
    5. Updates state with rules, client_type, applicable status
    6. Creates dataflow tasks for conditional rules

    The SSL agent runs ONCE and returns complete analysis with:
    - Rules marked as PASS/FAIL/CONDITIONAL/UNDETERMINED
    - For CONDITIONAL: conditions list with variables to trace
    - Summary text for final report

    Args:
        state: Current analysis state
        static_engine: Static Analysis Engine for IDA tools
        agent_factory: Agent factory for creating SSL agent

    Returns:
        State update dict with rules, ssl_summary, client_type, etc.
    """
    binary_path = state["binary_path"]
    security_rules = state["security_rules"]

    console.print(f"[cyan]🔐 Running SSL analysis on: {binary_path}[/cyan]")

    # Get IDA tools from Static Analysis Engine
    tools = await static_engine.get_tools(binary_path)

    # Create SSL agent with structured output
    ssl_agent = agent_factory.create_ssl_agent(
        tools=tools,
        security_rules_content=security_rules
    )

    # Execute SSL agent
    messages = [HumanMessage(content=f"Analyze SSL/TLS security for binary: {binary_path}")]

    result: SSLAnalysisOutput = await stream_and_log_agent(
        agent=ssl_agent,
        messages=messages,
        agent_name="SSL Agent",
        agent_emoji="🔐",
        output_model=SSLAnalysisOutput
    )

    # Check if SSL/TLS analysis is applicable
    if not result.applicable:
        console.print(f"[yellow]ℹ SSL/TLS not applicable: {result.reason}[/yellow]")
        return {
            "applicable": False,
            "ssl_summary": result.reason or "No SSL/TLS client code detected",
            "current_phase": AnalysisPhase.COMPLETED,
            "final_report": result.summary,
        }

    console.print(f"[green]✓ SSL analysis complete: {result.client_type}[/green]")
    console.print(f"[dim]  Rules analyzed: {len(result.rules)}[/dim]")

    # Convert rules list to dict: rule_id -> RuleResult
    rules_dict: Dict[str, RuleResult] = {
        rule.rule_id: rule for rule in result.rules
    }

    # Create dataflow tasks for all CONDITIONAL rules
    pending_dataflow_tasks: List[DataflowTask] = []

    for rule in result.rules:
        if rule.result == RuleResultStatus.CONDITIONAL and rule.conditions:
            # Extract variables from conditions
            variables = [
                {
                    "variable": cond.variable,
                    "function": cond.function,
                    "function_address": cond.function_address,
                    "security_mapping": cond.security_mapping,
                }
                for cond in rule.conditions
            ]

            # Create dataflow task for binary analysis
            task = DataflowTask(
                type="binary",
                target=binary_path,
                variables=variables
            )
            pending_dataflow_tasks.append(task)

    if pending_dataflow_tasks:
        console.print(f"[dim]  Dataflow tasks created: {len(pending_dataflow_tasks)}[/dim]")

    # Build state update
    return {
        "rule_result": rules_dict,
        "ssl_summary": result.summary,
        "client_type": result.client_type,
        "applicable": True,
        "pending_dataflow_tasks": pending_dataflow_tasks,
        "current_phase": AnalysisPhase.DATAFLOW_ANALYSIS if pending_dataflow_tasks else AnalysisPhase.SYNTHESIS,
    }


# ============================================================================
# Node: Dataflow Analysis
# ============================================================================

async def dataflow_analysis_node(
    state: AnalysisState,
    static_engine: StaticAnalysisEngine,
    agent_factory: AgentFactory,
    firmware_tools: List[any],  # For reading scripts/configs if needed
) -> Dict[str, Any]:
    """Execute dataflow analysis for all pending tasks.

    This node:
    1. Processes all pending_dataflow_tasks from state
    2. For each task:
       - Gets appropriate tools (IDA for binary, firmware tools for scripts/configs)
       - Creates dataflow agent
       - Traces all variables in the task
       - Processes structured output (DataflowAnalysisOutput)
    3. Updates state with variable_traces (using binary-qualified keys for cross-binary)
    4. Detects FUNCTION_PARAMETER_FROM_EXTERNAL_CALL traces and creates caller discovery tasks
    5. Creates firmware fetch tasks for CONFIG_FILE sources

    Args:
        state: Current analysis state
        static_engine: Static Analysis Engine for IDA tools
        agent_factory: Agent factory for creating dataflow agent
        firmware_tools: Firmware file system tools

    Returns:
        State update dict with variable_traces, pending_dataflow_tasks (caller discovery tasks)
    """
    pending_tasks = state.get("pending_dataflow_tasks", [])

    if not pending_tasks:
        console.print("[yellow]⚠ No dataflow tasks to process[/yellow]")
        return {"current_phase": AnalysisPhase.SYNTHESIS}

    console.print(f"[cyan]🔍 Running dataflow analysis: {len(pending_tasks)} tasks[/cyan]")

    all_traces: Dict[str, VariableTrace] = state.get("variable_traces", {}).copy()
    new_dataflow_tasks: List[DataflowTask] = []
    config_fetch_tasks: List[ConfigFetchTask] = []

    for task in pending_tasks:
        task_type = task["type"]
        target = task["target"]
        variables = task["variables"]

        console.print(f"[dim]  Processing {task_type} task: {target} ({len(variables)} variables)[/dim]")

        # Get appropriate tools based on task type
        if task_type == "binary":
            tools = await static_engine.get_tools(target)
            agent = agent_factory.create_dataflow_agent(tools=tools)
        elif task_type == "script":
            # For scripts, dataflow agent uses firmware tools to read script
            agent = agent_factory.create_dataflow_agent(tools=firmware_tools)
        else:
            console.print(f"[yellow]⚠ Unknown task type: {task_type}[/yellow]")
            continue

        # Build request with all variables for this task
        variables_desc = "\n".join([
            f"  - Variable '{v['variable']}' in function '{v['function']}' at {v.get('function_address', 'unknown')}"
            for v in variables
        ])

        request = f"Trace the following variables:\n{variables_desc}"
        messages = [HumanMessage(content=request)]

        # Execute dataflow agent
        result: DataflowAnalysisOutput = await stream_and_log_agent(
            agent=agent,
            messages=messages,
            agent_name="Dataflow Agent",
            agent_emoji="🔍",
            output_model=DataflowAnalysisOutput
        )

        # Process traces
        for trace in result.traces:
            # Build composite key based on whether this is cross-binary analysis
            binary_path = task.get("binary_path")
            if binary_path:
                # Cross-binary trace: "{binary_path}:{function}:{variable}"
                composite_key = f"{binary_path}:{trace.function}:{trace.variable}"
            else:
                # Main binary trace: "function:variable"
                composite_key = f"{trace.function}:{trace.variable}"

            all_traces[composite_key] = trace
            console.print(f"[dim]    ✓ {trace.variable}: {trace.source.value}[/dim]")

            # Check if this trace needs config fetching
            if trace.source == VariableSourceType.CONFIG_FILE:
                config_task = ConfigFetchTask(
                    variable=trace.variable,
                    function=trace.function,
                    config_reference=trace.source_details,
                    trace_details=trace.trace_path
                )
                config_fetch_tasks.append(config_task)
                console.print(f"[dim]    → Config fetch needed for {trace.variable} from {trace.source_details}[/dim]")

            # Check if this trace requires cross-binary analysis
            elif trace.source == VariableSourceType.FUNCTION_PARAMETER_FROM_EXTERNAL_CALL:
                # Extract function name from source_details (e.g., "upsc, init_ssl")
                if trace.source_details:
                    # Parse source_details to get function name
                    parts = trace.source_details.split(",")
                    function_name = parts[-1].strip() if len(parts) > 1 else parts[0].strip()

                    # Create a "needs_caller_discovery" task
                    caller_discovery_task = DataflowTask(
                        type="needs_caller_discovery",
                        target=function_name,
                        variables=variables,  # Same variables to trace in callers
                        binary_path=None,
                        context=f"Find callers of {function_name} for variable {trace.variable}"
                    )
                    new_dataflow_tasks.append(caller_discovery_task)
                    console.print(f"[dim]    → Cross-binary discovery needed for function '{function_name}'[/dim]")

    console.print(f"[green]✓ Dataflow complete: {len(all_traces)} traces[/green]")

    # Determine next phase
    if new_dataflow_tasks or config_fetch_tasks:
        next_phase = AnalysisPhase.FIRMWARE_EXPLORATION
    else:
        next_phase = AnalysisPhase.SYNTHESIS

    return {
        "variable_traces": all_traces,
        "pending_dataflow_tasks": new_dataflow_tasks,  # New tasks for caller discovery or cleared
        "pending_config_fetch_tasks": config_fetch_tasks,
        "current_phase": next_phase,
    }


# ============================================================================
# Node: Firmware Exploration
# ============================================================================

async def firmware_explore_node(
    state: AnalysisState,
    agent_factory: AgentFactory,
    firmware_tools: List[any],
    firmware_path: str,
) -> Dict[str, Any]:
    """Execute firmware exploration for various purposes.

    This node handles:
    1. Finding caller binaries (for cross-binary analysis via needs_caller_discovery tasks)
    2. Fetching config values (when dataflow traces to CONFIG_FILE)
    3. Reading scripts (when dataflow needs script content)

    Args:
        state: Current analysis state
        agent_factory: Agent factory for creating firmware agent
        firmware_tools: Firmware file system tools
        firmware_path: Path to firmware root

    Returns:
        State update dict with updated pending_dataflow_tasks, config_values, etc.
    """
    console.print(f"[cyan]📂 Firmware exploration[/cyan]")

    # Create firmware agent
    firmware_agent = agent_factory.create_firmware_agent(
        firmware_tools=firmware_tools,
        firmware_path=firmware_path
    )

    # Determine what type of firmware operation is needed
    pending_tasks = state.get("pending_dataflow_tasks", [])
    config_fetch_tasks = state.get("pending_config_fetch_tasks", [])

    # Find tasks that need caller discovery
    caller_discovery_tasks = [t for t in pending_tasks if t.get("type") == "needs_caller_discovery"]

    if caller_discovery_tasks:
        # Find caller binaries for cross-binary analysis
        task = caller_discovery_tasks[0]  # Process first task
        function_name = task["target"]

        console.print(f"[dim]  Finding binaries that call: {function_name}[/dim]")

        request = f"Find all binaries in firmware that call the function: {function_name}"
        messages = [HumanMessage(content=request)]

        result: FirmwareSearchResult = await stream_and_log_agent(
            agent=firmware_agent,
            messages=messages,
            agent_name="Firmware Agent",
            agent_emoji="📂",
            output_model=FirmwareSearchResult
        )

        # Remove the caller discovery task from pending tasks
        remaining_tasks = [t for t in pending_tasks if t.get("type") != "needs_caller_discovery" or t != task]

        if result.found and result.binaries:
            console.print(f"[green]✓ Found {len(result.binaries)} caller binaries[/green]")
            # Create new dataflow tasks for each caller binary
            for binary_path in result.binaries:
                binary_task = DataflowTask(
                    type="binary",
                    target=binary_path,
                    variables=task["variables"],
                    binary_path=binary_path,
                    context=f"traces call to {function_name}"
                )
                remaining_tasks.append(binary_task)

            return {
                "pending_dataflow_tasks": remaining_tasks,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.CROSS_BINARY_ANALYSIS,
            }
        else:
            console.print(f"[yellow]⚠ No caller binaries found for {function_name}[/yellow]")
            return {
                "pending_dataflow_tasks": remaining_tasks,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }

    elif config_fetch_tasks:
        # Fetch configuration values from firmware
        console.print(f"[dim]  Fetching config values: {len(config_fetch_tasks)} tasks[/dim]")

        # Build request with all config variables to fetch
        config_requests = []
        for task in config_fetch_tasks:
            config_ref = task.config_reference or "configuration file"
            config_requests.append(
                f"  - Variable '{task.variable}' from {config_ref} (used in {task.function})"
            )

        request = (
            f"Search the firmware and extract the following configuration values:\n"
            + "\n".join(config_requests)
        )
        messages = [HumanMessage(content=request)]

        result: FirmwareSearchResult = await stream_and_log_agent(
            agent=firmware_agent,
            messages=messages,
            agent_name="Firmware Agent",
            agent_emoji="📂",
            output_model=FirmwareSearchResult
        )

        if result.found and result.config_values:
            console.print(f"[green]✓ Found {len(result.config_values)} config values[/green]")

            # Update variable traces with fetched config values
            all_traces = state.get("variable_traces", {}).copy()
            for task in config_fetch_tasks:
                composite_key = f"{task.function}:{task.variable}"
                if composite_key in all_traces:
                    # Get the original trace
                    original_trace = all_traces[composite_key]
                    if task.variable in result.config_values:
                        # Create updated trace with fetched value
                        updated_trace = VariableTrace(
                            function=original_trace.function,
                            variable=original_trace.variable,
                            source=original_trace.source,
                            value=result.config_values[task.variable],
                            source_details=original_trace.source_details,
                            confidence=original_trace.confidence,
                            trace_path=original_trace.trace_path
                        )
                        all_traces[composite_key] = updated_trace
                        console.print(f"[dim]    ✓ Updated {task.variable} = {updated_trace.value}[/dim]")

            return {
                "variable_traces": all_traces,
                "pending_config_fetch_tasks": [],  # Clear completed tasks
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
        else:
            console.print(f"[yellow]⚠ No config values found[/yellow]")
            return {
                "pending_config_fetch_tasks": [],
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }

    # If no tasks, proceed to synthesis
    return {"current_phase": AnalysisPhase.SYNTHESIS}


# ============================================================================
# Node: Binary Analysis Sequential (for cross-binary analysis)
# ============================================================================

async def binary_analysis_sequential(
    state: AnalysisState,
    static_engine: StaticAnalysisEngine,
    agent_factory: AgentFactory,
) -> Dict[str, Any]:
    """Analyze multiple binaries sequentially for cross-binary analysis.

    This node processes dataflow tasks with binary_path set, one at a time to avoid
    deadlock issues with parallel MCP session creation.

    Args:
        state: Current analysis state
        static_engine: Static Analysis Engine
        agent_factory: Agent factory

    Returns:
        State update with variable_traces (unified with binary-qualified keys)
    """
    pending_tasks = state.get("pending_dataflow_tasks", [])

    # Filter tasks that have binary_path set (cross-binary tasks)
    cross_binary_tasks = [t for t in pending_tasks if t.get("binary_path") is not None]

    if not cross_binary_tasks:
        console.print("[yellow]⚠ No cross-binary tasks to process[/yellow]")
        return {
            "pending_dataflow_tasks": [],
            "current_phase": AnalysisPhase.SYNTHESIS,
        }

    console.print(f"[cyan]🔄 Analyzing {len(cross_binary_tasks)} caller binaries sequentially[/cyan]")

    # Get existing traces
    all_traces: Dict[str, VariableTrace] = state.get("variable_traces", {}).copy()

    for task in cross_binary_tasks:
        binary_path = task["binary_path"]
        variables = task["variables"]
        context = task.get("context", "")

        console.print(f"[dim]  Analyzing caller: {binary_path}[/dim]")
        console.print(f"[dim]  Context: {context}[/dim]")

        try:
            # Get IDA tools for this binary
            tools = await static_engine.get_tools(binary_path)

            # Create dataflow agent
            agent = agent_factory.create_dataflow_agent(tools=tools)

            # Build request with specific variables to trace
            if variables:
                variables_desc = "\n".join([
                    f"  - Variable '{v['variable']}' in function '{v.get('function', 'unknown')}'"
                    for v in variables
                ])
                request = f"{context}\n\nTrace the following variables:\n{variables_desc}"
            else:
                request = context
            messages = [HumanMessage(content=request)]

            result: DataflowAnalysisOutput = await stream_and_log_agent(
                agent=agent,
                messages=messages,
                agent_name=f"Dataflow ({binary_path.split('/')[-1]})",
                agent_emoji="🔍",
                output_model=DataflowAnalysisOutput
            )

            # Store traces using binary-qualified keys: "{binary_path}:{function}:{variable}"
            for trace in result.traces:
                composite_key = f"{binary_path}:{trace.function}:{trace.variable}"
                all_traces[composite_key] = trace

            console.print(f"[green]  ✓ {binary_path}: {len(result.traces)} traces[/green]")

        except Exception as e:
            console.print(f"[red]  ✗ Error analyzing {binary_path}: {e}[/red]")
            # Continue with other binaries even if one fails

    console.print(f"[green]✓ Cross-binary analysis complete: {len(cross_binary_tasks)} binaries analyzed[/green]")

    return {
        "variable_traces": all_traces,
        "pending_dataflow_tasks": [],  # Clear all tasks
        "current_phase": AnalysisPhase.SYNTHESIS,
    }




# ============================================================================
# Node: Synthesis (Final Report Generation)
# ============================================================================

async def synthesis_node(
    state: AnalysisState,
) -> Dict[str, Any]:
    """Generate final security analysis report.

    This node:
    1. Takes all results from state (rules, variable_traces)
    2. Resolves CONDITIONAL rules using variable traces
    3. Separates main binary traces from cross-binary traces based on key format
    4. Generates comprehensive security report
    5. Updates state with final_report

    Args:
        state: Current analysis state with all results

    Returns:
        State update with final_report and COMPLETED phase
    """
    console.print("[cyan]📝 Generating final report[/cyan]")

    rules = state.get("rule_result", {})
    variable_traces = state.get("variable_traces", {})
    ssl_summary = state.get("ssl_summary", "")
    client_type = state.get("client_type", "Unknown")

    # Separate main binary traces from cross-binary traces based on key format
    # Main binary: "function:variable"
    # Cross-binary: "{binary_path}:{function}:{variable}"
    main_traces = {}
    cross_binary_by_path = {}

    for composite_key, trace in variable_traces.items():
        parts = composite_key.split(":")
        if len(parts) == 2:
            # Main binary trace
            main_traces[composite_key] = trace
        elif len(parts) >= 3:
            # Cross-binary trace: first part is binary path
            binary_path = parts[0]
            trace_key = ":".join(parts[1:])  # "function:variable"
            if binary_path not in cross_binary_by_path:
                cross_binary_by_path[binary_path] = {}
            cross_binary_by_path[binary_path][trace_key] = trace

    # Build report sections
    report_lines = []

    # Header
    report_lines.append("=" * 80)
    report_lines.append("SSL/TLS SECURITY ANALYSIS REPORT")
    report_lines.append("=" * 80)
    report_lines.append("")

    # Client summary
    report_lines.append(f"Client Type: {client_type}")
    report_lines.append("")
    report_lines.append("Summary:")
    report_lines.append(ssl_summary)
    report_lines.append("")

    # Rules section
    report_lines.append("=" * 80)
    report_lines.append("SECURITY RULES ANALYSIS")
    report_lines.append("=" * 80)
    report_lines.append("")

    for rule_id, rule in rules.items():
        report_lines.append(f"Rule: {rule.rule_name}")
        report_lines.append(f"Status: {rule.result.value.upper()}")
        report_lines.append(f"Evidence: {rule.evidence}")

        # If conditional, show variable traces
        if rule.result == RuleResultStatus.CONDITIONAL and rule.conditions:
            report_lines.append("Conditions:")
            for cond in rule.conditions:
                report_lines.append(f"  - Variable: {cond.variable} in {cond.function}")

                # Look up trace using composite key "function:variable"
                composite_key = f"{cond.function}:{cond.variable}"
                if composite_key in main_traces:
                    trace = main_traces[composite_key]
                    report_lines.append(f"    Source: {trace.source.value}")
                    if trace.value:
                        report_lines.append(f"    Value: {trace.value}")
                        # Apply security mapping
                        if trace.value in cond.security_mapping:
                            outcome = cond.security_mapping[trace.value]
                            report_lines.append(f"    Outcome: {outcome}")
                    report_lines.append(f"    Trace: {trace.trace_path}")
                else:
                    report_lines.append(f"    [No trace available]")

        report_lines.append("")

    # Cross-binary findings
    if cross_binary_by_path:
        report_lines.append("=" * 80)
        report_lines.append("CROSS-BINARY ANALYSIS")
        report_lines.append("=" * 80)
        report_lines.append("")

        for binary_path, traces in cross_binary_by_path.items():
            report_lines.append(f"Binary: {binary_path}")
            for trace_key, trace in traces.items():
                # trace_key is "function:variable"
                report_lines.append(f"  - {trace.variable} in {trace.function}: {trace.source.value}")
                if trace.value:
                    report_lines.append(f"    Value: {trace.value}")
            report_lines.append("")

    final_report = "\n".join(report_lines)

    console.print("[green]✓ Final report generated[/green]")

    return {
        "final_report": final_report,
        "current_phase": AnalysisPhase.COMPLETED,
    }
