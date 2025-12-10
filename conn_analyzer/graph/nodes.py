"""Graph nodes for LangGraph-based SSL analysis workflow v2.

This module implements all graph nodes with:
- Structured output (Pydantic models instead of text parsing)
- State as single source of truth (no context passing through agents)
- Integration with Static Analysis Engine and Agent Factory
- Clean separation of concerns
"""

import time
from pathlib import Path
from typing import Dict, Any, List, Sequence, Set, Optional
from langchain_core.messages import HumanMessage

from langgraph.types import Send

from conn_analyzer.graph.state import (
    AnalysisState,
    AnalysisPhase,
    create_trace_key,
    parse_condition_key,
)
from conn_analyzer.graph.models import (
    RuleResultStatus,
    TraceResolvingStatus,
    SSLAnalysisOutput,
    DataflowAnalysisOutput,
    FirmwareSearchResult,
    VariableTrace,
    VariableTraceGroup,
    TraceContinuation,
    ContinuationType,
    RuleResult,
    ConfigFetchTask,
    DataflowTask,
    VariableSpec,
    TaskType,
    SourceKind,
    TraceStepType,
)
from conn_analyzer.static_analysis.engine import StaticAnalysisEngine
from conn_analyzer.agents.factory import AgentFactory
from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.utils.state_logging import (
    log_agent_state,
    log_agent_state_diff,
    capture_state_snapshot,
)

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
        state_update = {
            "applicable": False,
            "ssl_summary": result.reason or "No SSL/TLS client code detected",
            "current_phase": AnalysisPhase.COMPLETED,
            "final_report": result.summary,
        }
        # Log state after agent execution with changes
        log_agent_state("SSL Agent", state, changes=state_update)
        return state_update

    console.print(f"[green]✓ SSL analysis complete: {result.client_type}[/green]")
    console.print(f"[dim]  Rules analyzed: {len(result.rules)}[/dim]")

    # Convert rules list to dict
    # Note: Resolution status is now at trace level, not rule level
    rules_dict: Dict[str, RuleResult] = {}
    for rule in result.rules:
        rules_dict[rule.rule_id] = rule

    # Create dataflow tasks for all CONDITIONAL rules
    pending_dataflow_tasks: List[DataflowTask] = []

    for rule in result.rules:
        if rule.result == RuleResultStatus.CONDITIONAL and rule.conditions:
            # Extract variables from conditions as VariableSpec objects
            variables = [
                VariableSpec(
                    variable=cond.variable,
                    function=cond.function,
                    function_address=cond.function_address,
                    security_mapping=cond.security_mapping,
                )
                for cond in rule.conditions
            ]

            # Create dataflow task for binary analysis
            task = DataflowTask(
                type=TaskType.BINARY,
                target=binary_path,
                variables=variables
            )
            pending_dataflow_tasks.append(task)

    if pending_dataflow_tasks:
        console.print(f"[dim]  Dataflow tasks created: {len(pending_dataflow_tasks)}[/dim]")

    # Build state update
    state_update = {
        "rule_result": rules_dict,
        "ssl_summary": result.summary,
        "client_type": result.client_type,
        "applicable": True,
        "pending_dataflow_tasks": pending_dataflow_tasks,
        "current_phase": AnalysisPhase.DATAFLOW_ANALYSIS if pending_dataflow_tasks else AnalysisPhase.SYNTHESIS,
    }

    # Log state after agent execution with changes
    log_agent_state("SSL Agent", state, changes=state_update)
    return state_update


# ============================================================================
# Helper: Task Creation from Traces
# ============================================================================

def create_follow_up_tasks_from_trace(
    trace: VariableTrace,
    binary_path: Optional[str],
    variables: List[VariableSpec]
) -> tuple[List[DataflowTask], List[ConfigFetchTask]]:
    """Extract config/script/cross-binary tasks from a single trace.

    Args:
        trace: The variable trace to process
        binary_path: Path to the binary being analyzed (for cross-binary context)
        variables: Original variables list (VariableSpec objects) for security_mapping lookup

    Returns:
        (new_dataflow_tasks, config_fetch_tasks)
    """
    new_dataflow_tasks = []
    config_fetch_tasks = []

    # Get source info from the final step of trace_path
    if not trace.trace_path:
        return new_dataflow_tasks, config_fetch_tasks

    last_step = trace.trace_path[-1]

    # Only process TRACE_END steps with source_kind
    if last_step.step_type != TraceStepType.TRACE_END or not last_step.source_kind:
        return new_dataflow_tasks, config_fetch_tasks

    source_kind = last_step.source_kind

    # Check if this trace needs config fetching
    if source_kind == SourceKind.CONFIG_FILE:
        config_reference = last_step.config_file or "unknown_config_file"
        if last_step.config_key:
            config_reference = f"{config_reference} (key: {last_step.config_key})"

        config_task = ConfigFetchTask(
            variable=trace.variable,
            function=trace.function,
            config_reference=config_reference,
            trace_details=str(trace.trace_path)  # Convert to string for storage
        )
        config_fetch_tasks.append(config_task)

    # Check if this trace comes from command-line arguments
    elif source_kind == SourceKind.COMMAND_LINE_ARG:
        arg_name = last_step.arg_name or "CLI argument"

        # Find the original variable's security_mapping
        original_var = next((v for v in variables if v["variable"] == trace.variable and v["function"] == trace.function), None)
        security_mapping = original_var.get("security_mapping", {}) if original_var else {}

        script_discovery_task = DataflowTask(
            type=TaskType.NEEDS_SCRIPT_DISCOVERY,
            target=binary_path if binary_path else "unknown",
            variables=[VariableSpec(
                variable=trace.variable,
                function=trace.function,
                function_address=None,
                security_mapping=security_mapping,
            )],
            binary_path=None,
            context=f"Find scripts/binaries that invoke this binary and extract CLI argument: {arg_name}"
        )
        new_dataflow_tasks.append(script_discovery_task)

    # Check for further cross-binary calls
    elif source_kind == SourceKind.EXTERNAL_CALL:
        function_name = last_step.external_function
        parameter_name = last_step.parameter_name

        if function_name and parameter_name:
            # Find the original variable's security_mapping
            original_var = next((v for v in variables if v["variable"] == trace.variable and v["function"] == trace.function), None)
            security_mapping = original_var.get("security_mapping", {}) if original_var else {}

            # Origin condition is the original traced variable (function:variable)
            origin_condition = f"{trace.function}:{trace.variable}"

            caller_discovery_task = DataflowTask(
                type=TaskType.NEEDS_CALLER_DISCOVERY,
                target=function_name,
                variables=[VariableSpec(
                    variable=parameter_name,
                    function=function_name,
                    function_address=None,
                    security_mapping=security_mapping,
                )],
                binary_path=None,
                context=f"Find callers of {function_name} and trace parameter {parameter_name}",
                origin_condition=origin_condition,
            )
            new_dataflow_tasks.append(caller_discovery_task)

    return new_dataflow_tasks, config_fetch_tasks


# ============================================================================
# Helper: Execute Single Dataflow Task
# ============================================================================

async def execute_single_dataflow_task(
    task: DataflowTask,
    static_engine: StaticAnalysisEngine,
    agent_factory: AgentFactory,
    firmware_tools: List[any],
) -> DataflowAnalysisOutput:
    """Execute dataflow analysis for a single task.

    Extracts common logic shared by dataflow_analysis_node and
    binary_analysis_sequential to eliminate ~190 lines of duplication.

    Args:
        task: DataflowTask to process
        static_engine: Static Analysis Engine for IDA tools
        agent_factory: Agent factory for creating dataflow agent
        firmware_tools: Firmware tools for script analysis

    Returns:
        DataflowAnalysisOutput with traced variables

    Raises:
        Exception: If agent execution fails
    """
    task_type = task.type
    target = task.target
    variables = task.variables
    context = task.context or ""

    # Get appropriate tools based on task type
    if task_type == TaskType.BINARY:
        tools = await static_engine.get_tools(target)
        agent = agent_factory.create_dataflow_agent(tools=tools)
    elif task_type == TaskType.SCRIPT:
        # For scripts, dataflow agent uses firmware tools to read script
        agent = agent_factory.create_dataflow_agent(tools=firmware_tools)
    else:
        raise ValueError(f"Unknown task type: {task_type}")

    # Build request message
    if variables:
        # Detect cross-binary task by checking if binary_path is set
        if task.binary_path:
            # Cross-binary analysis: omit address clause since we're looking for function calls
            variables_desc = "\n".join([
                f"  - Variable '{v.variable}' in function '{v.function}'"
                for v in variables
            ])
        else:
            # Regular dataflow: include address if available
            variables_desc = "\n".join([
                f"  - Variable '{v.variable}' in function '{v.function}' at {v.function_address or 'unknown'}"
                for v in variables
            ])

        if context:
            request = f"{context}\n\nTrace the following variables:\n{variables_desc}"
        else:
            request = f"Trace the following variables:\n{variables_desc}"
    else:
        request = context

    messages = [HumanMessage(content=request)]

    # Execute dataflow agent
    result: DataflowAnalysisOutput = await stream_and_log_agent(
        agent=agent,
        messages=messages,
        agent_name=f"Dataflow ({target.split('/')[-1] if '/' in target else target})",
        agent_emoji="🔍",
        output_model=DataflowAnalysisOutput
    )

    return result


# ============================================================================
# Helper: Trace Group Management
# ============================================================================

def get_or_create_trace_group(
    trace_groups: Dict[str, VariableTraceGroup],
    function: str,
    variable: str,
    security_mapping: Optional[Dict[str, str]] = None,
) -> VariableTraceGroup:
    """Get existing trace group or create a new one.

    Args:
        trace_groups: Dict of existing trace groups
        function: Function name
        variable: Variable name
        security_mapping: Optional security mapping for this condition

    Returns:
        Existing or new VariableTraceGroup
    """
    condition_key = f"{function}:{variable}"
    if condition_key not in trace_groups:
        trace_groups[condition_key] = VariableTraceGroup(
            condition_key=condition_key,
            function=function,
            variable=variable,
            security_mapping=security_mapping,
        )
    elif security_mapping and not trace_groups[condition_key].security_mapping:
        # Update security mapping if not already set
        trace_groups[condition_key].security_mapping = security_mapping
    return trace_groups[condition_key]


def add_trace_to_group(
    trace_group: VariableTraceGroup,
    trace: VariableTrace,
    binary_path: Optional[str] = None,
) -> None:
    """Add a trace to the appropriate location in a trace group.

    Args:
        trace_group: The trace group to update
        trace: The trace to add
        binary_path: If set, trace is from cross-binary analysis
    """
    if binary_path:
        # Cross-binary trace: add to continuation
        continuation = None
        for cont in trace_group.continuations:
            if cont.source_path == binary_path and cont.type == ContinuationType.CROSS_BINARY:
                continuation = cont
                break

        if continuation is None:
            continuation = TraceContinuation(
                type=ContinuationType.CROSS_BINARY,
                source_path=binary_path,
            )
            trace_group.continuations.append(continuation)

        continuation.traces.append(trace)

        # Check if trace resolved to a value
        if trace.trace_path:
            last_step = trace.trace_path[-1]
            if last_step.step_type == TraceStepType.TRACE_END:
                if last_step.source_kind == SourceKind.CONSTANT and last_step.constant_value:
                    continuation.resolved_value = last_step.constant_value
                    continuation.resolved_source_kind = SourceKind.CONSTANT
                elif trace.value:
                    continuation.resolved_value = trace.value
                    continuation.resolved_source_kind = last_step.source_kind
    else:
        # Main binary trace
        trace_group.main_traces.append(trace)


def find_security_mapping_for_trace(
    state: AnalysisState,
    function: str,
    variable: str,
) -> Optional[Dict[str, str]]:
    """Find security mapping for a trace from rule conditions.

    Args:
        state: Current analysis state
        function: Function name
        variable: Variable name

    Returns:
        Security mapping if found, None otherwise
    """
    rules = state.get("rule_result", {})
    for rule in rules.values():
        for cond in rule.conditions:
            if cond.function == function and cond.variable == variable:
                return cond.security_mapping
    return None


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
    3. Updates state with trace_groups (hierarchical storage by condition)
    4. Detects FUNCTION_PARAMETER_FROM_EXTERNAL_CALL traces and creates caller discovery tasks
    5. Creates firmware fetch tasks for CONFIG_FILE sources

    Args:
        state: Current analysis state
        static_engine: Static Analysis Engine for IDA tools
        agent_factory: Agent factory for creating dataflow agent
        firmware_tools: Firmware file system tools

    Returns:
        State update dict with trace_groups, pending_dataflow_tasks (caller discovery tasks)
    """
    pending_tasks = state.get("pending_dataflow_tasks", [])

    if not pending_tasks:
        console.print("[yellow]⚠ No dataflow tasks to process[/yellow]")
        state_update = {"current_phase": AnalysisPhase.SYNTHESIS}
        # Log state after (no agent execution in this case)
        log_agent_state("Dataflow Agent", state, changes=state_update)
        return state_update

    console.print(f"[cyan]🔍 Running dataflow analysis: {len(pending_tasks)} tasks[/cyan]")

    # Get existing trace groups (deep copy)
    trace_groups: Dict[str, VariableTraceGroup] = {}
    for key, group in state.get("trace_groups", {}).items():
        trace_groups[key] = group.model_copy(deep=True)

    new_dataflow_tasks: List[DataflowTask] = []
    config_fetch_tasks: List[ConfigFetchTask] = []

    total_tasks = len(pending_tasks)

    for task_idx, task in enumerate(pending_tasks):
        console.print(f"[dim]  Processing {task.type.value} task: {task.target} ({len(task.variables)} variables)[/dim]")

        agent_name_with_progress = f"Dataflow Agent ({task_idx + 1}/{total_tasks})"

        # Capture state BEFORE processing this task
        state_before = capture_state_snapshot(
            config_fetch_tasks, new_dataflow_tasks, trace_groups
        )

        # Execute dataflow analysis for this task using shared helper
        try:
            result: DataflowAnalysisOutput = await execute_single_dataflow_task(
                task=task,
                static_engine=static_engine,
                agent_factory=agent_factory,
                firmware_tools=firmware_tools,
            )
        except Exception as e:
            console.print(f"[red]✗ Error processing task: {e}[/red]")
            continue

        # NOTE:
        # Firmware Agent needs to report file type and file type.

        # Process traces
        for trace in result.traces:
            # Build composite key based on whether this is cross-binary analysis
            binary_path = task.binary_path  # Use attribute access for Pydantic model

            # Update trace_groups with hierarchical structure
            # Find security mapping from task variables
            original_var = next(
                (v for v in task.variables if v.variable == trace.variable and v.function == trace.function),
                None
            )
            security_mapping = original_var.security_mapping if original_var else None
            if not security_mapping:
                # Fallback: look up from state's rule conditions
                security_mapping = find_security_mapping_for_trace(state, trace.function, trace.variable)

            trace_group = get_or_create_trace_group(
                trace_groups,
                trace.function,
                trace.variable,
                security_mapping,
            )
            add_trace_to_group(trace_group, trace, binary_path)

            # Get source info from final step of trace_path
            last_step = trace.trace_path[-1] if trace.trace_path else None
            source_kind = last_step.source_kind if last_step and last_step.step_type == TraceStepType.TRACE_END else None
            console.print(f"[dim]    ✓ {trace.variable}: {source_kind.value if source_kind else 'unknown'}[/dim]")

            # Check if this trace needs config fetching
            if source_kind == SourceKind.CONFIG_FILE:
                config_reference = last_step.config_file or "unknown_config_file"
                if last_step.config_key:
                    config_reference = f"{config_reference} (key: {last_step.config_key})"

                config_task = ConfigFetchTask(
                    variable=trace.variable,
                    function=trace.function,
                    config_reference=config_reference,
                    trace_details=str(trace.trace_path)
                )
                config_fetch_tasks.append(config_task)
                console.print(f"[dim]    → Config fetch needed for {trace.variable} from {config_reference}[/dim]")

            # Check if this trace requires cross-binary analysis
            elif source_kind == SourceKind.EXTERNAL_CALL:
                function_name = last_step.external_function
                parameter_name = last_step.parameter_name

                if function_name and parameter_name:
                    # Find the original variable's security_mapping to preserve it
                    original_var = next((v for v in task.variables if v.variable == trace.variable and v.function == trace.function), None)
                    security_mapping = original_var.security_mapping if (original_var and original_var.security_mapping) else {}

                    # Create NEW variables for the external function's parameter
                    new_variables = [VariableSpec(
                        variable=parameter_name,
                        function=function_name,
                        function_address=None,
                        security_mapping=security_mapping,
                    )]

                    # Determine origin_condition: use existing if propagated, otherwise use current trace
                    origin_condition = task.origin_condition or f"{trace.function}:{trace.variable}"

                    # Create a "needs_caller_discovery" task
                    caller_discovery_task = DataflowTask(
                        type=TaskType.NEEDS_CALLER_DISCOVERY,
                        target=function_name,
                        variables=new_variables,
                        binary_path=None,
                        context=f"Find callers of {function_name} and trace parameter {parameter_name}",
                        origin_condition=origin_condition,
                    )
                    new_dataflow_tasks.append(caller_discovery_task)
                    console.print(f"[dim]    → Cross-binary discovery needed for function '{function_name}', parameter '{parameter_name}'[/dim]")
                else:
                    console.print(f"[yellow]⚠ Missing external_function or parameter_name in trace_end step[/yellow]")

            # Check if this trace comes from command-line arguments
            elif source_kind == SourceKind.COMMAND_LINE_ARG:
                arg_name = last_step.arg_name or "CLI argument"

                # Find the original variable's security_mapping
                original_var = next((v for v in task.variables if v.variable == trace.variable and v.function == trace.function), None)
                security_mapping = original_var.security_mapping if (original_var and original_var.security_mapping) else {}

                # Create variables for CLI arg analysis in calling scripts/binaries
                cli_variables = [VariableSpec(
                    variable=trace.variable,
                    function=trace.function,
                    function_address=None,
                    security_mapping=security_mapping,
                )]

                # Create a "needs_script_discovery" task to find startup scripts/binaries
                script_discovery_task = DataflowTask(
                    type=TaskType.NEEDS_SCRIPT_DISCOVERY,
                    target=binary_path,
                    variables=cli_variables,
                    binary_path=None,
                    context=f"Find scripts/binaries that invoke this binary and extract CLI argument: {arg_name}"
                )
                new_dataflow_tasks.append(script_discovery_task)
                console.print(f"[dim]    → Script discovery needed for CLI argument '{arg_name}'[/dim]")

        # Capture state AFTER processing and log diff
        state_after = capture_state_snapshot(
            config_fetch_tasks, new_dataflow_tasks, trace_groups
        )
        log_agent_state_diff(agent_name_with_progress, state_before, state_after)

    console.print(f"[green]✓ Dataflow complete: {len(trace_groups)} trace groups[/green]")

    # Determine next phase
    if new_dataflow_tasks or config_fetch_tasks:
        next_phase = AnalysisPhase.FIRMWARE_EXPLORATION
    else:
        next_phase = AnalysisPhase.SYNTHESIS

    state_update = {
        "trace_groups": trace_groups,
        "pending_dataflow_tasks": new_dataflow_tasks,  # New tasks for caller discovery or cleared
        "pending_config_fetch_tasks": config_fetch_tasks,
        "current_phase": next_phase,
    }

    # Note: Individual task state changes are logged inside the loop
    return state_update


# ============================================================================
# Node: Firmware Exploration - Helper Functions
# ============================================================================

async def _process_caller_discovery(
    caller_discovery_tasks: List[DataflowTask],
    firmware_agent,
    pending_tasks: List[DataflowTask],
) -> tuple[List[DataflowTask], str]:
    """Process caller discovery tasks and return new cross-binary tasks.

    Args:
        caller_discovery_tasks: Tasks that need caller discovery
        firmware_agent: Firmware agent for searching
        pending_tasks: All pending tasks

    Returns:
        Tuple of (remaining_tasks_with_cross_binary_tasks, firmware_details)
    """
    # Extract all unique function names from all discovery tasks (deduplicate)
    function_names = list(dict.fromkeys(task.target for task in caller_discovery_tasks))

    console.print(f"[dim]  Finding binaries that call {len(function_names)} function(s): {', '.join(function_names)}[/dim]")

    # Build batch request (backward compatible for single task)
    if len(function_names) == 1:
        request = f"Find all binaries in firmware that call the function: {function_names[0]}"
    else:
        functions_list = "\n".join([f"  - {fname}" for fname in function_names])
        request = (
            f"Find all binaries in firmware that call ANY of these functions:\n"
            f"{functions_list}\n\n"
            f"For each binary found, specify which function(s) it calls."
        )
    messages = [HumanMessage(content=request)]

    result: FirmwareSearchResult = await stream_and_log_agent(
        agent=firmware_agent,
        messages=messages,
        agent_name="Firmware Agent",
        agent_emoji="📂",
        output_model=FirmwareSearchResult
    )

    # Remove ALL caller discovery tasks from pending
    remaining_tasks = [t for t in pending_tasks if t.type != TaskType.NEEDS_CALLER_DISCOVERY]

    if result.found and result.executables:
        console.print(f"[green]✓ Found {len(result.executables)} caller binaries for {len(caller_discovery_tasks)} function(s)[/green]")

        # Build reverse mapping: binary → functions it calls
        binary_to_functions: Dict[str, Set[str]] = {}

        if result.function_calls:
            # Use structured mapping from firmware agent
            console.print(f"[dim]  Using structured function_calls mapping[/dim]")
            for function_name, binary_paths in result.function_calls.items():
                for binary_path in binary_paths:
                    if binary_path not in binary_to_functions:
                        binary_to_functions[binary_path] = set()
                    binary_to_functions[binary_path].add(function_name)
        else:
            # Fallback: assume all binaries call all functions (backward compatibility)
            console.print(f"[yellow]⚠ No function_calls mapping - assigning all variables to all binaries[/yellow]")
            all_function_names = {task.target for task in caller_discovery_tasks}
            for binary_path in result.executables:
                binary_to_functions[binary_path] = all_function_names

        # Create function_to_variables and function_to_origin mappings for efficient lookup
        function_to_variables: Dict[str, List[VariableSpec]] = {}
        function_to_origin: Dict[str, str] = {}  # function_name -> origin_condition
        for task in caller_discovery_tasks:
            function_name = task.target
            function_to_variables[function_name] = task.variables
            if task.origin_condition:
                function_to_origin[function_name] = task.origin_condition

        # Create cross-binary tasks with function-specific variables
        for binary_path in result.executables:
            # Get functions this binary calls
            functions_called = binary_to_functions.get(binary_path, set())

            if not functions_called:
                console.print(f"[yellow]⚠ Binary {binary_path} has no function mapping - skipping[/yellow]")
                continue

            # Aggregate variables ONLY from functions this binary calls
            aggregated_variables: List[VariableSpec] = []
            # Build origin_conditions mapping: "function:variable" -> origin_condition
            origin_conditions: Dict[str, str] = {}

            for function_name in functions_called:
                if function_name in function_to_variables:
                    for var_spec in function_to_variables[function_name]:
                        aggregated_variables.append(var_spec)
                        # Map each variable to its origin condition
                        if function_name in function_to_origin:
                            var_key = f"{var_spec.function}:{var_spec.variable}"
                            origin_conditions[var_key] = function_to_origin[function_name]

            if not aggregated_variables:
                console.print(f"[dim]  Binary {binary_path} calls {functions_called} but no variables to trace[/dim]")
                continue

            # Log which functions and how many variables
            console.print(f"[dim]  Binary {binary_path} calls: {', '.join(sorted(functions_called))} ({len(aggregated_variables)} variables)[/dim]")

            binary_task = DataflowTask(
                type=TaskType.BINARY,
                target=binary_path,
                variables=aggregated_variables,
                binary_path=binary_path,
                origin_conditions=origin_conditions if origin_conditions else None,
            )
            remaining_tasks.append(binary_task)

        return remaining_tasks, result.details
    else:
        console.print(f"[yellow]⚠ No caller binaries found for function(s): {', '.join(function_names)}[/yellow]")
        return remaining_tasks, result.details


async def _process_script_discovery(
    script_discovery_tasks: List[DataflowTask],
    firmware_agent,
    pending_tasks: List[DataflowTask],
) -> tuple[List[DataflowTask], Optional[List[str]], str]:
    """Process script discovery tasks to find startup scripts.

    Args:
        script_discovery_tasks: Tasks that need script discovery
        firmware_agent: Firmware agent for searching
        pending_tasks: All pending tasks

    Returns:
        Tuple of (remaining_tasks, script_findings, firmware_details)
    """
    # Process first task
    task = script_discovery_tasks[0]
    binary_target = task.target
    context = task.context or ""

    console.print(f"[dim]  Finding scripts/binaries that invoke: {binary_target}[/dim]")
    console.print(f"[dim]  Context: {context}[/dim]")

    request = f"Find all startup scripts and binaries in firmware that invoke the binary: {binary_target}\n\n{context}"
    messages = [HumanMessage(content=request)]

    result: FirmwareSearchResult = await stream_and_log_agent(
        agent=firmware_agent,
        messages=messages,
        agent_name="Firmware Agent",
        agent_emoji="📂",
        output_model=FirmwareSearchResult
    )

    # Remove the script discovery task from pending tasks
    remaining_tasks = [t for t in pending_tasks if t.type != TaskType.NEEDS_SCRIPT_DISCOVERY or t != task]

    if result.found and result.executables:
        console.print(f"[green]✓ Found {len(result.executables)} startup scripts/binaries[/green]")
        # For now, just report the findings (future: could parse scripts to extract CLI args)
        return remaining_tasks, result.executables, result.details
    else:
        console.print(f"[yellow]⚠ No startup scripts found for {binary_target}[/yellow]")
        return remaining_tasks, None, result.details


async def _process_config_fetch(
    config_fetch_tasks: List[ConfigFetchTask],
    firmware_agent,
    trace_groups: Dict[str, VariableTraceGroup],
) -> tuple[Dict[str, VariableTraceGroup], str]:
    """Process config fetch tasks and update trace_groups with fetched values.

    Args:
        config_fetch_tasks: Tasks that need config value fetching
        firmware_agent: Firmware agent for searching
        trace_groups: Current trace groups to update

    Returns:
        Tuple of (updated_trace_groups, firmware_details)
    """
    console.print(f"[dim]  Fetching config values: {len(config_fetch_tasks)} tasks[/dim]")

    # Build structured request with explicit constraints
    config_requests = []
    for task in config_fetch_tasks:
        config_ref = task.config_reference or "configuration file"
        config_requests.append(f"  - {config_ref}")

    request = (
        f"CONFIG FETCH TASK:\n\n"
        f"Extract the following configuration values from their respective files:\n"
        + "\n".join(config_requests) + "\n\n"
        f"INSTRUCTIONS:\n"
        f"1. Find and read ONLY the specified config files\n"
        f"2. Extract ONLY the specified keys from each file\n"
        f"3. Use empty string (\"\") for keys not found in the file\n"
        f"4. STOP after reading the files - do NOT search binaries or other configs\n"
    )
    messages = [HumanMessage(content=request)]

    result: FirmwareSearchResult = await stream_and_log_agent(
        agent=firmware_agent,
        messages=messages,
        agent_name="Firmware Agent",
        agent_emoji="📂",
        output_model=FirmwareSearchResult
    )

    # Validation: warn if agent returned unexpected results for config fetch
    if result.executables and len(result.executables) > 0:
        console.print(
            f"[yellow]⚠ Warning: Config fetch returned {len(result.executables)} binaries. "
            f"This suggests the agent did unnecessary searches.[/yellow]"
        )

    if result.found and result.config_values:
        console.print(f"[green]✓ Found {len(result.config_values)} config values[/green]")

        # Update trace_groups with fetched config values
        for task in config_fetch_tasks:
            condition_key = f"{task.function}:{task.variable}"

            # Find or create trace group for this condition
            if condition_key not in trace_groups:
                # Edge case: trace group doesn't exist, create it
                trace_groups[condition_key] = VariableTraceGroup(
                    condition_key=condition_key,
                    function=task.function,
                    variable=task.variable,
                )

            trace_group = trace_groups[condition_key]

            # Extract config file path from config_reference
            # Format: "filename.conf (key: KEYNAME)" or just "filename.conf"
            config_path = task.config_reference or "unknown_config"
            if " (key:" in config_path:
                config_path = config_path.split(" (key:")[0].strip()

            # Get the fetched value for this variable
            fetched_value = result.config_values.get(task.variable)

            # Create config continuation
            config_continuation = TraceContinuation(
                type=ContinuationType.CONFIG_FILE,
                source_path=config_path,
                config_values={task.variable: fetched_value} if fetched_value is not None else {},
                resolved_value=fetched_value,
                resolved_source_kind=SourceKind.CONFIG_FILE if fetched_value else None,
            )

            # Add to trace group's continuations
            trace_group.continuations.append(config_continuation)
            console.print(f"[dim]    ✓ {task.variable} = {fetched_value or '(not found)'}[/dim]")

        return trace_groups, result.details
    else:
        console.print(f"[yellow]⚠ No config values found[/yellow]")
        return trace_groups, result.details


# ============================================================================
# Node: Firmware Exploration
# ============================================================================

async def firmware_explore_node(
    state: AnalysisState,
    agent_factory: AgentFactory,
    firmware_tools: List[any],
    firmware_path: str,
) -> Dict[str, Any]:
    """Execute firmware exploration for ALL pending tasks.

    Processes tasks in priority order:
    1. Caller discovery (cross-binary analysis)
    2. Script discovery (CLI argument sources)
    3. Config fetch (configuration values)

    All task types are processed in a single execution to prevent
    task starvation due to early returns.

    Args:
        state: Current analysis state
        agent_factory: Agent factory for creating firmware agent
        firmware_tools: Firmware file system tools
        firmware_path: Path to firmware root

    Returns:
        State update dict with updated pending_dataflow_tasks, config_values, etc.
    """
    console.print(f"[cyan]📂 Firmware exploration[/cyan]")

    # Create firmware agent (shared for all task types)
    firmware_agent = agent_factory.create_firmware_agent(
        firmware_tools=firmware_tools,
        firmware_path=firmware_path
    )

    # Get pending tasks
    pending_tasks = state.get("pending_dataflow_tasks", [])
    config_fetch_tasks = state.get("pending_config_fetch_tasks", [])

    # Categorize tasks by type
    caller_discovery_tasks = [t for t in pending_tasks if t.type == TaskType.NEEDS_CALLER_DISCOVERY]
    script_discovery_tasks = [t for t in pending_tasks if t.type == TaskType.NEEDS_SCRIPT_DISCOVERY]

    # Initialize accumulated state update
    accumulated_update = {
        "pending_dataflow_tasks": [t for t in pending_tasks
                                   if t.type not in [TaskType.NEEDS_CALLER_DISCOVERY,
                                                     TaskType.NEEDS_SCRIPT_DISCOVERY]],
        "pending_config_fetch_tasks": [],
        "firmware_details": "",
        "script_findings": state.get("script_findings"),
    }

    errors = []
    details_parts = []

    # ========================================================================
    # Priority 1: Caller Discovery (Cross-Binary Analysis)
    # ========================================================================
    if caller_discovery_tasks:
        # Capture state BEFORE caller discovery
        state_before = capture_state_snapshot(
            [],  # config tasks not affected by caller discovery
            accumulated_update["pending_dataflow_tasks"]
        )

        try:
            remaining, details = await _process_caller_discovery(
                caller_discovery_tasks, firmware_agent, pending_tasks
            )
            accumulated_update["pending_dataflow_tasks"] = remaining
            details_parts.append(details)

            # Capture state AFTER caller discovery and log diff
            state_after = capture_state_snapshot(
                [],
                accumulated_update["pending_dataflow_tasks"]
            )
            log_agent_state_diff("Firmware Agent - Caller Discovery", state_before, state_after)

        except Exception as e:
            errors.append(f"Caller discovery failed: {e}")
            console.print(f"[red]✗ Caller discovery error: {e}[/red]")

    # ========================================================================
    # Priority 2: Script Discovery (CLI Arguments) - NO elif!
    # ========================================================================
    if script_discovery_tasks:
        # Capture state BEFORE script discovery
        state_before = capture_state_snapshot(
            [],
            accumulated_update["pending_dataflow_tasks"]
        )

        try:
            remaining, script_findings, details = await _process_script_discovery(
                script_discovery_tasks, firmware_agent,
                accumulated_update["pending_dataflow_tasks"]
            )
            accumulated_update["pending_dataflow_tasks"] = remaining
            accumulated_update["script_findings"] = script_findings
            details_parts.append(details)

            # Capture state AFTER script discovery and log diff
            state_after = capture_state_snapshot(
                [],
                accumulated_update["pending_dataflow_tasks"]
            )
            log_agent_state_diff("Firmware Agent - Script Discovery", state_before, state_after)

        except Exception as e:
            errors.append(f"Script discovery failed: {e}")
            console.print(f"[red]✗ Script discovery error: {e}[/red]")

    # ========================================================================
    # Priority 3: Config Fetch (Configuration Values)
    # ========================================================================
    if config_fetch_tasks:
        # Get trace_groups from state (deep copy)
        trace_groups: Dict[str, VariableTraceGroup] = {}
        for key, group in state.get("trace_groups", {}).items():
            trace_groups[key] = group.model_copy(deep=True)

        # Capture state BEFORE config fetch
        state_before = capture_state_snapshot(
            config_fetch_tasks,
            accumulated_update["pending_dataflow_tasks"],
            trace_groups
        )

        try:
            updated_groups, details = await _process_config_fetch(
                config_fetch_tasks, firmware_agent, trace_groups
            )
            accumulated_update["trace_groups"] = updated_groups
            accumulated_update["pending_config_fetch_tasks"] = []
            details_parts.append(details)

            # Capture state AFTER config fetch and log diff
            state_after = capture_state_snapshot(
                [],
                accumulated_update["pending_dataflow_tasks"],
                updated_groups
            )
            log_agent_state_diff("Firmware Agent - Config Fetch", state_before, state_after)

        except Exception as e:
            errors.append(f"Config fetch failed: {e}")
            console.print(f"[red]✗ Config fetch error: {e}[/red]")

    # Merge all firmware details
    accumulated_update["firmware_details"] = "\n\n".join(filter(None, details_parts))

    # Add any errors
    if errors:
        accumulated_update["errors"] = state.get("errors", []) + errors

    # Determine next phase based on what remains
    if accumulated_update["pending_dataflow_tasks"]:
        # Check if there are cross-binary tasks
        has_cross_binary = any(t.binary_path is not None
                               for t in accumulated_update["pending_dataflow_tasks"])
        if has_cross_binary:
            accumulated_update["current_phase"] = AnalysisPhase.CROSS_BINARY_ANALYSIS
        else:
            # Still have discovery tasks - loop back
            accumulated_update["current_phase"] = AnalysisPhase.FIRMWARE_EXPLORATION
    else:
        accumulated_update["current_phase"] = AnalysisPhase.SYNTHESIS

    # Per-agent state changes already logged after each helper function
    return accumulated_update


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
        State update with trace_groups (hierarchical storage by condition)
    """
    pending_tasks = state.get("pending_dataflow_tasks", [])

    # Filter tasks that have binary_path set (cross-binary tasks)
    cross_binary_tasks = [t for t in pending_tasks if t.binary_path is not None]

    if not cross_binary_tasks:
        console.print("[yellow]⚠ No cross-binary tasks to process[/yellow]")
        state_update = {
            "pending_dataflow_tasks": [],
            "current_phase": AnalysisPhase.SYNTHESIS,
        }
        # Log state after (no agent execution in this case)
        log_agent_state("Dataflow Agent", state, changes=state_update)
        return state_update

    console.print(f"[cyan]🔄 Analyzing {len(cross_binary_tasks)} caller binaries sequentially[/cyan]")

    # Accumulate follow-up tasks from cross-binary traces
    config_fetch_tasks: List[ConfigFetchTask] = []
    new_dataflow_tasks: List[DataflowTask] = []

    # Get existing trace groups - deep copy
    trace_groups: Dict[str, VariableTraceGroup] = {}
    for key, group in state.get("trace_groups", {}).items():
        trace_groups[key] = group.model_copy(deep=True)

    for task_idx, task in enumerate(cross_binary_tasks):
        binary_path = task.binary_path
        binary_name = Path(binary_path).name
        agent_name = f"Cross-binary ({task_idx + 1}/{len(cross_binary_tasks)}: {binary_name})"
        context = task.context or ""

        console.print(f"[dim]  Analyzing caller: {binary_path}[/dim]")
        if context:
            console.print(f"[dim]  Context: {context}[/dim]")

        # Capture state BEFORE processing this task
        state_before = capture_state_snapshot(
            config_fetch_tasks, new_dataflow_tasks, trace_groups
        )

        try:
            # Execute dataflow analysis using shared helper
            result: DataflowAnalysisOutput = await execute_single_dataflow_task(
                task=task,
                static_engine=static_engine,
                agent_factory=agent_factory,
                firmware_tools=[],  # Cross-binary tasks are always BINARY type, no firmware tools needed
            )

            # Process traces and add to trace_groups
            for trace in result.traces:
                # === BEGIN: Origin condition handling ===
                # Determine origin condition for trace group linkage
                trace_key = f"{trace.function}:{trace.variable}"
                origin_key = None

                # Priority: origin_conditions mapping > origin_condition > fallback to trace key
                if task.origin_conditions and trace_key in task.origin_conditions:
                    origin_key = task.origin_conditions[trace_key]
                elif task.origin_condition:
                    origin_key = task.origin_condition

                # Parse origin_key to get function and variable for trace group
                if origin_key:
                    try:
                        origin_func, origin_var = parse_condition_key(origin_key)
                    except ValueError:
                        origin_func, origin_var = trace.function, trace.variable
                else:
                    origin_func, origin_var = trace.function, trace.variable

                # Find security mapping from the ORIGINAL condition
                security_mapping = find_security_mapping_for_trace(state, origin_func, origin_var)
                if not security_mapping:
                    original_var = next(
                        (v for v in task.variables if v.variable == trace.variable and v.function == trace.function),
                        None
                    )
                    security_mapping = original_var.security_mapping if original_var else None

                # Get or create trace group under ORIGIN condition key
                trace_group = get_or_create_trace_group(
                    trace_groups,
                    origin_func,
                    origin_var,
                    security_mapping,
                )
                # Add trace as continuation (binary_path is set for cross-binary)
                add_trace_to_group(trace_group, trace, binary_path)
                # === END: Origin condition handling ===

                # === BEGIN: Follow-up task creation ===
                # Create follow-up tasks from this trace (config fetch, caller discovery, etc.)
                df_tasks, cf_tasks = create_follow_up_tasks_from_trace(
                    trace=trace,
                    binary_path=binary_path,
                    variables=[v.model_dump() for v in task.variables]
                )
                new_dataflow_tasks.extend(df_tasks)
                config_fetch_tasks.extend(cf_tasks)

                if cf_tasks:
                    console.print(f"[dim]    → Config fetch needed for {trace.variable}[/dim]")
                if df_tasks:
                    console.print(f"[dim]    → Follow-up tasks created: {len(df_tasks)}[/dim]")
                # === END: Follow-up task creation ===

            console.print(f"[green]  ✓ {binary_path}: {len(result.traces)} traces[/green]")

            # Capture state AFTER processing and log diff
            state_after = capture_state_snapshot(
                config_fetch_tasks, new_dataflow_tasks, trace_groups
            )
            log_agent_state_diff(agent_name, state_before, state_after)

        except Exception as e:
            console.print(f"[red]  ✗ Error analyzing {binary_path}: {e}[/red]")
            # Continue with other binaries even if one fails

    console.print(f"[green]✓ Cross-binary analysis complete: {len(cross_binary_tasks)} binaries analyzed[/green]")

    # Determine next phase based on tasks created (from HEAD)
    if new_dataflow_tasks or config_fetch_tasks:
        next_phase = AnalysisPhase.FIRMWARE_EXPLORATION
    else:
        next_phase = AnalysisPhase.SYNTHESIS

    state_update = {
        "trace_groups": trace_groups,
        "pending_dataflow_tasks": new_dataflow_tasks,
        "pending_config_fetch_tasks": config_fetch_tasks,
        "current_phase": next_phase,
    }

    # Per-task state changes already logged inside the loop
    return state_update




# ============================================================================
# Node: Synthesis (Final Report Generation)
# ============================================================================

# ----------------------------------------------------------------------------
# Markdown Formatting Helper Functions
# ----------------------------------------------------------------------------

def format_status_badge(status: RuleResultStatus) -> str:
    """Format rule status with emoji and markdown bold."""
    badges = {
        RuleResultStatus.PASS: "**✅ PASS**",
        RuleResultStatus.FAIL: "**❌ FAIL**",
        RuleResultStatus.CONDITIONAL: "**⚠️ CONDITIONAL**",
        RuleResultStatus.UNDETERMINED: "**❓ UNDETERMINED**",
    }
    return badges.get(status, f"**{status.value.upper()}**")


def format_trace_resolution_badge(resolution: TraceResolvingStatus) -> str:
    """Format trace resolution status with emoji and markdown."""
    badges = {
        TraceResolvingStatus.PENDING: "**⏳ PENDING**",
        TraceResolvingStatus.RESOLVED: "**✓ RESOLVED**",
        TraceResolvingStatus.CANNOT_RESOLVE: "**⊘ CANNOT_RESOLVE**",
    }
    return badges.get(resolution, f"**{resolution.value.upper()}**")


def format_source_kind_badge(source_kind: SourceKind) -> str:
    """Format source kind with emoji badge."""
    badges = {
        SourceKind.CONSTANT: "🔢",
        SourceKind.CONFIG_FILE: "🗂️",
        SourceKind.ENVIRONMENT_VARIABLE: "🔧",
        SourceKind.COMMAND_LINE_ARG: "📝",
        SourceKind.EXTERNAL_CALL: "🔗",
        SourceKind.UNKNOWN: "❓",
    }
    emoji = badges.get(source_kind, "")
    return f"{emoji} {source_kind.value.upper()}"


def calculate_rule_statistics(rules: Dict[str, RuleResult]) -> Dict[str, int]:
    """Calculate counts for each rule status."""
    stats = {
        "total": len(rules),
        "pass": 0,
        "fail": 0,
        "conditional": 0,
        "undetermined": 0,
    }
    for rule in rules.values():
        if rule.result == RuleResultStatus.PASS:
            stats["pass"] += 1
        elif rule.result == RuleResultStatus.FAIL:
            stats["fail"] += 1
        elif rule.result == RuleResultStatus.CONDITIONAL:
            stats["conditional"] += 1
        elif rule.result == RuleResultStatus.UNDETERMINED:
            stats["undetermined"] += 1
    return stats


def format_summary_table(stats: Dict[str, int], trace_count: int, cross_binary_count: int) -> str:
    """Format statistics as Markdown table."""
    lines = [
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total Rules | {stats['total']} |",
        f"| ✅ Passed | {stats['pass']} |",
        f"| ❌ Failed | {stats['fail']} |",
        f"| ⚠️ Conditional | {stats['conditional']} |",
        f"| ❓ Undetermined | {stats['undetermined']} |",
        f"| Variables Traced | {trace_count} |",
        f"| Cross-Binary Traces | {cross_binary_count} |",
    ]
    return "\n".join(lines)


def format_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    from datetime import datetime
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def escape_markdown(text: str) -> str:
    """Escape special markdown characters in text."""
    if not text:
        return text
    # Escape pipe characters for table cells
    return text.replace("|", "\\|")


def wrap_long_text(text: str, width: int = 200) -> str:
    """Wrap very long text in code block if it exceeds width."""
    if len(text) > width:
        return f"```\n{text}\n```"
    return text


async def synthesis_node(
    state: AnalysisState,
) -> Dict[str, Any]:
    """Generate final security analysis report.

    This node:
    1. Takes all results from state (rules, trace_groups)
    2. Resolves CONDITIONAL rules using hierarchical trace groups
    3. Computes overall resolution considering main traces and continuations
    4. Generates comprehensive security report
    5. Updates state with final_report

    Args:
        state: Current analysis state with all results

    Returns:
        State update with final_report and COMPLETED phase
    """
    console.print("[cyan]📝 Generating final report[/cyan]")

    rules = state.get("rule_result", {})
    trace_groups = state.get("trace_groups", {})
    ssl_summary = state.get("ssl_summary", "")
    client_type = state.get("client_type", "Unknown")

    # Build mapping from (function, variable) to security_mapping for quick lookup
    condition_mappings: Dict[str, Dict[str, str]] = {}
    for rule in rules.values():
        for cond in rule.conditions:
            key = create_trace_key(cond.function, cond.variable)
            condition_mappings[key] = cond.security_mapping

    # Compute resolution for each trace group
    resolved_count = 0
    cannot_resolve_count = 0
    pending_count = 0

    updated_trace_groups: Dict[str, VariableTraceGroup] = {}

    for condition_key, group in trace_groups.items():
        # Deep copy the group for modification
        updated_group = group.model_copy(deep=True)

        # Get security mapping for this condition
        security_mapping = condition_mappings.get(condition_key, group.security_mapping)
        if security_mapping:
            updated_group.security_mapping = security_mapping

        # Compute resolution from main traces + continuations
        updated_group.compute_resolution(security_mapping)

        updated_trace_groups[condition_key] = updated_group

        # Count by status
        if updated_group.overall_status == TraceResolvingStatus.RESOLVED:
            resolved_count += 1
        elif updated_group.overall_status == TraceResolvingStatus.CANNOT_RESOLVE:
            cannot_resolve_count += 1
        else:
            pending_count += 1

    # Calculate statistics for summary
    stats = calculate_rule_statistics(rules)

    # Count traces from groups
    main_trace_count = sum(len(g.main_traces) for g in updated_trace_groups.values())
    continuation_trace_count = sum(
        sum(len(c.traces) for c in g.continuations)
        for g in updated_trace_groups.values()
    )

    stats["trace_count"] = main_trace_count
    stats["cross_binary_count"] = continuation_trace_count
    stats["groups_resolved"] = resolved_count
    stats["groups_cannot_resolve"] = cannot_resolve_count
    stats["groups_pending"] = pending_count

    # Script findings for display
    script_findings = state.get('script_findings', [])

    # Log resolution summary
    if resolved_count > 0:
        console.print(f"[green]✓ Trace groups resolved: {resolved_count}[/green]")
    if cannot_resolve_count > 0:
        console.print(f"[yellow]⚠ Trace groups unresolved: {cannot_resolve_count}[/yellow]")
    if pending_count > 0:
        console.print(f"[dim]  Trace groups pending: {pending_count}[/dim]")

    console.print("[green]✓ Report data prepared[/green]")

    return {
        "report_data": {
            "summary_stats": stats,
            "context": {
                "binary_path": state.get("binary_path"),
                "client_type": client_type,
                "firmware_path": state.get("firmware_path"),
                "summary": ssl_summary
            },
            "rules": rules,
            "trace_groups": updated_trace_groups,
            "scripts": script_findings
        },
        "trace_groups": updated_trace_groups,
        "current_phase": AnalysisPhase.COMPLETED,
    }
