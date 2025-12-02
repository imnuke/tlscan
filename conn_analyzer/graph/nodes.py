"""Graph nodes for LangGraph-based SSL analysis workflow v2.

This module implements all graph nodes with:
- Structured output (Pydantic models instead of text parsing)
- State as single source of truth (no context passing through agents)
- Integration with Static Analysis Engine and Agent Factory
- Clean separation of concerns
"""

import time
from typing import Dict, Any, List, Sequence, Set
from langchain_core.messages import HumanMessage

from langgraph.types import Send

from conn_analyzer.graph.state import (
    AnalysisState,
    AnalysisPhase,
    create_trace_key,
    parse_trace_key,
)
from conn_analyzer.graph.models import (
    RuleResultStatus,
    RuleResolvingStatus,
    SSLAnalysisOutput,
    DataflowAnalysisOutput,
    FirmwareSearchResult,
    VariableTrace,
    RuleResult,
    ConfigFetchTask,
    DataflowTask,
    VariableSpec,
    TaskType,
    VariableSourceType,
    FunctionParameterDetails,
    ConstantDetails,
    ConfigFileDetails,
    EnvironmentVariableDetails,
    CommandLineArgDetails,
    UnknownDetails,
)
from conn_analyzer.static_analysis.engine import StaticAnalysisEngine
from conn_analyzer.agents.factory import AgentFactory
from conn_analyzer.agents.core.execution import stream_and_log_agent
from conn_analyzer.utils.state_logging import log_agent_state

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

    # Convert rules list to dict and set correct resolving_status
    rules_dict: Dict[str, RuleResult] = {}
    for rule in result.rules:
        # Determine resolving_status based on result type and conditions
        if rule.result == RuleResultStatus.CONDITIONAL and rule.conditions:
            # Needs dataflow analysis - keep as UNRESOLVED
            resolving_status = RuleResolvingStatus.UNRESOLVED
        else:
            # Definitive result (PASS/FAIL/UNDETERMINED) - mark as RESOLVED
            resolving_status = RuleResolvingStatus.RESOLVED

        # Create updated rule with correct status
        updated_rule = RuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            result=rule.result,
            resolving_status=resolving_status,
            evidence=rule.evidence,
            conditions=rule.conditions
        )
        rules_dict[rule.rule_id] = updated_rule

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
    composite_key: str,
    variables: List[VariableSpec]
) -> tuple[List[DataflowTask], List[ConfigFetchTask]]:
    """Extract config/script/cross-binary tasks from a single trace.

    Args:
        trace: The variable trace to process
        composite_key: Composite key (e.g., "binary:function:variable")
        variables: Original variables list (VariableSpec objects) for security_mapping lookup

    Returns:
        (new_dataflow_tasks, config_fetch_tasks)
    """
    new_dataflow_tasks = []
    config_fetch_tasks = []

    # Check if this trace needs config fetching
    if trace.source == VariableSourceType.CONFIG_FILE:
        # Extract config path (handle both Pydantic model and dict)
        config_details = None
        if isinstance(trace.source_details, ConfigFileDetails):
            config_details = trace.source_details
        elif isinstance(trace.source_details, dict):
            try:
                config_details = ConfigFileDetails(**trace.source_details)
            except Exception:
                pass

        if config_details:
            config_reference = config_details.config_file or "unknown_config_file"
            if config_details.config_key:
                config_reference = f"{config_reference} (key: {config_details.config_key})"

            config_task = ConfigFetchTask(
                variable=trace.variable,
                function=trace.function,
                config_reference=config_reference,
                trace_details=trace.trace_path
            )
            config_fetch_tasks.append(config_task)

    # Check if this trace comes from command-line arguments
    elif trace.source == VariableSourceType.COMMAND_LINE_ARG:
        # Extract CLI arg details (handle both Pydantic model and dict)
        cli_details = None
        if isinstance(trace.source_details, CommandLineArgDetails):
            cli_details = trace.source_details
        elif isinstance(trace.source_details, dict):
            try:
                cli_details = CommandLineArgDetails(**trace.source_details)
            except Exception:
                pass

        if cli_details:
            # Get binary path from composite_key: "binary_path:function:variable"
            key_parts = composite_key.split(":")
            if len(key_parts) >= 3:
                binary_path = ":".join(key_parts[:-2])
            else:
                binary_path = None

            arg_name = cli_details.arg_name or "CLI argument"

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
    elif trace.source == VariableSourceType.FUNCTION_PARAMETER_FROM_EXTERNAL_CALL:
        # Create needs_caller_discovery task
        param_details = None
        if isinstance(trace.source_details, FunctionParameterDetails):
            param_details = trace.source_details
        elif isinstance(trace.source_details, dict):
            try:
                param_details = FunctionParameterDetails(**trace.source_details)
            except Exception:
                pass

        if param_details:
            function_name = param_details.external_function
            parameter_name = param_details.parameter_name

            # Find the original variable's security_mapping
            original_var = next((v for v in variables if v["variable"] == trace.variable and v["function"] == trace.function), None)
            security_mapping = original_var.get("security_mapping", {}) if original_var else {}

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
                context=f"Find callers of {function_name} and trace parameter {parameter_name}"
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
        state_update = {"current_phase": AnalysisPhase.SYNTHESIS}
        # Log state after (no agent execution in this case)
        log_agent_state("Dataflow Agent", state, changes=state_update)
        return state_update

    console.print(f"[cyan]🔍 Running dataflow analysis: {len(pending_tasks)} tasks[/cyan]")

    # Get existing traces (deep copy to avoid modifying state directly)
    all_traces: Dict[str, List[VariableTrace]] = {}
    for key, value in state.get("variable_traces", {}).items():
        all_traces[key] = value.copy() if isinstance(value, list) else [value]

    new_dataflow_tasks: List[DataflowTask] = []
    config_fetch_tasks: List[ConfigFetchTask] = []

    total_tasks = len(pending_tasks)

    for task_idx, task in enumerate(pending_tasks):
        console.print(f"[dim]  Processing {task.type.value} task: {task.target} ({len(task.variables)} variables)[/dim]")

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
            # TODO: Not only for binary, we can unify the composite key for binary/script/config.
            # we can use "{file_path}:{}"
            # ??

            # Build composite key based on whether this is cross-binary analysis
            binary_path = task.binary_path  # Use attribute access for Pydantic model
            if binary_path:
                # Cross-binary trace: "{binary_path}:{function}:{variable}"
                composite_key = create_trace_key(trace.function, trace.variable, binary_path)
            else:
                # Main binary trace: "function:variable"
                composite_key = create_trace_key(trace.function, trace.variable)

            # Store traces as list to support multiple sources per variable
            if composite_key not in all_traces:
                all_traces[composite_key] = []
            all_traces[composite_key].append(trace)
            console.print(f"[dim]    ✓ {trace.variable}: {trace.source.value}[/dim]")

            # Check if this trace needs config fetching
            if trace.source == VariableSourceType.CONFIG_FILE:
                # Extract config path from typed source_details
                config_reference = None
                if isinstance(trace.source_details, ConfigFileDetails):
                    config_reference = trace.source_details.config_path
                    if trace.source_details.config_key:
                        config_reference = f"{config_reference} (key: {trace.source_details.config_key})"

                config_task = ConfigFetchTask(
                    variable=trace.variable,
                    function=trace.function,
                    config_reference=config_reference,
                    trace_details=trace.trace_path
                )
                config_fetch_tasks.append(config_task)
                console.print(f"[dim]    → Config fetch needed for {trace.variable} from {config_reference}[/dim]")

            # Check if this trace requires cross-binary analysis
            elif trace.source == VariableSourceType.FUNCTION_PARAMETER_FROM_EXTERNAL_CALL:
                # Extract function name from typed source_details
                if isinstance(trace.source_details, FunctionParameterDetails):
                    function_name = trace.source_details.external_function
                    parameter_name = trace.source_details.parameter_name

                    # Find the original variable's security_mapping to preserve it
                    original_var = next((v for v in task.variables if v.variable == trace.variable and v.function == trace.function), None)
                    security_mapping = original_var.security_mapping if (original_var and original_var.security_mapping) else {}

                    # Create NEW variables for the external function's parameter
                    # (NOT the original function's variable - that would confuse the next agent)
                    new_variables = [VariableSpec(
                        variable=parameter_name,
                        function=function_name,
                        function_address=None,  # External function address unknown
                        security_mapping=security_mapping,  # Preserve security mapping
                    )]

                    # Create a "needs_caller_discovery" task
                    caller_discovery_task = DataflowTask(
                        type=TaskType.NEEDS_CALLER_DISCOVERY,
                        target=function_name,
                        variables=new_variables,  # New variables for external function parameter
                        binary_path=None,
                        context=f"Find callers of {function_name} and trace parameter {parameter_name}"
                    )
                    new_dataflow_tasks.append(caller_discovery_task)
                    console.print(f"[dim]    → Cross-binary discovery needed for function '{function_name}', parameter '{parameter_name}'[/dim]")
                else:
                    console.print(f"[yellow]⚠ Invalid source_details type for FUNCTION_PARAMETER_FROM_EXTERNAL_CALL: {type(trace.source_details)}[/yellow]")

            # Check if this trace comes from command-line arguments
            elif trace.source == VariableSourceType.COMMAND_LINE_ARG:
                # Extract CLI arg details
                if isinstance(trace.source_details, CommandLineArgDetails):
                    arg_name = trace.source_details.arg_name or "CLI argument"

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
                        target=binary_path,  # The binary being invoked
                        variables=cli_variables,
                        binary_path=None,
                        context=f"Find scripts/binaries that invoke this binary and extract CLI argument: {arg_name}"
                    )
                    new_dataflow_tasks.append(script_discovery_task)
                    console.print(f"[dim]    → Script discovery needed for CLI argument '{arg_name}'[/dim]")
                else:
                    console.print(f"[yellow]⚠ Invalid source_details type for COMMAND_LINE_ARG: {type(trace.source_details)}[/yellow]")

        # Log state changes for this individual task
        traces_after = set(all_traces.keys())
        new_traces = {k: all_traces[k] for k in traces_after - traces_before}
        new_config_tasks_count = len(config_fetch_tasks) - config_tasks_before
        new_dataflow_tasks_count = len(new_dataflow_tasks) - dataflow_tasks_before

        # Build state update for this task only
        task_state_update = {}
        if new_traces:
            task_state_update["variable_traces"] = new_traces
        if new_dataflow_tasks_count > 0:
            task_state_update["pending_dataflow_tasks"] = new_dataflow_tasks[dataflow_tasks_before:]
        if new_config_tasks_count > 0:
            task_state_update["pending_config_fetch_tasks"] = config_fetch_tasks[config_tasks_before:]

        # Log individual task changes
        if task_state_update:
            log_agent_state(agent_name_with_progress, state, changes=task_state_update)

    console.print(f"[green]✓ Dataflow complete: {len(all_traces)} traces[/green]")

    # Determine next phase
    if new_dataflow_tasks or config_fetch_tasks:
        next_phase = AnalysisPhase.FIRMWARE_EXPLORATION
    else:
        next_phase = AnalysisPhase.SYNTHESIS

    state_update = {
        "variable_traces": all_traces,
        "pending_dataflow_tasks": new_dataflow_tasks,  # New tasks for caller discovery or cleared
        "pending_config_fetch_tasks": config_fetch_tasks,
        "current_phase": next_phase,
    }

    # Note: Individual task state changes are logged inside the loop
    return state_update


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
    caller_discovery_tasks = [t for t in pending_tasks if t.type == TaskType.NEEDS_CALLER_DISCOVERY]

    if caller_discovery_tasks:
        # Find caller binaries for cross-binary analysis
        # Extract all unique function names from all discovery tasks (deduplicate)
        function_names = list(dict.fromkeys(task.target for task in caller_discovery_tasks))  # Use attribute access

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
        remaining_tasks = [t for t in pending_tasks if t.get("type") != "needs_caller_discovery"]

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
                all_function_names = {task.target for task in caller_discovery_tasks}  # Use attribute access
                for binary_path in result.executables:
                    binary_to_functions[binary_path] = all_function_names

            # Create function_to_variables mapping for efficient lookup
            function_to_variables: Dict[str, List[VariableSpec]] = {}
            for task in caller_discovery_tasks:
                function_name = task.target  # Use attribute access for Pydantic model
                function_to_variables[function_name] = task.variables

            # Create cross-binary tasks with function-specific variables
            for binary_path in result.executables:
                # Get functions this binary calls
                functions_called = binary_to_functions.get(binary_path, set())

                if not functions_called:
                    console.print(f"[yellow]⚠ Binary {binary_path} has no function mapping - skipping[/yellow]")
                    continue

                # Aggregate variables ONLY from functions this binary calls
                aggregated_variables: List[VariableSpec] = []
                for function_name in functions_called:
                    if function_name in function_to_variables:
                        aggregated_variables.extend(function_to_variables[function_name])

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
                )
                remaining_tasks.append(binary_task)

            state_update = {
                "pending_dataflow_tasks": remaining_tasks,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.CROSS_BINARY_ANALYSIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update
        else:
            console.print(f"[yellow]⚠ No caller binaries found for function(s): {', '.join(function_names)}[/yellow]")
            state_update = {
                "pending_dataflow_tasks": remaining_tasks,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update

    # Find tasks that need script discovery (for CLI arguments)
    script_discovery_tasks = [t for t in pending_tasks if t.type == TaskType.NEEDS_SCRIPT_DISCOVERY]

    if script_discovery_tasks:
        # Find startup scripts/binaries that invoke the target binary
        task = script_discovery_tasks[0]  # Process first task
        binary_target = task.target  # Use attribute access for Pydantic model
        context = task.context or ""  # Use attribute access

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
        remaining_tasks = [t for t in pending_tasks if t.get("type") != "needs_script_discovery" or t != task]

        if result.found and result.executables:
            console.print(f"[green]✓ Found {len(result.executables)} startup scripts/binaries[/green]")
            # For now, just report the findings (future: could parse scripts to extract CLI args)
            # Store script findings for synthesis to report
            state_update = {
                "pending_dataflow_tasks": remaining_tasks,
                "script_findings": result.executables,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update
        else:
            console.print(f"[yellow]⚠ No startup scripts found for {binary_target}[/yellow]")
            state_update = {
                "pending_dataflow_tasks": remaining_tasks,
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update

    elif config_fetch_tasks:
        # Fetch configuration values from firmware
        console.print(f"[dim]  Fetching config values: {len(config_fetch_tasks)} tasks[/dim]")

        # Build request with all config variables to fetch
        config_requests = []
        for task in config_fetch_tasks:
            config_ref = task.config_reference or "configuration file"
            config_requests.append(f"  - {config_ref}")

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
            all_traces: Dict[str, List[VariableTrace]] = {}
            for key, value in state.get("variable_traces", {}).items():
                all_traces[key] = value.copy() if isinstance(value, list) else [value]

            for task in config_fetch_tasks:
                composite_key = f"{task.function}:{task.variable}"
                if composite_key in all_traces:
                    # Find the config trace in the list and update it
                    traces_list = all_traces[composite_key]
                    for i, original_trace in enumerate(traces_list):
                        if original_trace.source == VariableSourceType.CONFIG_FILE and task.variable in result.config_values:
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
                            traces_list[i] = updated_trace
                            console.print(f"[dim]    ✓ Updated {task.variable} = {updated_trace.value}[/dim]")

            state_update = {
                "variable_traces": all_traces,
                "pending_config_fetch_tasks": [],  # Clear completed tasks
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update
        else:
            console.print(f"[yellow]⚠ No config values found[/yellow]")
            state_update = {
                "pending_config_fetch_tasks": [],
                "firmware_details": result.details,
                "current_phase": AnalysisPhase.SYNTHESIS,
            }
            # Log state after agent execution with changes
            log_agent_state("Firmware Agent", state, changes=state_update)
            return state_update

    # If no tasks, proceed to synthesis
    state_update = {"current_phase": AnalysisPhase.SYNTHESIS}
    # Log state after (no agent execution in this case)
    log_agent_state("Firmware Agent", state, changes=state_update)
    return state_update


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
        state_update = {
            "pending_dataflow_tasks": [],
            "current_phase": AnalysisPhase.SYNTHESIS,
        }
        # Log state after (no agent execution in this case)
        log_agent_state("Dataflow Agent", state, changes=state_update)
        return state_update

    console.print(f"[cyan]🔄 Analyzing {len(cross_binary_tasks)} caller binaries sequentially[/cyan]")

    # Get existing traces (deep copy lists)
    all_traces: Dict[str, List[VariableTrace]] = {}
    for key, value in state.get("variable_traces", {}).items():
        all_traces[key] = value.copy() if isinstance(value, list) else [value]

    for task in cross_binary_tasks:
        binary_path = task.binary_path
        context = task.context or ""

        console.print(f"[dim]  Analyzing caller: {binary_path}[/dim]")
        if context:
            console.print(f"[dim]  Context: {context}[/dim]")

        try:
            # Execute dataflow analysis using shared helper
            result: DataflowAnalysisOutput = await execute_single_dataflow_task(
                task=task,
                static_engine=static_engine,
                agent_factory=agent_factory,
                firmware_tools=[],  # Cross-binary tasks are always BINARY type, no firmware tools needed
            )

            # Store traces using binary-qualified keys: "{binary_path}:{function}:{variable}"
            for trace in result.traces:
                composite_key = create_trace_key(trace.function, trace.variable, binary_path)
                if composite_key not in all_traces:
                    all_traces[composite_key] = []
                all_traces[composite_key].append(trace)

            console.print(f"[green]  ✓ {binary_path}: {len(result.traces)} traces[/green]")

        except Exception as e:
            console.print(f"[red]  ✗ Error analyzing {binary_path}: {e}[/red]")
            # Continue with other binaries even if one fails

    console.print(f"[green]✓ Cross-binary analysis complete: {len(cross_binary_tasks)} binaries analyzed[/green]")

    state_update = {
        "variable_traces": all_traces,
        "pending_dataflow_tasks": [],  # Clear all tasks
        "current_phase": AnalysisPhase.SYNTHESIS,
    }

    # Log state after all agent executions with changes
    log_agent_state("Cross-binary Dataflow", state, changes=state_update)
    return state_update




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
    # Note: Each key now maps to a LIST of traces (multi-source support)
    main_traces = {}
    cross_binary_by_path = {}

    for composite_key, traces_value in variable_traces.items():
        # Ensure traces_value is a list (backwards compatibility)
        traces_list = traces_value if isinstance(traces_value, list) else [traces_value]

        parts = composite_key.split(":")
        if len(parts) == 2:
            # Main binary trace
            main_traces[composite_key] = traces_list
        elif len(parts) >= 3:
            # Cross-binary trace: first part is binary path
            binary_path = parts[0]
            trace_key = ":".join(parts[1:])  # "function:variable"
            if binary_path not in cross_binary_by_path:
                cross_binary_by_path[binary_path] = {}
            cross_binary_by_path[binary_path][trace_key] = traces_list

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
                    traces_list = main_traces[composite_key]

                    # Handle single vs multiple sources
                    if len(traces_list) == 1:
                        # Single source - existing format
                        trace = traces_list[0]
                        report_lines.append(f"    Source: {trace.source.value}")

                        # Show detailed source information from typed details
                        if isinstance(trace.source_details, ConstantDetails):
                            if trace.source_details.constant_name:
                                report_lines.append(f"    Details: Constant {trace.source_details.constant_name} = {trace.source_details.constant_value}")
                        elif isinstance(trace.source_details, ConfigFileDetails):
                            details_str = f"    Details: Config file {trace.source_details.config_path}"
                            if trace.source_details.config_key:
                                details_str += f" (key: {trace.source_details.config_key})"
                            report_lines.append(details_str)
                        elif isinstance(trace.source_details, FunctionParameterDetails):
                            report_lines.append(f"    Details: External call to {trace.source_details.external_function} (parameter: {trace.source_details.parameter_name})")
                        elif isinstance(trace.source_details, EnvironmentVariableDetails):
                            report_lines.append(f"    Details: Environment variable {trace.source_details.env_var_name}")
                        elif isinstance(trace.source_details, CommandLineArgDetails):
                            details_str = "    Details: Command-line argument"
                            if trace.source_details.arg_name:
                                details_str += f" {trace.source_details.arg_name}"
                            report_lines.append(details_str)

                        if trace.value:
                            report_lines.append(f"    Value: {trace.value}")
                            # Apply security mapping
                            if trace.value in cond.security_mapping:
                                outcome = cond.security_mapping[trace.value]
                                report_lines.append(f"    Outcome: {outcome}")
                        report_lines.append(f"    Trace: {trace.trace_path}")

                    else:
                        # Multiple sources - show all
                        report_lines.append(f"    ⚠️  Variable computed from {len(traces_list)} sources:")
                        for i, trace in enumerate(traces_list, 1):
                            report_lines.append(f"      Source {i}: {trace.source.value}")

                            # Show details for each source
                            if isinstance(trace.source_details, ConfigFileDetails):
                                details_str = f"        Config: {trace.source_details.config_path}"
                                if trace.source_details.config_key:
                                    details_str += f" (key: {trace.source_details.config_key})"
                                report_lines.append(details_str)
                            elif isinstance(trace.source_details, CommandLineArgDetails):
                                details_str = "        CLI Arg:"
                                if trace.source_details.arg_name:
                                    details_str += f" {trace.source_details.arg_name}"
                                report_lines.append(details_str)
                            elif isinstance(trace.source_details, ConstantDetails):
                                report_lines.append(f"        Constant: {trace.source_details.constant_value}")

                            if trace.value:
                                report_lines.append(f"        Value: {trace.value}")
                                # Apply security mapping
                                if trace.value in cond.security_mapping:
                                    outcome = cond.security_mapping[trace.value]
                                    report_lines.append(f"        → Outcome: {outcome}")

                            report_lines.append(f"        Trace: {trace.trace_path}")
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
            for trace_key, traces_list in traces.items():
                # trace_key is "function:variable", traces_list is List[VariableTrace]
                for trace in traces_list:
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
