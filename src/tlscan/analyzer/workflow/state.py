"""State schema for LangGraph-based SSL analysis workflow.

This module defines the complete state structure that flows through
the analysis graph. State is the single source of truth for all
intermediate results.
"""

from enum import Enum
from typing import TypedDict, Optional, Dict, List, Set, Tuple, Any
from tlscan.analyzer.utils.binary import FileType
from tlscan.analyzer.workflow.models import (
    RuleResult,
    VariableTrace,
    RuleTraceLink,
    ConfigFetchTask,
    DataflowTask,
    TraceResolvingStatus,
    LibraryVersions,
)


# ============================================================================
# Enums for Workflow Control
# ============================================================================

class AnalysisPhase(str, Enum):
    """Current phase of the analysis workflow."""

    INITIAL_SSL_ANALYSIS = "initial_ssl_analysis"
    DATAFLOW_ANALYSIS = "dataflow_analysis"
    CROSS_BINARY_ANALYSIS = "cross_binary_analysis"
    FIRMWARE_EXPLORATION = "firmware_exploration"
    SYNTHESIS = "synthesis"
    COMPLETED = "completed"


# ============================================================================
# Composite Key Helpers
# ============================================================================

def create_trace_key(function: str, variable: str, binary_path: Optional[str] = None) -> str:
    """
    Create composite key for variable traces.

    Args:
        function: Function name where variable is used
        variable: Variable name to trace
        binary_path: Optional binary path for cross-binary analysis

    Returns:
        Composite key in format:
        - Main binary: "function:variable"
        - Cross-binary: "binary_path:function:variable"

    Examples:
        >>> create_trace_key("SSL_CTX_set_verify", "mode")
        "SSL_CTX_set_verify:mode"
        >>> create_trace_key("init_ssl", "mode", "/usr/bin/app")
        "/usr/bin/app:init_ssl:mode"
    """
    if binary_path:
        return f"{binary_path}:{function}:{variable}"
    return f"{function}:{variable}"


def parse_condition_key(key: str) -> Tuple[str, str]:
    """
    Parse a simple condition key into (function, variable).

    Args:
        key: Condition key in format "function:variable"

    Returns:
        Tuple of (function, variable)

    Examples:
        >>> parse_condition_key("SSL_CTX_set_verify:mode")
        ("SSL_CTX_set_verify", "mode")
        >>> parse_condition_key("upscli_sslinit:a2")
        ("upscli_sslinit", "a2")

    Raises:
        ValueError: If key is not in expected format
    """
    parts = key.split(":", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    raise ValueError(f"Invalid condition key format: {key}")


# ============================================================================
# Trace Graph Helpers
# ============================================================================

def compute_trace_content_key(trace: VariableTrace) -> str:
    """
    Compute a content-based key for deduplication.

    Traces with the same content key are considered duplicates.
    The key includes a hash of trace_path to distinguish traces
    with different analysis paths.

    Args:
        trace: VariableTrace to compute key for

    Returns:
        Content key in format "trace_type:source_path:function:variable:path_hash"
    """
    import hashlib
    import json

    source = trace.source_path or "main"

    # Hash the trace_path for deduplication
    path_hash = "empty"
    if trace.trace_path:
        # Serialize trace_path to JSON and hash it
        path_data = []
        for step in trace.trace_path:
            if hasattr(step, 'model_dump'):
                path_data.append(step.model_dump(exclude_none=True))
            else:
                path_data.append(str(step))
        path_json = json.dumps(path_data, sort_keys=True)
        path_hash = hashlib.md5(path_json.encode()).hexdigest()[:8]

    return f"{trace.trace_type.value}:{source}:{trace.function}:{trace.variable}:{path_hash}"


def add_trace_to_graph(
    traces: Dict[str, VariableTrace],
    trace: VariableTrace,
    parent_trace_id: Optional[str] = None,
) -> str:
    """
    Add a trace to the trace graph with deduplication.

    If a trace with the same content key already exists, returns the existing
    trace ID. Otherwise, adds the new trace and updates parent-child links.

    Args:
        traces: Dict of all traces (modified in place)
        trace: New trace to add
        parent_trace_id: Optional parent trace ID for linking

    Returns:
        trace_id of the added or existing trace
    """
    import uuid

    # Compute content key for deduplication
    new_key = compute_trace_content_key(trace)

    # Check for existing trace with same content
    for existing_id, existing in traces.items():
        existing_key = compute_trace_content_key(existing)
        if existing_key == new_key:
            # Trace already exists - update parent link if needed
            if parent_trace_id and parent_trace_id in traces:
                if existing_id not in traces[parent_trace_id].child_trace_ids:
                    traces[parent_trace_id].child_trace_ids.append(existing_id)
            return existing_id

    # New trace - generate ID if needed
    if not trace.trace_id:
        trace.trace_id = str(uuid.uuid4())

    # Set parent link
    if parent_trace_id:
        trace.parent_trace_id = parent_trace_id
        # Update parent's children
        if parent_trace_id in traces:
            if trace.trace_id not in traces[parent_trace_id].child_trace_ids:
                traces[parent_trace_id].child_trace_ids.append(trace.trace_id)

    # Add to graph
    traces[trace.trace_id] = trace
    return trace.trace_id


def collect_trace_tree(
    traces: Dict[str, VariableTrace],
    trace_id: str,
    collected: Optional[List[VariableTrace]] = None,
) -> List[VariableTrace]:
    """
    Recursively collect all traces in a subtree.

    Args:
        traces: Dict of all traces
        trace_id: Root trace ID to start from
        collected: List to accumulate traces (for recursion)

    Returns:
        List of all traces in the subtree (root first, then children)
    """
    if collected is None:
        collected = []

    trace = traces.get(trace_id)
    if not trace:
        return collected

    collected.append(trace)

    for child_id in trace.child_trace_ids:
        collect_trace_tree(traces, child_id, collected)

    return collected


def resolve_trace_tree(
    traces: Dict[str, VariableTrace],
    trace_id: str,
    security_mapping: Optional[Dict[str, str]],
) -> List[str]:
    """
    Recursively resolve a trace tree, returning security outcomes.

    Traverses the trace graph from the given trace, collecting outcomes
    for any traces that have resolved values.

    Args:
        traces: Dict of all traces
        trace_id: Root trace ID to start from
        security_mapping: Mapping of values to outcomes (e.g., {'0': 'UNSATISFIED', '1': 'SATISFIED'})

    Returns:
        List of outcome strings (e.g., ["cross_binary:/usr/bin/upsc: SATISFIED"])
    """
    trace = traces.get(trace_id)
    if not trace:
        return []

    outcomes = []

    # A trace whose forward replay failed twice was never committed, so its
    # claimed value carries no evidence. Children are separately verified
    # traces, so the subtree is still traversed.
    if trace.verification_failed:
        for child_id in trace.child_trace_ids:
            outcomes.extend(resolve_trace_tree(traces, child_id, security_mapping))
        return outcomes

    # Check if this trace has a resolved value
    if trace.value and security_mapping:
        if trace.value in security_mapping:
            source_desc = f"{trace.trace_type.value}:{trace.source_path or 'main'}"
            outcome = security_mapping[trace.value]
            outcomes.append(f"{source_desc}: {outcome}")

    # Recurse to children
    for child_id in trace.child_trace_ids:
        child_outcomes = resolve_trace_tree(traces, child_id, security_mapping)
        outcomes.extend(child_outcomes)

    return outcomes


def update_trace_statuses(
    traces: Dict[str, VariableTrace],
    trace_id: str,
    security_mapping: Optional[Dict[str, str]],
) -> None:
    """
    Recursively update trace resolving_status fields based on resolution.

    Traverses the trace graph and sets:
    - RESOLVED: If trace has value that maps to an outcome
    - CANNOT_RESOLVE: If trace is a leaf node with no resolved value
    - PENDING: For intermediate traces with unresolved children

    Also sets the outcome field for resolved traces.

    Args:
        traces: Dict of all traces (modified in place)
        trace_id: Root trace ID to start from
        security_mapping: Mapping of values to outcomes
    """
    trace = traces.get(trace_id)
    if not trace:
        return

    # A trace whose forward replay failed twice is Unresolved and stays that
    # way: neither its own claimed value nor a resolved child may promote it.
    # Children are separately verified traces, so recursion continues.
    if trace.verification_failed:
        trace.resolving_status = TraceResolvingStatus.CANNOT_RESOLVE
        if not trace.resolution_reason:
            trace.resolution_reason = "Trace verification failed"
        for child_id in trace.child_trace_ids:
            update_trace_statuses(traces, child_id, security_mapping)
        return

    # Check if this trace has a resolved value
    is_resolved = False
    if trace.value and security_mapping:
        if trace.value in security_mapping:
            is_resolved = True
            trace.resolving_status = TraceResolvingStatus.RESOLVED
            trace.outcome = security_mapping[trace.value]

    # Recurse to children first (so we can check their status)
    for child_id in trace.child_trace_ids:
        update_trace_statuses(traces, child_id, security_mapping)

    # If not resolved via value, determine status based on tree structure
    if not is_resolved:
        if trace.child_trace_ids:
            # Has children - check if any child resolved
            any_child_resolved = any(
                traces.get(cid) and traces[cid].resolving_status == TraceResolvingStatus.RESOLVED
                for cid in trace.child_trace_ids
            )
            if any_child_resolved:
                trace.resolving_status = TraceResolvingStatus.RESOLVED
            # else: remains PENDING (intermediate with no resolved children)
        else:
            # Leaf node with no value - cannot resolve
            trace.resolving_status = TraceResolvingStatus.CANNOT_RESOLVE
            trace.resolution_reason = "Leaf trace with no resolved value"


# ============================================================================
# Statistics Schema
# ============================================================================

class AgentStatistics(TypedDict, total=False):
    """Statistics for a single agent type."""

    total_tokens: int
    """Total tokens consumed (thinking + tool results)."""

    thinking_tokens: int
    """Tokens in AI thinking/content messages."""

    tool_result_tokens: int
    """Tokens in tool result messages."""

    tool_call_count: int
    """Number of tool calls made."""

    total_time_seconds: float
    """Total execution time in seconds."""

    invocation_count: int
    """How many times this agent was invoked."""

    real_input_tokens: int
    """Real prompt tokens billed by the provider (from usage_metadata)."""

    real_output_tokens: int
    """Real completion tokens billed by the provider."""

    real_total_tokens: int
    """Real total tokens billed by the provider (input + output)."""

    cache_hit_tokens: int
    """Prompt tokens served from the provider's context cache."""


class AnalysisStatistics(TypedDict, total=False):
    """Comprehensive analysis statistics."""

    # Per-agent type statistics
    ssl_agent: AgentStatistics
    """Statistics for SSL analysis agent."""

    dataflow_agent: AgentStatistics
    """Statistics for dataflow analysis agent."""

    firmware_agent: AgentStatistics
    """Statistics for firmware exploration agent."""

    verification_agent: AgentStatistics
    """Statistics for verification agent (only populated when --verify is used)."""

    trace_verification_agent: AgentStatistics
    """Statistics for trace verification agent (only populated when --verify is used)."""

    # Dependency counts
    config_dependency_count: int
    """Number of config file dependencies discovered."""

    script_dependency_count: int
    """Number of script dependencies discovered."""

    cross_binary_dependency_count: int
    """Number of cross-binary dependencies discovered."""

    # Overall totals (computed from per-agent stats)
    total_tokens: int
    """Total tokens consumed across all agents (local estimate)."""

    total_time_seconds: float
    """Total execution time across all agents."""

    total_tool_calls: int
    """Total tool calls across all agents."""

    real_input_tokens: int
    """Real prompt tokens billed across all agents (from usage_metadata)."""

    real_output_tokens: int
    """Real completion tokens billed across all agents."""

    real_total_tokens: int
    """Real total tokens billed across all agents (input + output)."""

    cache_hit_tokens: int
    """Prompt tokens served from the provider's context cache across all agents."""


def create_empty_agent_statistics() -> AgentStatistics:
    """Create an empty AgentStatistics dict with all fields initialized to zero."""
    return AgentStatistics(
        total_tokens=0,
        thinking_tokens=0,
        tool_result_tokens=0,
        tool_call_count=0,
        total_time_seconds=0.0,
        invocation_count=0,
        real_input_tokens=0,
        real_output_tokens=0,
        real_total_tokens=0,
        cache_hit_tokens=0,
    )


def create_empty_statistics() -> AnalysisStatistics:
    """Create an empty AnalysisStatistics dict with all fields initialized."""
    return AnalysisStatistics(
        ssl_agent=create_empty_agent_statistics(),
        dataflow_agent=create_empty_agent_statistics(),
        firmware_agent=create_empty_agent_statistics(),
        verification_agent=create_empty_agent_statistics(),
        trace_verification_agent=create_empty_agent_statistics(),
        config_dependency_count=0,
        script_dependency_count=0,
        cross_binary_dependency_count=0,
        total_tokens=0,
        total_time_seconds=0.0,
        total_tool_calls=0,
        real_input_tokens=0,
        real_output_tokens=0,
        real_total_tokens=0,
        cache_hit_tokens=0,
    )


# ============================================================================
# Main State Schema
# ============================================================================

class AnalysisState(TypedDict, total=False):
    """
    Complete state for SSL analysis workflow.

    This state flows through all nodes in the graph. Each node reads from
    state and returns updates to merge back into state.

    Using TypedDict with total=False allows partial updates - nodes only
    need to return the fields they want to update.
    """

    # ========================================================================
    # Context & Configuration
    # ========================================================================

    # NOTE: is this field correctly used?
    binary_path: str
    """Path to the current binary/script being analyzed."""

    main_binary_path: str
    """Path to the original main binary/script (preserved during cross-binary analysis)."""

    security_rules: str
    """Security rules content (from security_rules/*.md files)."""

    file_type: FileType
    """Detected file type (elf_binary, shell_script, php_script, etc.)."""

    library_name: str
    """Name of the library/command being analyzed (from -r argument, e.g., 'curl', 'libcurl', 'openssl')."""

    no_rules: bool
    """Whether running in ablation mode without security rules."""

    enable_verification: bool
    """Whether to run verification agent after SSL analysis (default: False)."""

    enable_trace_verification: bool
    """Whether to run the trace verification agent on each dataflow trace.

    Gated by enable_verification: both stages share the verify-then-commit gate,
    so this is only consulted when enable_verification is True.
    """

    # ========================================================================
    # Pre-Analysis Context
    # ========================================================================

    call_graph_context: str
    """Pre-computed call graph text for SSL agent."""

    # ========================================================================
    # Workflow Control
    # ========================================================================

    current_phase: AnalysisPhase
    """Current phase of the analysis workflow."""

    _next_node: str
    """Used by checkpoint router to determine next node when resuming from checkpoint."""

    # ========================================================================
    # SSL Analysis Results
    # ========================================================================

    rule_result: Dict[str, RuleResult]
    """
    Security rules analysis results.

    Key: rule_id (e.g., "rule_certificate_verification")
    Value: RuleResult Pydantic model with status, evidence, conditions

    Example:
    {
        "rule_certificate_verification": RuleResult(
            rule_id="rule_certificate_verification",
            rule_name="Certificate Verification Enabled",
            result=RuleResultStatus.CONDITIONAL,
            evidence="SSL_CTX_set_verify() found at 0x401234",
            conditions=[
                RuleCondition(
                    variable="mode",
                    function="SSL_CTX_set_verify",
                    function_address="0x401234",
                    security_mapping={"0": "UNSATISFIED", "1": "SATISFIED"}
                )
            ]
        )
    }
    """

    ssl_summary: str
    """Human-readable summary from SSL analysis (for display in final report)."""

    client_type: Optional[str]
    """Type of SSL/TLS client detected (e.g., 'OpenSSL', 'libcurl')."""

    applicable: bool
    """Whether SSL/TLS security analysis is applicable to this binary."""

    # ========================================================================
    # Dataflow Analysis
    # ========================================================================

    pending_dataflow_tasks: List[DataflowTask]
    """
    Queue of dataflow analysis tasks to execute.

    Populated by SSL analysis node when it finds conditional rules.
    Consumed by dataflow analysis node.
    """

    # ========================================================================
    # Unified Trace Graph
    # ========================================================================

    traces: Dict[str, VariableTrace]
    """
    All traces in the unified trace graph, keyed by trace_id.

    This is the single source of truth for all trace data in the new architecture.
    Traces link to each other via parent_trace_id and child_trace_ids, forming
    a directed graph from rule conditions to resolved values.

    Key: trace_id (UUID string)
    Value: VariableTrace with trace_type, source_path, and graph links

    Example:
    {
        "trace-001": VariableTrace(
            trace_id="trace-001",
            trace_type=TraceType.MAIN_BINARY,
            source_path="/lib/libupsclient.so",
            function="upscli_sslinit", variable="a2",
            parent_trace_id=None,
            child_trace_ids=["trace-002"]
        ),
        "trace-002": VariableTrace(
            trace_id="trace-002",
            trace_type=TraceType.CROSS_BINARY,
            source_path="/usr/bin/upsc",
            function="main", variable="...",
            parent_trace_id="trace-001",
            value="1"
        )
    }
    """

    rule_trace_links: Dict[str, RuleTraceLink]
    """
    Mapping from rule conditions to their root traces in the trace graph.

    Key: "function:variable" (condition key)
    Value: RuleTraceLink with root_trace_ids and resolution info

    Example:
    {
        "upscli_sslinit:a2": RuleTraceLink(
            condition_key="upscli_sslinit:a2",
            root_trace_ids=["trace-001"],
            security_mapping={"0": "UNSATISFIED", "1": "SATISFIED"}
        )
    }
    """

    # ========================================================================
    # Config Fetch Tasks
    # ========================================================================

    pending_config_fetch_tasks: List[ConfigFetchTask]
    """
    Queue of config fetch tasks.

    Populated when dataflow finds a variable comes from CONFIG_FILE source.
    These tasks trigger firmware exploration to extract config values.
    """

    # ========================================================================
    # Firmware Context
    # ========================================================================

    firmware_path: Optional[str]
    """Root path of firmware filesystem for cross-binary and config analysis."""

    firmware_details: Optional[str]
    """Detailed findings from firmware exploration (for logging/display)."""

    script_findings: Optional[List[str]]
    """Startup scripts that invoke the analyzed binary (for CLI argument analysis)."""

    # ========================================================================
    # Library Version Information
    # ========================================================================

    library_versions: Optional[LibraryVersions]
    """
    Detected library version information.

    Contains versions detected from:
    - The binary being analyzed (via VERNEED sections, API inference)
    - Library files in firmware (via version strings, SONAME, VERDEF)

    Used by SSL agent to resolve version-dependent rules from UNDETERMINED
    to SATISFIED/UNSATISFIED when defaults are known for the detected version.

    Loaded from firmware cache (.tlscan/library_versions.json) or
    detected at startup if cache is not available.
    """

    # ========================================================================
    # Final Output
    # ========================================================================

    final_report: str
    """Final security analysis report (generated by synthesis node)."""

    report_data: Optional[Dict[str, Any]]
    """
    Structured report data for Rich widget display.
    Contains summary_stats, context, rules, traces, and scripts.
    Generated by synthesis node for format_and_display_report().
    """

    # ========================================================================
    # Error Tracking
    # ========================================================================

    errors: List[str]
    """
    List of errors encountered during analysis.

    Non-critical errors are logged here instead of failing the entire analysis.
    """

    # ========================================================================
    # Statistics Tracking
    # ========================================================================

    statistics: AnalysisStatistics
    """
    Comprehensive analysis statistics for reporting.

    Tracks tokens, tool calls, timing, and dependency counts per agent type.
    Updated by each node and displayed in final summary.
    """


# ============================================================================
# State Factory
# ============================================================================

def create_initial_state(
    binary_path: str,
    security_rules: str,
    file_type: FileType = FileType.ELF_BINARY,
    library_versions: Optional[LibraryVersions] = None,
    library_name: str = "unknown",
    firmware_path: Optional[str] = None,
    no_rules: bool = False,
    call_graph_context: str = "",
    enable_verification: bool = False,
    enable_trace_verification: bool = True,
) -> AnalysisState:
    """
    Create initial state for analysis.

    Args:
        binary_path: Path to binary/script to analyze
        security_rules: Security rules content
        file_type: Detected file type (default: ELF_BINARY for backward compatibility)
        library_versions: Optional detected library versions from firmware cache
        library_name: Name of the library/command being analyzed (from -r argument)
        firmware_path: Path to firmware root (optional)
        no_rules: Whether running in ablation mode without security rules
        call_graph_context: Pre-computed call graph text for SSL agent
        enable_verification: Whether to run verification agent after SSL analysis
        enable_trace_verification: Whether to also audit dataflow traces by
            forward replay (only consulted when enable_verification is True)

    Returns:
        Initial AnalysisState with all required fields initialized
    """
    return AnalysisState(
        # Context
        binary_path=binary_path,
        main_binary_path=binary_path,
        security_rules=security_rules,
        file_type=file_type,
        library_name=library_name,
        no_rules=no_rules,
        enable_verification=enable_verification,
        enable_trace_verification=enable_trace_verification,

        # Pre-analysis context
        call_graph_context=call_graph_context,

        # Workflow control
        current_phase=AnalysisPhase.INITIAL_SSL_ANALYSIS,

        # SSL results
        rule_result={},
        ssl_summary="",
        client_type=None,
        applicable=True,

        # Dataflow
        pending_dataflow_tasks=[],

        # Unified trace graph
        traces={},
        rule_trace_links={},

        # Config fetch
        pending_config_fetch_tasks=[],

        # Firmware
        firmware_path=firmware_path,
        firmware_details=None,
        script_findings=None,

        # Library versions
        library_versions=library_versions,

        # Final output
        final_report="",
        report_data=None,

        # Errors
        errors=[],

        # Statistics
        statistics=create_empty_statistics(),
    )
