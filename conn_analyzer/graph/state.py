"""State schema for LangGraph-based SSL analysis workflow.

This module defines the complete state structure that flows through
the analysis graph. State is the single source of truth for all
intermediate results.
"""

from enum import Enum
from typing import TypedDict, Optional, Dict, List, Set, Tuple, Any
from conn_analyzer.graph.models import (
    RuleResult,
    VariableTrace,
    VariableTraceGroup,
    ExternalTraceGroup,
    RuleTraceLink,
    ConfigFetchTask,
    DataflowTask,
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

    Args:
        trace: VariableTrace to compute key for

    Returns:
        Content key in format "trace_type:source_path:function:variable"
    """
    source = trace.source_path or "main"
    return f"{trace.trace_type.value}:{source}:{trace.function}:{trace.variable}"


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
        security_mapping: Mapping of values to outcomes (e.g., {'0': 'FAIL', '1': 'PASS'})

    Returns:
        List of outcome strings (e.g., ["cross_binary:/usr/bin/upsc: PASS"])
    """
    trace = traces.get(trace_id)
    if not trace:
        return []

    outcomes = []

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
    """Path to the current binary being analyzed."""

    main_binary_path: str
    """Path to the original main binary (preserved during cross-binary analysis)."""

    security_rules: str
    """Security rules content (from security_rules/*.md files)."""

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
                    security_mapping={"0": "FAIL", "1": "PASS"}
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

    trace_groups: Dict[str, VariableTraceGroup]
    """
    All traces grouped by condition they resolve.

    This is the primary storage for trace analysis results. It groups main binary
    traces with all continuations (cross-binary, config, script) that contribute
    to resolving each condition.

    Key: "function:variable" (condition key)
    Value: VariableTraceGroup containing main traces and all continuations

    Example:
    {
        "upscli_connect:a4": VariableTraceGroup(
            condition_key="upscli_connect:a4",
            function="upscli_connect",
            variable="a4",
            main_traces=[VariableTrace(source_kind=EXTERNAL_CALL, ...)],
            continuations=[
                TraceContinuation(
                    type=CROSS_BINARY,
                    source_path="usr/bin/upsc",
                    traces=[VariableTrace(source_kind=CONSTANT, value="1")],
                    resolved_value="1"
                ),
                TraceContinuation(
                    type=CROSS_BINARY,
                    source_path="usr/sbin/upsmon",
                    traces=[VariableTrace(source_kind=CONFIG_FILE, ...)],
                    sub_continuations=[
                        TraceContinuation(
                            type=CONFIG_FILE,
                            source_path="upsmon.conf",
                            config_values={"CERTVERIFY": "1"}
                        )
                    ]
                )
            ],
            security_mapping={"0": "FAIL", "1": "PASS"},
            overall_status=RESOLVED,
            resolution_summary="Resolved from multiple sources"
        )
    }
    """

    external_traces: Dict[str, ExternalTraceGroup]
    """
    Shared storage for cross-binary analysis results.

    When multiple rule conditions trace to the same external function (e.g.,
    both "Certificate Verification" and "SSL/TLS Usage" trace to upscli_tryconnect:a4),
    the cross-binary analysis results are stored here ONCE and referenced by
    multiple trace_groups via their external_refs field.

    Key: "function:variable" (external function being traced)
    Value: ExternalTraceGroup with cross-binary continuations and origin conditions

    Example:
    {
        "upscli_tryconnect:a4": ExternalTraceGroup(
            external_key="upscli_tryconnect:a4",
            function="upscli_tryconnect",
            variable="a4",
            continuations=[
                TraceContinuation(type=CROSS_BINARY, source_path="usr/bin/upsc", ...),
                TraceContinuation(type=CROSS_BINARY, source_path="usr/sbin/upsmon", ...)
            ],
            origin_conditions=["upscli_sslinit:a2", "upscli_tryconnect:a4"]
        )
    }
    """

    # ========================================================================
    # Unified Trace Graph (NEW - replaces trace_groups + external_traces)
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
            security_mapping={"0": "FAIL", "1": "PASS"}
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

    firmware_details: Optional[str]
    """Detailed findings from firmware exploration (for logging/display)."""

    script_findings: Optional[List[str]]
    """Startup scripts that invoke the analyzed binary (for CLI argument analysis)."""

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


# ============================================================================
# State Factory
# ============================================================================

def create_initial_state(
    binary_path: str,
    security_rules: str
) -> AnalysisState:
    """
    Create initial state for analysis.

    Args:
        binary_path: Path to binary to analyze
        security_rules: Security rules content

    Returns:
        Initial AnalysisState with all required fields initialized
    """
    return AnalysisState(
        # Context
        binary_path=binary_path,
        main_binary_path=binary_path,
        security_rules=security_rules,

        # Workflow control
        current_phase=AnalysisPhase.INITIAL_SSL_ANALYSIS,

        # SSL results
        rule_result={},
        ssl_summary="",
        client_type=None,
        applicable=True,

        # Dataflow
        pending_dataflow_tasks=[],
        trace_groups={},

        # Config fetch
        pending_config_fetch_tasks=[],

        # Firmware
        firmware_details=None,
        script_findings=None,

        # Final output
        final_report="",
        report_data=None,

        # Errors
        errors=[]
    )
