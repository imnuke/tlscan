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
