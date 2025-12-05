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
    ExternalValue,
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


def parse_trace_key(key: str) -> Tuple[Optional[str], str, str]:
    """
    Parse composite key into components.

    Args:
        key: Composite key from create_trace_key()

    Returns:
        Tuple of (binary_path, function, variable)
        - binary_path is None for main binary traces
        - binary_path is set for cross-binary traces

    Examples:
        >>> parse_trace_key("SSL_CTX_set_verify:mode")
        (None, "SSL_CTX_set_verify", "mode")
        >>> parse_trace_key("/usr/bin/app:init_ssl:mode")
        ("/usr/bin/app", "init_ssl", "mode")
    """
    parts = key.split(":")
    if len(parts) == 2:
        return None, parts[0], parts[1]
    elif len(parts) >= 3:
        # Handle cases where binary_path or function might contain colons
        return parts[0], parts[1], ":".join(parts[2:])
    else:
        raise ValueError(f"Invalid trace key format: {key}")


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

    # NOTE: is this used?
    depth: int
    """Depth of cross-binary recursion (for preventing infinite loops)."""

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

    variable_traces: Dict[str, List[VariableTrace]]
    """
    Results of variable tracing from all analyzed binaries.

    Key: composite key in format "{binary_path}:{function}:{variable}" for cross-binary traces,
         or "function:variable" for main binary traces
    Value: List of VariableTrace objects (multiple sources can contribute to same variable)

    Using composite keys prevents conflicts when the same variable name appears
    in different functions or binaries.

    Each VariableTrace now contains:
    - trace_path: List[TraceStep] - structured list of trace steps
    - resolving_status: TraceResolvingStatus - PENDING/RESOLVED/CANNOT_RESOLVE
    - outcome: Optional[str] - security outcome when resolved
    - resolution_reason: Optional[str] - explanation when cannot_resolve

    Example:
    {
        "SSL_CTX_set_verify:verify_mode": [VariableTrace(
            variable="verify_mode",
            function="SSL_CTX_set_verify",
            value="1",
            confidence="high",
            trace_path=[
                TraceStep(step_number=1, step_type="trace_start",
                          description="Begin tracing verify_mode in SSL_CTX_set_verify",
                          function="SSL_CTX_set_verify"),
                TraceStep(step_number=2, step_type="trace_end",
                          description="Found constant value 1",
                          source_kind="constant",
                          constant_value="1",
                          constant_name="SSL_VERIFY_PEER")
            ],
            resolving_status=TraceResolvingStatus.RESOLVED,
            outcome="PASS - enables verification"
        )]
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
    # Firmware Context & External Values
    # ========================================================================

    external_values: Dict[str, ExternalValue]
    """
    Values sourced from external firmware files (binaries/scripts/configs).

    Unified structure for all external sources that follow the same pattern:
    dataflow finds external source → firmware exploration → fetch value

    Key: variable name (e.g., "ssl_verify_mode")
    Value: ExternalValue with value, source_type, source_path, context

    Example:
    {
        "ssl_verify_mode": ExternalValue(
            value="1",
            source_type=ExternalSourceType.CONFIG,
            source_path="/etc/ssl.conf",
            variable_name="ssl_verify_mode",
            context="Found in main config file"
        ),
        "tls_min_version": ExternalValue(
            value="1.2",
            source_type=ExternalSourceType.SCRIPT,
            source_path="/etc/init.d/ssl-setup.sh",
            variable_name="tls_min_version",
            context="Set in initialization script"
        )
    }
    """

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
        depth=0,

        # SSL results
        rule_result={},
        ssl_summary="",
        client_type=None,
        applicable=True,

        # Dataflow
        pending_dataflow_tasks=[],
        variable_traces={},

        # Config fetch
        pending_config_fetch_tasks=[],

        # Firmware & External Values
        external_values={},
        firmware_details=None,
        script_findings=None,

        # Final output
        final_report="",
        report_data=None,

        # Errors
        errors=[]
    )
