"""State schema for LangGraph-based SSL analysis workflow.

This module defines the complete state structure that flows through
the analysis graph. State is the single source of truth for all
intermediate results.
"""

from enum import Enum
from typing import TypedDict, Optional, Dict, List, Set
from conn_analyzer.graph.models import RuleResult, VariableTrace


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
# Task Definitions
# ============================================================================

class DataflowTask(TypedDict):
    """
    Task specification for dataflow analysis.

    Attributes:
        type: Type of analysis - "binary", "script", or "config"
        target: Path to binary, script, or config file
        variables: List of variables to trace with their context
    """

    type: str  # "binary" | "script" | "config"
    target: str
    variables: List[Dict[str, str]]  # [{"variable": "name", "function": "func", ...}]


class CrossBinaryTask(TypedDict):
    """
    Task for cross-binary analysis.

    Attributes:
        function: Function name to search for callers
        caller_binaries: List of binaries that call this function
        variables: Variables to trace in caller binaries
    """

    function: str
    caller_binaries: List[str]
    variables: List[Dict[str, str]]


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

    depth: int
    """Depth of cross-binary recursion (for preventing infinite loops)."""

    # ========================================================================
    # SSL Analysis Results
    # ========================================================================

    rules: Dict[str, RuleResult]
    """
    Security rules analysis results.

    Key: rule_id (e.g., "rule_certificate_verification")
    Value: RuleResult Pydantic model with status, evidence, conditions

    Example:
    {
        "rule_certificate_verification": RuleResult(
            rule_id="rule_certificate_verification",
            rule_name="Certificate Verification Enabled",
            status=RuleStatus.CONDITIONAL,
            evidence="SSL_CTX_set_verify() found at 0x401234",
            conditions=[
                RuleCondition(
                    variable="mode",
                    function="SSL_CTX_set_verify",
                    function_address="0x401234",
                    parameter_position=1,
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

    variable_traces: Dict[str, VariableTrace]
    """
    Results of variable tracing.

    Key: variable name (e.g., "verify_mode")
    Value: VariableTrace Pydantic model with source, value, confidence

    Example:
    {
        "verify_mode": VariableTrace(
            variable="verify_mode",
            function="SSL_CTX_set_verify",
            source=VariableSource.CONSTANT,
            value="1",
            source_details="SSL_VERIFY_PEER",
            confidence="high",
            trace_path="Traced from parameter 2 → local var → constant 1"
        )
    }
    """

    # ========================================================================
    # Cross-Binary Analysis
    # ========================================================================

    analyzed_binaries: Set[str]
    """
    Set of binary paths already analyzed (prevents circular dependencies).

    Example: {"/usr/bin/app", "/lib/libcustom.so"}
    """

    pending_cross_binary_tasks: List[CrossBinaryTask]
    """
    Queue of cross-binary analysis tasks.

    Populated when dataflow finds a variable comes from an exported function parameter.
    """

    cross_binary_traces: Dict[str, Dict[str, VariableTrace]]
    """
    Traces from cross-binary analysis.

    Outer key: binary path
    Inner key: variable name
    Value: VariableTrace

    Example:
    {
        "/usr/bin/app": {
            "ssl_mode": VariableTrace(...)
        },
        "/lib/libcustom.so": {
            "ssl_mode": VariableTrace(...)
        }
    }
    """

    # ========================================================================
    # Firmware Context
    # ========================================================================

    config_values: Dict[str, str]
    """
    Configuration values fetched from firmware.

    Key: setting name (e.g., "ssl_verify_mode")
    Value: configured value (e.g., "1")

    Example: {"ssl_verify_mode": "1", "tls_min_version": "1.2"}
    """

    firmware_details: Optional[str]
    """Detailed findings from firmware exploration (for logging/display)."""

    # ========================================================================
    # Final Output
    # ========================================================================

    final_report: str
    """Final security analysis report (generated by synthesis node)."""

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
        rules={},
        ssl_summary="",
        client_type=None,
        applicable=True,

        # Dataflow
        pending_dataflow_tasks=[],
        variable_traces={},

        # Cross-binary
        analyzed_binaries=set(),
        pending_cross_binary_tasks=[],
        cross_binary_traces={},

        # Firmware
        config_values={},
        firmware_details=None,

        # Final output
        final_report="",

        # Errors
        errors=[]
    )
