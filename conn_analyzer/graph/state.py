"""State schema for LangGraph-based SSL analysis workflow.

This module defines the complete state structure that flows through
the analysis graph. State is the single source of truth for all
intermediate results.
"""

from enum import Enum
from typing import TypedDict, Optional, Dict, List, Set
from conn_analyzer.graph.models import RuleResult, VariableTrace, ExternalValue, ConfigFetchTask


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

class DataflowTask(TypedDict, total=False):
    """
    Task specification for dataflow analysis.

    Attributes:
        type: Type of analysis - "binary", "script", "config", or "needs_caller_discovery"
        target: Path to binary, script, or config file, or function name for caller discovery
        variables: List of variables to trace with their context
        binary_path: Optional binary to analyze (None = main binary, set for cross-binary tasks)
        context: Optional description for task context (e.g., "traces call to init_ssl")
    """

    type: str  # "binary" | "script" | "config" | "needs_caller_discovery"
    target: str
    variables: List[Dict[str, str]]  # [{"variable": "name", "function": "func", ...}]
    binary_path: Optional[str]  # None for main binary, path for cross-binary analysis
    context: Optional[str]  # Description of task context


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

    variable_traces: Dict[str, VariableTrace]
    """
    Results of variable tracing from all analyzed binaries.

    Key: composite key in format "{binary_path}:{function}:{variable}" for cross-binary traces,
         or "function:variable" for main binary traces
    Value: VariableTrace Pydantic model with source, value, confidence

    Using composite keys prevents conflicts when the same variable name appears
    in different functions or binaries.

    Example:
    {
        "SSL_CTX_set_verify:verify_mode": VariableTrace(
            variable="verify_mode",
            function="SSL_CTX_set_verify",
            source=VariableSourceType.CONSTANT,
            value="1",
            source_details="SSL_VERIFY_PEER",
            confidence="high",
            trace_path="Traced from parameter 2 → local var → constant 1"
        ),
        "/usr/bin/app:init_ssl:ssl_mode": VariableTrace(
            variable="ssl_mode",
            function="init_ssl",
            source=VariableSourceType.CONSTANT,
            value="1",
            confidence="high",
            trace_path="Cross-binary trace from caller /usr/bin/app"
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

        # Final output
        final_report="",

        # Errors
        errors=[]
    )
