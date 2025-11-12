"""State schema for LangGraph-based SSL analysis workflow."""

from enum import Enum
from typing import TypedDict, Optional, Annotated
from operator import add

from langchain_core.messages import BaseMessage


class AnalysisStatus(str, Enum):
    """Status returned by SSL agent indicating next action needed."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEED_DATAFLOW = "NEED_DATAFLOW"
    NEED_CROSS_BINARY_ANALYSIS = "NEED_CROSS_BINARY_ANALYSIS"
    NEED_CONFIG_ANALYSIS = "NEED_CONFIG_ANALYSIS"
    NEED_FIRMWARE = "NEED_FIRMWARE"
    COMPLETE = "COMPLETE"


class AnalysisPhase(str, Enum):
    """Current phase of the analysis workflow."""

    INITIAL_SSL_ANALYSIS = "initial_ssl_analysis"
    DATAFLOW_ANALYSIS = "dataflow_analysis"
    FIRMWARE_EXPLORE = "firmware_explore"
    CROSS_BINARY_ANALYSIS = "cross_binary_analysis"
    CONFIG_ANALYSIS = "config_analysis"
    AGGREGATING_RESULTS = "aggregating_results"
    SYNTHESIS = "synthesis"
    COMPLETED = "completed"


class AnalysisState(TypedDict, total=False):
    """
    State for the SSL analysis workflow graph.

    Uses TypedDict with total=False to allow partial updates.
    """

    # Input configuration
    binary_path: str
    """Path to the main binary being analyzed."""

    main_binary_path: str
    """Path to the original main binary (preserved during cross-binary analysis)."""

    security_rules: str
    """Security rules content to check against."""

    # Workflow control
    current_phase: AnalysisPhase
    """Current phase of the analysis."""

    ssl_status: Optional[AnalysisStatus]
    """Most recent status returned by SSL agent."""

    depth: int
    """Depth of cross-binary recursion."""

    analyzed_binaries: set[str]
    """Set of binary paths already analyzed (circular dependency prevention)."""

    # Results storage
    ssl_analysis_result: Optional[str]
    """Latest result from SSL agent analysis."""

    dataflow_result: Optional[str]
    """Result from dataflow agent (for current binary)."""

    dataflow_results: dict[str, str]
    """Map of binary_path -> dataflow result (for cross-binary analysis)."""

    firmware_findings: Optional[str]
    """Result from firmware exploration."""

    discovered_binaries: list[str]
    """List of binaries discovered through firmware exploration."""

    aggregated_findings: Optional[str]
    """Aggregated results from multiple binary analyses."""

    final_report: Optional[str]
    """Final analysis report."""

    # Message history (for agent communication)
    messages: Annotated[list[BaseMessage], add]
    """Message history for agent interactions. Uses operator.add for updates."""

    # Analysis request details (parsed from SSL agent status)
    requested_variable: Optional[str]
    """Variable name requested for dataflow analysis."""

    requested_function: Optional[str]
    """Function name for cross-binary analysis."""

    requested_parameter: Optional[str]
    """Parameter position/name for cross-binary analysis."""

    config_source_type: Optional[str]
    """Type of config source: CONFIG_FILE, ENVIRONMENT_VARIABLE, COMMAND_LINE_ARG."""

    config_source_details: Optional[str]
    """Details about config source (file path, var name, arg pattern)."""

    config_setting_name: Optional[str]
    """Setting name to look for in config."""

    # Error tracking
    error: Optional[str]
    """Error message if analysis fails."""


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
        Initial AnalysisState
    """
    return AnalysisState(
        binary_path=binary_path,
        main_binary_path=binary_path,
        security_rules=security_rules,
        current_phase=AnalysisPhase.INITIAL_SSL_ANALYSIS,
        ssl_status=None,
        depth=0,
        analyzed_binaries=set(),
        dataflow_results={},
        discovered_binaries=[],
        messages=[],
    )
