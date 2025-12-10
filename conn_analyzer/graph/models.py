"""Pydantic models for structured output from agents.

This module defines all structured output models that agents return.
Using Pydantic ensures type safety and eliminates regex parsing.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from enum import Enum


# ============================================================================
# Enums
# ============================================================================

class RuleResultStatus(str, Enum):
    """Result status of a security rule after analysis."""

    UNDETERMINED = "undetermined"
    PASS = "pass"
    FAIL = "fail"
    CONDITIONAL = "conditional"

class SourceKind(str, Enum):
    """What kind of source was found at TRACE_END step."""

    CONSTANT = "constant"
    CONFIG_FILE = "config_file"
    ENVIRONMENT_VARIABLE = "environment_variable"
    COMMAND_LINE_ARG = "command_line_arg"
    EXTERNAL_CALL = "external_call"
    UNKNOWN = "unknown"


class TaskType(str, Enum):
    """Type of dataflow analysis task."""

    BINARY = "binary"
    SCRIPT = "script"
    CONFIG = "config"
    NEEDS_CALLER_DISCOVERY = "needs_caller_discovery"
    NEEDS_SCRIPT_DISCOVERY = "needs_script_discovery"


class TraceStepType(str, Enum):
    """Type of step in a dataflow trace path."""

    TRACE_START = "trace_start"
    CALL_SITE = "call_site"
    PARAMETER_TRANSFORM = "parameter_transform"
    VARIABLE_ASSIGNMENT = "variable_assignment"
    TRACE_END = "trace_end"


class TraceResolvingStatus(str, Enum):
    """Resolution status for a single trace."""

    PENDING = "pending"
    RESOLVED = "resolved"
    CANNOT_RESOLVE = "cannot_resolve"


class ContinuationType(str, Enum):
    """Type of continuation in trace resolution.

    When a trace ends with an external source (EXTERNAL_CALL, CONFIG_FILE, etc.),
    analysis continues by fetching data from that source. This enum identifies
    the type of continuation.
    """

    CROSS_BINARY = "cross_binary"
    CONFIG_FILE = "config_file"
    SCRIPT = "script"
    ENVIRONMENT = "environment"


# ============================================================================
# Task Models
# ============================================================================

class VariableSpec(BaseModel):
    """
    Specification for a variable to trace in dataflow analysis.

    Provides type-safe structure for variable tracing requests with all
    necessary context (function, address, security mappings).
    """

    variable: str = Field(
        description="Variable or parameter name to trace (e.g., 'verify_mode', 'v20')"
    )

    function: str = Field(
        description="Function where variable is used (e.g., 'SSL_CTX_set_verify', 'sub_AB123')"
    )

    function_address: Optional[str] = Field(
        None,
        description="Hex address of function (e.g., '0xAB123') - optional but helpful for IDA analysis"
    )

    security_mapping: Optional[Dict[str, str]] = Field(
        None,
        description=(
            "Optional mapping of variable values to security outcomes. "
            "Example: {'0': 'FAIL - disables verification', '1': 'PASS - enables verification'}"
        )
    )

    parameter_name: Optional[str] = Field(
        None,
        description="Parameter name if tracing function parameter (e.g., 'mode', 'arg1')"
    )


class DataflowTask(BaseModel):
    """
    Task specification for dataflow analysis (Pydantic version).

    Replaces the TypedDict version with full type safety and validation.
    """

    type: TaskType = Field(
        description="Type of analysis to perform"
    )

    target: str = Field(
        description=(
            "Target for analysis: "
            "- For 'binary'/'script'/'config': Path to file "
            "- For 'needs_caller_discovery': Function name to find callers "
            "- For 'needs_script_discovery': Binary path to find invoking scripts"
        )
    )

    variables: List[VariableSpec] = Field(
        default_factory=list,
        description="List of variables to trace with their context"
    )

    binary_path: Optional[str] = Field(
        None,
        description=(
            "Binary to analyze for cross-binary analysis. "
            "None = main binary (current binary_path from state), "
            "Set = cross-binary task (analyze different binary)"
        )
    )

    context: Optional[str] = Field(
        None,
        description="Optional description for task context (e.g., 'traces call to init_ssl')"
    )

    origin_condition: Optional[str] = Field(
        None,
        description=(
            "Original condition key ('function:variable') that this task is resolving. "
            "Used to link cross-binary analysis results back to the original condition's "
            "trace group. When set, results are stored as continuations of the origin "
            "condition rather than creating new trace groups."
        )
    )

    origin_conditions: Optional[Dict[str, List[str]]] = Field(
        None,
        description=(
            "Mapping from 'function:variable' to list of origin condition keys. "
            "Supports multiple conditions tracing to the same external function. "
            "Keys are the traced function:variable, values are lists of origin condition keys. "
            "Takes precedence over origin_condition when set. "
            "Example: {'upscli_tryconnect:a4': ['upscli_sslinit:a2', 'upscli_tryconnect:a4']}"
        )
    )


# ============================================================================
# SSL Analysis Models
# ============================================================================

class RuleCondition(BaseModel):
    """
    Single condition dependency for a security rule.

    Represents a variable that must be traced to determine the final
    status of a security rule.
    """

    variable: str = Field(
        description="Variable or parameter to trace (e.g., 'verify_mode', 'v20')"
    )

    function: str = Field(
        description="Function where variable is used (e.g., 'sub_AB123')"
    )

    function_address: str = Field(
        description="Hex address of function (e.g., '0xAB123')"
    )

    security_mapping: Dict[str, str] = Field(
        description=(
            "Mapping of values to security outcomes. "
            "Example: {'0': 'FAIL - disables verification', '1': 'PASS - enables verification'}"
        )
    )


class RuleResult(BaseModel):
    """
    Result for a single security rule.

    Contains the rule's status (PASS/FAIL/CONDITIONAL/UNDETERMINED),
    supporting evidence, and any conditions it depends on.
    """

    rule_id: str = Field(
        description="Unique rule identifier (e.g., 'rule_certificate_chain_verification')"
    )

    rule_name: str = Field(
        description="Human-readable rule name (e.g., 'Certificate Chain Verification')"
    )

    result: RuleResultStatus = Field(
        default=RuleResultStatus.UNDETERMINED,
        description="Rule status: pass/fail/conditional/undetermined"
    )

    evidence: str = Field(
        description="Detailed evidence supporting the status (function calls, addresses, etc.)"
    )

    conditions: List[RuleCondition] = Field(
        default_factory=list,
        description="List of conditions this rule depends on (empty if not conditional)"
    )


class SSLAnalysisOutput(BaseModel):
    """
    Structured output from SSL security analysis agent.

    This is the complete result of analyzing a binary's SSL/TLS implementation
    against security rules.
    """

    client_type: str = Field(
        description="Type of SSL/TLS client (e.g., 'OpenSSL', 'libcurl', 'mbedTLS')"
    )

    rules: List[RuleResult] = Field(
        description="Results for each security rule checked"
    )

    summary: str = Field(
        description=(
            "Human-readable summary of analysis for display. "
            "Should include client purpose, connection flow, and overall security posture."
        )
    )

    applicable: bool = Field(
        True,
        description="Whether this binary contains SSL/TLS client code"
    )

    reason: Optional[str] = Field(
        None,
        description="Reason if not applicable (e.g., 'Server-only code', 'No SSL/TLS detected')"
    )


# ============================================================================
# Dataflow Analysis Models
# ============================================================================

class TraceStep(BaseModel):
    """A single step in the dataflow trace path.

    Represents one step in the chain from target variable to its source.
    When step_type is TRACE_END, source-specific fields are populated.
    """

    step_number: int = Field(
        description="Step number in the trace (1-indexed)"
    )

    step_type: TraceStepType = Field(
        description="Type of this trace step"
    )

    description: str = Field(
        description="Human-readable description of this step"
    )

    function: Optional[str] = Field(
        None,
        description="Function at this step"
    )

    address: Optional[str] = Field(
        None,
        description="Hex address if known (e.g., '0x6796')"
    )

    # === Fields only used when step_type == TRACE_END ===

    source_kind: Optional[SourceKind] = Field(
        None,
        description="What kind of source was found (only for TRACE_END step)"
    )

    # For CONSTANT:
    constant_value: Optional[str] = Field(
        None,
        description="The constant value (e.g., '1', '0', '0x10')"
    )

    constant_name: Optional[str] = Field(
        None,
        description="Symbolic name of constant if known (e.g., 'SSL_VERIFY_PEER')"
    )

    # For CONFIG_FILE:
    config_file: Optional[str] = Field(
        None,
        description="Config file path or identifier (e.g., '/etc/upsmon.conf', 'upsmon.conf')"
    )

    config_key: Optional[str] = Field(
        None,
        description="Key name in the config file if known"
    )

    # For ENVIRONMENT_VARIABLE:
    env_var_name: Optional[str] = Field(
        None,
        description="Name of the environment variable (e.g., 'SSL_VERIFY_MODE')"
    )

    # For COMMAND_LINE_ARG:
    arg_name: Optional[str] = Field(
        None,
        description="Flag or argument name if applicable (e.g., '--verify', '-v')"
    )

    arg_position: Optional[int] = Field(
        None,
        description="Position in argv array (e.g., 1 for first argument after program name)"
    )

    # For EXTERNAL_CALL:
    external_function: Optional[str] = Field(
        None,
        description="Name of the function being called from outside (e.g., 'upscli_connect')"
    )

    parameter_name: Optional[str] = Field(
        None,
        description="Name of the parameter in that function (e.g., 'a4', 'verify_mode')"
    )

    parameter_index: Optional[int] = Field(
        None,
        description="Zero-indexed position of parameter in function signature"
    )

    # For UNKNOWN:
    unknown_reason: Optional[str] = Field(
        None,
        description="Explanation of why the source could not be determined"
    )


class VariableTrace(BaseModel):
    """
    Result of tracing a single variable through dataflow analysis.

    Contains information about where the variable's value comes from
    and what that value is (if determinable). Source information is
    stored in the final step of trace_path (step_type == TRACE_END).
    """

    function: str = Field(
        description="Function where variable is used"
    )

    variable: str = Field(
        description="Variable or parameter name that was traced"
    )

    value: Optional[str] = Field(
        None,
        description="Concrete value if determinable (e.g., '1', 'SSL_VERIFY_PEER', '/etc/ssl.conf')"
    )

    trace_path: List[TraceStep] = Field(
        description="Structured list of steps in the trace path. Final step contains source info."
    )

    # Resolution fields (set by synthesis_node, not by agent)
    resolving_status: TraceResolvingStatus = Field(
        default=TraceResolvingStatus.PENDING,
        description="Resolution status: pending/resolved/cannot_resolve"
    )

    outcome: Optional[str] = Field(
        None,
        description="Security outcome when resolved (e.g., 'PASS - enables verification')"
    )

    resolution_reason: Optional[str] = Field(
        None,
        description="Why resolution failed (e.g., 'Value controlled by external caller')"
    )


class DataflowAnalysisOutput(BaseModel):
    """
    Structured output from dataflow analysis agent.

    Contains traces for all requested variables.
    """

    traces: List[VariableTrace] = Field(
        description="Traces for all requested variables"
    )


# ============================================================================
# Firmware Analysis Models
# ============================================================================

class ConfigFetchTask(BaseModel):
    """
    Task for fetching configuration values from firmware.

    Created when dataflow analysis traces a variable to CONFIG_FILE source.
    """

    variable: str = Field(
        description="Variable name that needs the config value"
    )

    function: str = Field(
        description="Function where the variable is used"
    )

    config_reference: Optional[str] = Field(
        None,
        description=(
            "Config file or key reference from dataflow trace final step. "
            "Example: '/etc/ssl.conf', 'CERTVERIFY setting'"
        )
    )

    trace_details: Optional[str] = Field(
        None,
        description="Original trace path and details from dataflow analysis"
    )


class FirmwareSearchResult(BaseModel):
    """
    Result from firmware exploration and analysis.

    Used for:
    - Finding binaries that call a specific function
    - Fetching configuration values
    - Reading script files
    """

    found: bool = Field(
        description="Whether the search/fetch was successful"
    )

    executables: List[str] = Field(
        default_factory=list,
        description=(
            "List of executable paths found (binaries, scripts, libraries). "
            "Paths MUST be relative to firmware root (no leading slash). "
            "Used for cross-binary analysis and script discovery. "
            "Example: ['usr/bin/app', 'etc/init.d/startup.sh', 'lib/libcustom.so']"
        )
    )

    @field_validator('executables', mode='before')
    @classmethod
    def normalize_executable_paths(cls, v):
        """Strip leading slashes from executable paths to ensure firmware-relative paths."""
        if not isinstance(v, list):
            return v
        return [path.lstrip('/') if isinstance(path, str) else path for path in v]

    config_values: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Configuration key-value pairs found. "
            "Example: {'ssl_verify_mode': '1', 'tls_min_version': '1.2'}"
        )
    )

    script_content: Optional[str] = Field(
        None,
        description="Content of script file if requested"
    )

    details: str = Field(
        description=(
            "Detailed explanation of findings. "
            "Should include: what was searched, where it was found, any relevant context."
        )
    )

    function_calls: Optional[Dict[str, List[str]]] = Field(
        None,
        description=(
            "Mapping of function names to binaries that call them. "
            "Key: function name (e.g., 'upscli_connect') "
            "Value: list of binary paths relative to firmware root "
            "Example: {'upscli_connect': ['usr/bin/upsmon', 'usr/bin/upsc'], "
            "'upscli_tryconnect': []} "
            "Enables precise variable assignment during cross-binary analysis. "
            "If null/missing, falls back to assigning all variables to all binaries."
        )
    )


# ============================================================================
# Hierarchical Trace Models
# ============================================================================

class TraceContinuation(BaseModel):
    """A continuation of trace analysis from another source.

    Represents analysis that continues from an EXTERNAL_CALL, CONFIG_FILE,
    or other source kind that requires fetching data from outside the current binary.

    Supports multi-level chains via sub_continuations (e.g., binary → binary → config).
    """

    type: ContinuationType = Field(
        description="Type of continuation: cross_binary, config_file, script, environment"
    )

    source_path: str = Field(
        description="Path to the source: binary path, config file path, script path, etc."
    )

    # The traces from this continuation source
    traces: List["VariableTrace"] = Field(
        default_factory=list,
        description="Traces obtained from analyzing this continuation source"
    )

    # For multi-level chains (e.g., binary → binary → config)
    sub_continuations: List["TraceContinuation"] = Field(
        default_factory=list,
        description="Nested continuations for multi-level resolution chains"
    )

    # Resolved value from this continuation (if found)
    resolved_value: Optional[str] = Field(
        None,
        description="The final resolved value from this continuation (if found)"
    )

    resolved_source_kind: Optional[SourceKind] = Field(
        None,
        description="What source_kind provided the resolved value (e.g., CONSTANT, CONFIG_FILE)"
    )

    # For config files: the actual fetched values
    config_values: Dict[str, str] = Field(
        default_factory=dict,
        description="For CONFIG_FILE continuations: key-value pairs fetched from the config"
    )


class ExternalTraceGroup(BaseModel):
    """Cross-binary analysis results for an external function parameter.

    Stores cross-binary analysis results (from binaries calling a library function)
    in a shared location. Multiple rule conditions that trace to the same external
    function can reference this shared data, avoiding duplication.

    Example: Both "Certificate Verification" (a2 in upscli_sslinit) and
    "SSL/TLS Usage" (a4 in upscli_tryconnect) trace to upscli_tryconnect:a4.
    Instead of duplicating the cross-binary analysis results, they both
    reference this ExternalTraceGroup.
    """

    external_key: str = Field(
        description="Key identifying the external function:parameter (e.g., 'upscli_tryconnect:a4')"
    )

    function: str = Field(
        description="External function name being called"
    )

    variable: str = Field(
        description="Parameter being traced in the external function"
    )

    # Cross-binary continuations (from binaries calling this function)
    continuations: List[TraceContinuation] = Field(
        default_factory=list,
        description="Cross-binary analysis results from binaries calling this function"
    )

    # Which conditions (rule trace groups) reference this external trace
    origin_conditions: List[str] = Field(
        default_factory=list,
        description="List of condition keys that trace to this external function (e.g., ['upscli_sslinit:a2', 'upscli_tryconnect:a4'])"
    )


class VariableTraceGroup(BaseModel):
    """All traces related to resolving one condition.

    Groups the main binary trace(s) with all continuations (cross-binary,
    config, script) that contribute to resolving this condition.

    This provides a hierarchical view of the complete resolution chain,
    from the initial trace in the main binary through all external sources.
    """

    condition_key: str = Field(
        description="Composite key 'function:variable' identifying this condition"
    )

    function: str = Field(
        description="Function where the variable is used"
    )

    variable: str = Field(
        description="Variable or parameter being traced"
    )

    # Main binary traces (may have multiple if variable has multiple sources)
    main_traces: List["VariableTrace"] = Field(
        default_factory=list,
        description="Traces from the main binary being analyzed"
    )

    # Continuations from external sources (direct, non-shared)
    continuations: List[TraceContinuation] = Field(
        default_factory=list,
        description="Continuations from cross-binary, config, script sources (direct storage)"
    )

    # References to shared external trace groups
    external_refs: List[str] = Field(
        default_factory=list,
        description="Keys to ExternalTraceGroup entries in state.external_traces (e.g., ['upscli_tryconnect:a4'])"
    )

    # Security mapping from the original condition
    security_mapping: Optional[Dict[str, str]] = Field(
        None,
        description="Mapping of values to security outcomes (e.g., {'0': 'FAIL', '1': 'PASS'})"
    )

    # Overall resolution (computed from all traces)
    overall_status: TraceResolvingStatus = Field(
        default=TraceResolvingStatus.PENDING,
        description="Overall resolution status computed from all traces and continuations"
    )

    resolution_summary: str = Field(
        default="",
        description="Human-readable summary of the resolution"
    )

    # Individual resolution outcomes
    resolution_outcomes: List[str] = Field(
        default_factory=list,
        description="List of individual resolution outcomes from each source"
    )

    def compute_resolution(self, security_mapping: Optional[Dict[str, str]] = None) -> None:
        """Compute overall resolution from all traces and continuations.

        Updates overall_status, resolution_summary, and resolution_outcomes
        based on the values found in main_traces and continuations.

        Args:
            security_mapping: Optional override for security_mapping
        """
        mapping = security_mapping or self.security_mapping
        outcomes = []

        # Check main traces with resolved values
        for trace in self.main_traces:
            if trace.value is not None and mapping:
                if trace.value in mapping:
                    outcomes.append(mapping[trace.value])

        # Check continuations recursively
        for continuation in self.continuations:
            outcome = self._resolve_continuation(continuation, mapping)
            if outcome:
                outcomes.append(f"{continuation.source_path}: {outcome}")

        # Update resolution status
        if outcomes:
            self.overall_status = TraceResolvingStatus.RESOLVED
            self.resolution_outcomes = outcomes
            self.resolution_summary = "; ".join(outcomes)
        elif self._has_pending_continuations():
            self.overall_status = TraceResolvingStatus.PENDING
            self.resolution_summary = "Awaiting continuation results"
        else:
            self.overall_status = TraceResolvingStatus.CANNOT_RESOLVE
            self.resolution_summary = "No resolution path found"

    def _resolve_continuation(
        self,
        continuation: TraceContinuation,
        mapping: Optional[Dict[str, str]]
    ) -> Optional[str]:
        """Resolve a single continuation and its sub-continuations."""
        # Check if continuation has a resolved value
        if continuation.resolved_value is not None and mapping:
            if continuation.resolved_value in mapping:
                return mapping[continuation.resolved_value]
            return f"value={continuation.resolved_value}"

        # Check traces in continuation
        for trace in continuation.traces:
            if trace.value is not None and mapping:
                if trace.value in mapping:
                    return mapping[trace.value]
                return f"value={trace.value}"

        # Check config values
        for key, value in continuation.config_values.items():
            if mapping and value in mapping:
                return f"{key}: {mapping[value]}"

        # Check sub-continuations recursively
        for sub in continuation.sub_continuations:
            result = self._resolve_continuation(sub, mapping)
            if result:
                return result

        return None

    def _has_pending_continuations(self) -> bool:
        """Check if any traces require continuations that haven't been processed."""
        for trace in self.main_traces:
            if trace.trace_path:
                last_step = trace.trace_path[-1]
                if last_step.step_type == TraceStepType.TRACE_END:
                    if last_step.source_kind in (
                        SourceKind.EXTERNAL_CALL,
                        SourceKind.CONFIG_FILE,
                        SourceKind.COMMAND_LINE_ARG
                    ):
                        # Check if we have a continuation for this
                        if not self._has_continuation_for_trace(trace, last_step):
                            return True
        return False

    def _has_continuation_for_trace(
        self,
        trace: "VariableTrace",
        last_step: "TraceStep"
    ) -> bool:
        """Check if a continuation exists for the given trace's external source."""
        if last_step.source_kind == SourceKind.EXTERNAL_CALL:
            # Look for cross-binary continuations
            for cont in self.continuations:
                if cont.type == ContinuationType.CROSS_BINARY:
                    return True
        elif last_step.source_kind == SourceKind.CONFIG_FILE:
            # Look for config continuations
            for cont in self.continuations:
                if cont.type == ContinuationType.CONFIG_FILE:
                    if cont.config_values:
                        return True
        return False


# Update forward references for recursive models
TraceContinuation.model_rebuild()
VariableTraceGroup.model_rebuild()
