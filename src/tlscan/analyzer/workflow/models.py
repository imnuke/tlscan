"""Pydantic models for structured output from agents.

This module defines all structured output models that agents return.
Using Pydantic ensures type safety and eliminates regex parsing.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from enum import Enum


def _coerce_optional_int(v):
    """Coerce hex/decimal string offsets to int for Optional[int] fields.

    Some LLM backends (observed with GLM-5.2) emit numeric struct offsets and
    access sizes as hex strings such as '0x274A8' instead of integers. Accept
    those transparently so an otherwise well-formed analysis is not discarded
    on a serialisation-format mismatch. This only normalises the value's type;
    it does not affect any rule verdict logic.
    """
    if isinstance(v, str):
        s = v.strip().lower()
        if not s:
            return None
        try:
            return int(s, 16) if s.startswith("0x") else int(s, 10)
        except ValueError:
            # last resort: bare hex digits without a 0x prefix
            return int(s, 16)
    return v


# ============================================================================
# Enums
# ============================================================================

class RuleResultStatus(str, Enum):
    """Result status of a security rule after analysis."""

    UNDETERMINED = "undetermined"
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    CONDITIONAL = "conditional"
    DEFAULT = "default"  # Rule follows library default behavior - not explicitly configured
    LOW_CONFIDENCE = "low_confidence"  # Verdict flagged after two failed verifications

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


class TraceType(str, Enum):
    """Type of trace based on its source context.

    In the unified trace graph, all traces are equal - they just have different
    types indicating where they came from. This replaces the old distinction
    between main_traces and continuations.
    """

    MAIN_BINARY = "main_binary"      # Trace from the main binary being analyzed
    CROSS_BINARY = "cross_binary"    # Trace from a caller binary (cross-binary analysis)
    CONFIG_FILE = "config_file"      # Value extracted from a config file
    SCRIPT = "script"                # Value from script analysis
    ENVIRONMENT = "environment"      # Value from environment variable


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
        description=(
            "Variable name or memory access expression. "
            "Simple: 'v20', 'a1'. Struct: '*(DWORD *)(v18+12)'"
        )
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
            "Example: {'0': 'UNSATISFIED - disables verification', '1': 'SATISFIED - enables verification'}"
        )
    )

    parameter_name: Optional[str] = Field(
        None,
        description="Parameter name if tracing function parameter (e.g., 'mode', 'arg1')"
    )

    usage_address: Optional[str] = Field(
        None,
        description=(
            "Hex address where variable is used in security-relevant context "
            "(e.g., '0x407a8c'). Restricts dataflow to assignments before this point."
        )
    )

    usage_context: Optional[str] = Field(
        None,
        description=(
            "How/where the variable is used at the usage point "
            "(e.g., '4th argument to Execute_Command_Line')"
        )
    )

    struct_base: Optional[str] = Field(
        None,
        description="Base variable for struct access (e.g., 'v18' from '*(DWORD *)(v18+12)')"
    )

    struct_offset: Optional[int] = Field(
        None,
        description="Byte offset into struct (e.g., 12 from '*(DWORD *)(v18+12)')"
    )

    access_size: Optional[int] = Field(
        None,
        description="Access size in bytes (e.g., 4 for DWORD, 8 for QWORD)"
    )

    _coerce_offsets = field_validator(
        "struct_offset", "access_size", mode="before"
    )(_coerce_optional_int)


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
        description=(
            "Variable name or memory access expression. "
            "Simple: 'v20', 'a1'. Struct: '*(DWORD *)(v18+12)'"
        )
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
            "Example: {'0': 'UNSATISFIED - disables verification', '1': 'SATISFIED - enables verification'}"
        )
    )

    usage_address: Optional[str] = Field(
        None,
        description=(
            "Hex address where variable is used in security-relevant context "
            "(e.g., '0x407a8c'). Restricts dataflow to assignments before this point."
        )
    )

    usage_context: Optional[str] = Field(
        None,
        description=(
            "How/where the variable is used at the usage point "
            "(e.g., '4th argument to Execute_Command_Line')"
        )
    )

    struct_base: Optional[str] = Field(
        None,
        description="Base variable for struct access (e.g., 'v18' from '*(DWORD *)(v18+12)')"
    )

    struct_offset: Optional[int] = Field(
        None,
        description="Byte offset into struct (e.g., 12 from '*(DWORD *)(v18+12)')"
    )

    access_size: Optional[int] = Field(
        None,
        description="Access size in bytes (e.g., 4 for DWORD, 8 for QWORD)"
    )

    _coerce_offsets = field_validator(
        "struct_offset", "access_size", mode="before"
    )(_coerce_optional_int)


class RuleResult(BaseModel):
    """
    Result for a single security rule.

    Contains the rule's status (SATISFIED/UNSATISFIED/CONDITIONAL/UNDETERMINED),
    supporting evidence, and any conditions it depends on.
    """

    rule_id: str = Field(
        description="Unique rule identifier matching rule header (e.g., 'R2')"
    )

    rule_name: str = Field(
        description="Human-readable rule name (e.g., 'Certificate Chain Verification')"
    )

    result: RuleResultStatus = Field(
        default=RuleResultStatus.UNDETERMINED,
        description="Rule status: satisfied/unsatisfied/conditional/undetermined"
    )

    evidence: str = Field(
        description="Detailed evidence supporting the status (function calls, addresses, etc.)"
    )

    conditions: List[RuleCondition] = Field(
        default_factory=list,
        description="List of conditions this rule depends on (empty if not conditional)"
    )

    critique: Optional[str] = Field(
        None,
        description="Critique from verification agent when verdict was challenged"
    )

    low_confidence: bool = Field(
        False,
        description="True if verdict was downgraded to LOW_CONFIDENCE after two failed verifications"
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
# Verification Models
# ============================================================================

class VerificationCheckResult(BaseModel):
    """Result of a single check within verification."""

    check_name: str = Field(
        description=(
            "Name of the check: 'evidence_grounding', 'logical_soundness', "
            "or 'condition_adequacy'"
        )
    )

    passed: bool = Field(
        description="Whether this specific check passed"
    )

    finding: str = Field(
        description=(
            "What was found during this check. If failed, include what the evidence "
            "claims vs. what the re-fetched code actually shows."
        )
    )


class VerificationOutput(BaseModel):
    """Structured output from the Verification Agent."""

    rule_id: str = Field(
        description="Rule identifier being verified (e.g., 'R3')"
    )

    passed: bool = Field(
        description="True only if ALL applicable checks passed"
    )

    critique: Optional[str] = Field(
        None,
        description=(
            "If not passed: concise explanation of exactly what failed and why. "
            "Cite function names, addresses, and what the evidence claims vs. "
            "what the re-fetched code actually shows."
        )
    )

    check_results: List[VerificationCheckResult] = Field(
        default_factory=list,
        description="Individual result for each check performed"
    )


class TraceReplayFailureKind(str, Enum):
    """How a forward replay of a dataflow trace failed."""

    PREMATURE_STOP = "premature_stop"
    """Replay ran out of steps before reaching the original condition variable."""

    DIVERGENCE = "divergence"
    """A re-fetched instruction propagates a different value than the trace claims."""

    UNCOVERED_HOP = "uncovered_hop"
    """Two consecutive steps are not connected by any instruction in the cited code."""

    FABRICATION = "fabrication"
    """A cited instruction does not exist at the cited location."""


class TraceVerificationCheckResult(BaseModel):
    """Result of a single check within trace verification."""

    check_name: str = Field(
        description=(
            "Name of the check: 'step_grounding', 'forward_replay', "
            "or 'terminal_soundness'"
        )
    )

    passed: bool = Field(
        description="Whether this specific check passed"
    )

    finding: str = Field(
        description=(
            "What was found during this check. If failed, state what the trace "
            "claims vs. what the re-fetched code actually shows."
        )
    )


class TraceVerificationOutput(BaseModel):
    """Structured output from the Trace Verification Agent.

    The agent replays the trace forward from the reported source terminal back
    to the original condition variable, using only re-fetched code.
    """

    trace_id: str = Field(
        description="Identifier of the trace being verified"
    )

    passed: bool = Field(
        description=(
            "True only if the forward replay reached the original condition "
            "variable AND all checks passed"
        )
    )

    failure_kind: Optional[TraceReplayFailureKind] = Field(
        None,
        description=(
            "If not passed: which failure mode was observed. Omit when passed."
        )
    )

    divergence_step: Optional[int] = Field(
        None,
        description=(
            "If not passed: the step_number at which the replay diverged from "
            "the claimed trace. Omit when passed."
        )
    )

    critique: Optional[str] = Field(
        None,
        description=(
            "If not passed: concise explanation of exactly where and why the "
            "replay failed. Cite function names and addresses, and state what "
            "the trace claims vs. what the re-fetched code actually shows."
        )
    )

    check_results: List[TraceVerificationCheckResult] = Field(
        default_factory=list,
        description="Individual result for each check performed"
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

    config_file_source: Optional[str] = Field(
        None,
        description=(
            "When config_file path cannot be determined statically, indicates where "
            "the path comes from. Example: 'CLI argument -f', 'environment variable CONFIG_PATH'. "
            "If set, the workflow should search for config files by key instead of by filename."
        )
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

    In the unified trace graph architecture, all traces are nodes in a directed
    graph. Traces link to each other via parent_trace_id and child_trace_ids,
    forming chains from rule conditions to resolved values.

    Contains information about where the variable's value comes from
    and what that value is (if determinable). Source information is
    stored in the final step of trace_path (step_type == TRACE_END).
    """

    # === Identity (for trace graph) ===
    trace_id: Optional[str] = Field(
        None,
        description="Unique identifier for this trace in the graph (UUID). None for legacy traces."
    )

    # === Type & Source ===
    trace_type: TraceType = Field(
        default=TraceType.MAIN_BINARY,
        description="Type of trace: main_binary, cross_binary, config_file, script, environment"
    )

    source_path: Optional[str] = Field(
        None,
        description="Path to source: binary path, config file path, script path. None for main binary traces."
    )

    # === Traced Variable ===
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
        default_factory=list,
        description="Structured list of steps in the trace path. Final step contains source info."
    )

    # === Graph Links ===
    parent_trace_id: Optional[str] = Field(
        None,
        description="ID of parent trace that led to this one (None for root traces)"
    )

    child_trace_ids: List[str] = Field(
        default_factory=list,
        description="IDs of child traces (continuations from this trace)"
    )

    # === Resolution fields (set by synthesis_node, not by agent) ===
    resolving_status: TraceResolvingStatus = Field(
        default=TraceResolvingStatus.PENDING,
        description="Resolution status: pending/resolved/cannot_resolve"
    )

    outcome: Optional[str] = Field(
        None,
        description="Security outcome when resolved (e.g., 'SATISFIED - enables verification')"
    )

    resolution_reason: Optional[str] = Field(
        None,
        description="Why resolution failed (e.g., 'Value controlled by external caller')"
    )

    # === Verification fields (set by the Trace Verification Agent) ===
    verification_failed: bool = Field(
        default=False,
        description=(
            "True when forward replay failed twice, so this trace was never "
            "committed. Its claimed value must not be used for resolution."
        )
    )

    verification_critique: Optional[str] = Field(
        None,
        description="Why the forward replay failed (set when verification_failed)"
    )


class DataflowAnalysisOutput(BaseModel):
    """
    Structured output from dataflow analysis agent.

    Contains traces for all requested variables.
    """

    traces: List[VariableTrace] = Field(
        description="Traces for all requested variables"
    )


class RuleTraceLink(BaseModel):
    """
    Link between a rule condition and its root traces in the trace graph.

    In the unified trace graph architecture, rules connect to traces via
    RuleTraceLink. Multiple conditions can share the same root traces
    (natural deduplication).

    Example:
        rule_trace_links = {
            "upscli_sslinit:a2": RuleTraceLink(
                condition_key="upscli_sslinit:a2",
                root_trace_ids=["trace-001"],
                security_mapping={"0": "UNSATISFIED", "1": "SATISFIED"}
            )
        }
    """

    condition_key: str = Field(
        description="Condition key 'function:variable' identifying this rule condition"
    )

    root_trace_ids: List[str] = Field(
        default_factory=list,
        description="IDs of root traces for this condition (entry points into trace graph)"
    )

    security_mapping: Optional[Dict[str, str]] = Field(
        None,
        description="Mapping of values to security outcomes (e.g., {'0': 'UNSATISFIED', '1': 'SATISFIED'})"
    )

    # === Computed Resolution (set by synthesis_node) ===
    overall_status: TraceResolvingStatus = Field(
        default=TraceResolvingStatus.PENDING,
        description="Overall resolution status computed from all traces in the graph"
    )

    resolution_summary: str = Field(
        default="",
        description="Human-readable summary of the resolution"
    )

    resolution_outcomes: List[str] = Field(
        default_factory=list,
        description="Individual outcomes from each resolution path"
    )


# ============================================================================
# Library Version Detection Models
# ============================================================================

class VersionConfidence(str, Enum):
    """Confidence level for detected library version."""

    HIGH = "high"      # Version string found directly
    MEDIUM = "medium"  # SONAME or symbol versioning
    LOW = "low"        # Inferred from API presence only
    NONE = "none"      # Could not determine


class VersionDetectionMethod(str, Enum):
    """Method used to detect library version."""

    VERSION_STRING = "version_string"    # Direct version string in .rodata
    SONAME = "soname"                    # From DT_SONAME
    VERDEF = "verdef"                    # Symbol versioning VERDEF section
    VERNEED = "verneed"                  # Symbol versioning VERNEED section
    API_INFERENCE = "api_inference"      # Based on presence of version-specific APIs
    NONE = "none"                        # No specific detection method


class LibraryVersion(BaseModel):
    """
    Version information for a detected library.

    Stores the detected version along with confidence level, detection method,
    and supporting details for traceability.
    """

    library: str = Field(
        description="Library identifier (e.g., 'openssl', 'libcurl', 'gnutls', 'mbedtls')"
    )

    version: Optional[str] = Field(
        None,
        description="Detected version string (e.g., '1.1.1k', '7.68.0', '>=1.1.0')"
    )

    version_major: Optional[int] = Field(
        None,
        description="Major version number for comparison"
    )

    version_minor: Optional[int] = Field(
        None,
        description="Minor version number for comparison"
    )

    version_patch: Optional[int] = Field(
        None,
        description="Patch version number for comparison"
    )

    confidence: VersionConfidence = Field(
        default=VersionConfidence.NONE,
        description="Confidence level of version detection"
    )

    detection_method: VersionDetectionMethod = Field(
        default=VersionDetectionMethod.API_INFERENCE,
        description="Method used to detect the version"
    )

    source_path: Optional[str] = Field(
        None,
        description="Path to library file if detected from .so file (relative to firmware root)"
    )

    soname: Optional[str] = Field(
        None,
        description="SONAME if available (e.g., 'libssl.so.1.1')"
    )

    details: str = Field(
        default="",
        description="Additional detection details (e.g., 'Found: OpenSSL 1.1.1k 25 Mar 2021')"
    )

    required_symbols: List[str] = Field(
        default_factory=list,
        description="List of required symbol versions from VERNEED (e.g., ['OPENSSL_1_1_0'])"
    )


class LibraryVersions(BaseModel):
    """
    Collection of library versions for analysis.

    Contains both firmware-level library versions (from .so files) and
    binary-specific version requirements (from VERNEED sections).
    """

    binary_path: str = Field(
        description="Path to the binary being analyzed"
    )

    libraries: Dict[str, LibraryVersion] = Field(
        default_factory=dict,
        description="Detected library versions for the binary being analyzed (keyed by library id)"
    )

    firmware_libraries: Dict[str, LibraryVersion] = Field(
        default_factory=dict,
        description="Library versions found in firmware .so files (keyed by library id)"
    )

    @classmethod
    def from_cache(cls, cache_data: Dict, binary_path: str) -> "LibraryVersions":
        """Create LibraryVersions from cached JSON data.

        Args:
            cache_data: Data loaded from library_versions.json cache
            binary_path: Path to the binary being analyzed

        Returns:
            LibraryVersions instance populated from cache
        """
        result = cls(binary_path=binary_path)

        # Load firmware-level library versions
        for lib_id, lib_data in cache_data.get("firmware_libraries", {}).items():
            # Parse detection method with fallback for unrecognized values
            method_str = lib_data.get("method", "api_inference")
            try:
                detection_method = VersionDetectionMethod(method_str)
            except ValueError:
                detection_method = VersionDetectionMethod.NONE

            result.firmware_libraries[lib_id] = LibraryVersion(
                library=lib_id,
                version=lib_data.get("version"),
                confidence=VersionConfidence(lib_data.get("confidence", "none")),
                detection_method=detection_method,
                source_path=lib_data.get("source_path"),
                soname=lib_data.get("soname"),
                details=lib_data.get("details", ""),
                required_symbols=lib_data.get("required_symbols", []),
            )

        return result

    def format_for_prompt(self) -> str:
        """Format library versions for inclusion in agent prompts.

        Returns:
            Human-readable string describing detected versions
        """
        lines = []

        # Binary-specific versions first
        if self.libraries:
            lines.append("Binary library requirements:")
            for lib_id, ver in sorted(self.libraries.items()):
                if ver.version:
                    line = f"  - {lib_id}: {ver.version} ({ver.confidence.value} confidence)"
                    lines.append(line)

        # Firmware library versions
        if self.firmware_libraries:
            if lines:
                lines.append("")
            lines.append("Firmware library versions:")
            for lib_id, ver in sorted(self.firmware_libraries.items()):
                if ver.version:
                    source = f" from {ver.source_path}" if ver.source_path else ""
                    line = f"  - {lib_id}: {ver.version} ({ver.confidence.value} confidence){source}"
                    lines.append(line)

        return "\n".join(lines) if lines else "No library versions detected"


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

    config_key: Optional[str] = Field(
        None,
        description="Config key to search for when filename is unknown"
    )

    search_mode: str = Field(
        default="by_file",
        description="'by_file' (filename known) or 'by_key' (search files for key)"
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
