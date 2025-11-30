"""Pydantic models for structured output from agents.

This module defines all structured output models that agents return.
Using Pydantic ensures type safety and eliminates regex parsing.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Literal, Optional, List, Dict, Any, Union
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

class RuleResolvingStatus(str, Enum):
    """Status of rule resolution during analysis."""

    UNRESOLVED = "unresolved"
    RESOLVED = "resolved"
    CANNOT_RESOLVE = "cannot_resolve"



class VariableSourceType(str, Enum):
    """Source of a variable's value in dataflow analysis."""

    CONSTANT = "constant"
    CONFIG_FILE = "config_file"
    ENVIRONMENT_VARIABLE = "environment_variable"
    COMMAND_LINE_ARG = "command_line_arg"
    FUNCTION_PARAMETER_FROM_EXTERNAL_CALL = "function_parameter_from_external_call"
    UNKNOWN = "unknown"


class ExternalSourceType(str, Enum):
    """Type of external source for firmware exploration."""

    BINARY = "binary"
    SCRIPT = "script"
    CONFIG = "config"


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

    resolving_status: RuleResolvingStatus = Field(
        RuleResolvingStatus.UNRESOLVED,
        description="Status of rule resolution during analysis: unresolved/resolved/cannot_resolve"
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

# Source-specific detail models for type-safe discriminated union

class FunctionParameterDetails(BaseModel):
    """Details for FUNCTION_PARAMETER_FROM_EXTERNAL_CALL source.

    Represents a variable whose value comes from an external function call
    outside the current binary.
    """
    source_type: Literal["function_parameter_from_external_call"] = "function_parameter_from_external_call"
    external_function: str = Field(
        description="Name of the function being called from outside (e.g., 'upscli_connect')"
    )
    parameter_name: str = Field(
        description="Name of the parameter in that function (e.g., 'a4', 'verify_mode')"
    )
    # FIXME: not used.
    parameter_index: Optional[int] = Field(
        None,
        description="Zero-indexed position of parameter in function signature"
    )


class ConstantDetails(BaseModel):
    """Details for CONSTANT source.

    Represents a variable whose value is a compile-time constant.
    """
    source_type: Literal["constant"] = "constant"
    constant_value: str = Field(
        description="The constant value (e.g., '1', '0', '0x10')"
    )
    constant_name: Optional[str] = Field(
        None,
        description="Symbolic name of constant if known (e.g., 'SSL_VERIFY_PEER')"
    )


class ConfigFileDetails(BaseModel):
    """Details for CONFIG_FILE source.

    Represents a variable whose value comes from a configuration file.
    """
    source_type: Literal["config_file"] = "config_file"
    config_file: Optional[str] = Field(
        None,
        description=(
            "Config file identifier - can be:\n"
            "  - Full path: '/etc/upsmon.conf'\n"
            "  - Filename only: 'upsmon.conf'\n"
            "  - Partial path: 'config/ups.conf'\n"
            "  - Any identifiable clue\n"
            "Provide ANY information you have - firmware agent will search for it."
        )
    )
    config_key: Optional[str] = Field(
        None,
        description="Key name in the config file if known"
    )


class EnvironmentVariableDetails(BaseModel):
    """Details for ENVIRONMENT_VARIABLE source.

    Represents a variable whose value comes from an environment variable.
    """
    source_type: Literal["environment_variable"] = "environment_variable"
    env_var_name: str = Field(
        description="Name of the environment variable (e.g., 'SSL_VERIFY_MODE')"
    )


class CommandLineArgDetails(BaseModel):
    """Details for COMMAND_LINE_ARG source.

    Represents a variable whose value comes from command-line arguments.
    """
    source_type: Literal["command_line_arg"] = "command_line_arg"
    arg_position: Optional[int] = Field(
        None,
        description="Position in argv array (e.g., 1 for first argument after program name)"
    )
    arg_name: Optional[str] = Field(
        None,
        description="Flag or argument name if applicable (e.g., '--verify', '-v')"
    )


class UnknownDetails(BaseModel):
    """Details for UNKNOWN source.

    Represents a variable whose source could not be determined.
    """
    source_type: Literal["unknown"] = "unknown"
    reason: str = Field(
        description="Explanation of why the source could not be determined"
    )


class VariableTrace(BaseModel):
    """
    Result of tracing a single variable through dataflow analysis.

    Contains information about where the variable's value comes from
    and what that value is (if determinable).
    """

    function: str = Field(
        description="Function where variable is used"
    )

    variable: str = Field(
        description="Variable or parameter name that was traced"
    )

    source: VariableSourceType = Field(
        description=(
            "Source of variable value: "
            "constant/config_file/environment_variable/command_line_arg/function_parameter/unknown"
        )
    )

    value: Optional[str] = Field(
        None,
        description="Concrete value if determinable (e.g., '1', 'SSL_VERIFY_PEER', '/etc/ssl.conf')"
    )

    source_details: Union[
        FunctionParameterDetails,
        ConstantDetails,
        ConfigFileDetails,
        EnvironmentVariableDetails,
        CommandLineArgDetails,
        UnknownDetails
    ] = Field(
        description="Type-safe details about the variable's source (discriminated by source_type)",
        discriminator="source_type"
    )

    confidence: Literal["high", "medium", "low"] = Field(
        "medium",
        description="Confidence level in the trace result"
    )

    trace_path: str = Field(
        description=(
            "Detailed explanation of the trace path. "
            "Example: 'Traced from SSL_CTX_set_verify parameter 2 → "
            "local variable verify_mode → initialized with constant 1'"
        )
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
# External Value Models (Unified for Firmware Exploration)
# ============================================================================

class ExternalValue(BaseModel):
    """
    A value sourced from external firmware files (binary/script/config).

    This unifies all external value sources that follow the same pattern:
    dataflow finds external source → firmware exploration → fetch value
    """

    value: str = Field(
        description="The actual value found"
    )

    source_type: ExternalSourceType = Field(
        description="Type of external source: binary/script/config"
    )

    source_path: str = Field(
        description="Path to the source file in firmware (e.g., '/etc/ssl.conf', '/usr/bin/client')"
    )

    variable_name: str = Field(
        description="Name of the variable this value is for (e.g., 'ssl_verify_mode')"
    )

    context: Optional[str] = Field(
        None,
        description="Additional context about how/where the value was found"
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
            "Config file or key reference from dataflow trace source_details. "
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
