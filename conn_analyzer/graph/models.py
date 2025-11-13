"""Pydantic models for structured output from agents.

This module defines all structured output models that agents return.
Using Pydantic ensures type safety and eliminates regex parsing.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict, Any
from enum import Enum


# ============================================================================
# Enums
# ============================================================================

class RuleStatus(str, Enum):
    """Status of a security rule after analysis."""

    PASS = "pass"
    FAIL = "fail"
    CONDITIONAL = "conditional"
    UNDETERMINED = "undetermined"


class VariableSource(str, Enum):
    """Source of a variable's value in dataflow analysis."""

    CONSTANT = "constant"
    CONFIG_FILE = "config_file"
    ENVIRONMENT_VARIABLE = "environment_variable"
    COMMAND_LINE_ARG = "command_line_arg"
    FUNCTION_PARAMETER = "function_parameter"
    UNKNOWN = "unknown"


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
        description="Variable name to trace (e.g., 'verify_mode', 'ssl_options')"
    )

    function: str = Field(
        description="Function where variable is used (e.g., 'SSL_CTX_set_verify')"
    )

    function_address: str = Field(
        description="Hex address of function (e.g., '0x401234')"
    )

    parameter_position: Optional[int] = Field(
        None,
        description="Parameter position if variable is a function parameter (0-indexed)"
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
        description="Unique rule identifier (e.g., 'rule_certificate_verification')"
    )

    rule_name: str = Field(
        description="Human-readable rule name (e.g., 'Certificate Verification Enabled')"
    )

    status: RuleStatus = Field(
        default=RuleStatus.UNDETERMINED,
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

class VariableTrace(BaseModel):
    """
    Result of tracing a single variable through dataflow analysis.

    Contains information about where the variable's value comes from
    and what that value is (if determinable).
    """

    variable: str = Field(
        description="Variable name that was traced"
    )

    function: str = Field(
        description="Function where variable is used"
    )

    source: VariableSource = Field(
        description=(
            "Source of variable value: "
            "constant/config_file/environment_variable/command_line_arg/function_parameter/unknown"
        )
    )

    value: Optional[str] = Field(
        None,
        description="Concrete value if determinable (e.g., '1', 'SSL_VERIFY_PEER', '/etc/ssl.conf')"
    )

    source_details: Optional[str] = Field(
        None,
        description=(
            "Additional details about the source: "
            "- For CONFIG_FILE: file path (e.g., '/etc/ssl.conf') "
            "- For ENV_VAR: variable name (e.g., 'SSL_VERIFY_MODE') "
            "- For FUNCTION_PARAMETER: function name (e.g., 'init_ssl') "
            "- For CONSTANT: constant name (e.g., 'SSL_VERIFY_PEER')"
        )
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

    Contains traces for all requested variables and indicates if
    cross-binary analysis is needed.
    """

    traces: List[VariableTrace] = Field(
        description="Traces for all requested variables"
    )

    cross_binary_needed: bool = Field(
        False,
        description=(
            "Whether cross-binary analysis is needed. "
            "True if any trace leads to an exported function parameter with no callers in this binary."
        )
    )

    cross_binary_details: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Details for cross-binary analysis if needed. "
            "Example: {'function': 'init_ssl', 'binary': '/usr/bin/app', 'variables': ['param1', 'param2']}"
        )
    )


# ============================================================================
# Firmware Analysis Models
# ============================================================================

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

    binaries: List[str] = Field(
        default_factory=list,
        description=(
            "List of binary paths found (for cross-binary analysis). "
            "Example: ['/usr/bin/app', '/lib/libcustom.so']"
        )
    )

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
