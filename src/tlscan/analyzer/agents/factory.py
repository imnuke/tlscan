"""Agent Factory with structured output support.

This factory creates agents that return Pydantic model outputs instead of
free-form text. It works with the Static Analysis Engine to get tools.
"""

from typing import List, Optional
from langchain.agents import create_agent

from tlscan.analyzer.agents.core.middleware import handle_tool_errors
from tlscan.analyzer.workflow.models import (
    SSLAnalysisOutput,
    DataflowAnalysisOutput,
    FirmwareSearchResult,
    VerificationOutput,
)
from tlscan.config.loader import LLMConfig


class AgentFactory:
    """Factory for creating agents with structured output.

    This factory creates specialized agents that return Pydantic models.
    Each agent is configured with:
    - Appropriate tools
    - System prompt
    - Structured output format (via .with_structured_output())
    - Error handling middleware

    The factory does NOT manage MCP servers - that's the responsibility of
    StaticAnalysisEngine.
    """

    def __init__(self, llm: any, config: LLMConfig):
        """Initialize the agent factory.

        Args:
            llm: Base language model instance (will be cloned with different temperatures per agent)
            config: LLMConfig instance for retrieving temperature settings
        """
        self._llm = llm
        self._config = config

    def _prepare_llm_for_sequential_tools(self, llm: any, tools: List[any]) -> any:
        """Prepare LLM to call tools sequentially (not in parallel).

        This prevents SSE timeout issues when agents make parallel IDA tool calls.

        Args:
            llm: Language model instance
            tools: Tools to bind to the LLM

        Returns:
            LLM configured for sequential tool calling, or original LLM if not supported
        """
        # Try to bind tools with parallel_tool_calls=False
        # This works for OpenAI, DeepSeek, and other LLMs that support this parameter
        if hasattr(llm, 'bind_tools'):
            try:
                # NOTE: Actually this does not work for deepseek-chat model in 2025-11-21.
                return llm.bind_tools(tools, parallel_tool_calls=False)
            except TypeError:
                # LLM doesn't support parallel_tool_calls parameter
                # Return original LLM (fall back to prompt-based instructions)
                return llm
        return llm

    @staticmethod
    def _filter_tools(
        tools: List[any],
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None
    ) -> List[any]:
        """Filter tools by name using either include or exclude mode.

        Args:
            tools: List of tools to filter
            include: Allowlist - only keep tools with these names
            exclude: Denylist - remove tools with these names

        Returns:
            Filtered tool list

        Raises:
            ValueError: If both include and exclude are provided
        """
        if include is not None and exclude is not None:
            raise ValueError("Cannot use both include and exclude modes simultaneously")

        if include is not None:
            # Allowlist mode - only keep specified tools
            return [tool for tool in tools if tool.name in include]
        elif exclude is not None:
            # Denylist mode - remove specified tools
            return [tool for tool in tools if tool.name not in exclude]
        else:
            # No filtering - return all tools
            return tools

    def create_ssl_agent(
        self,
        tools: List[any],
        security_rules_content: str = "",
        library_name: str = "unknown",
        no_rules: bool = False
    ) -> any:
        """Create SSL analysis agent with structured output.

        Args:
            tools: IDA tools from Static Analysis Engine
            security_rules_content: Security rules to inject into prompt
            library_name: Name of the library/command being analyzed (from -r argument)
            no_rules: If True, use ablation prompt for free-form analysis

        Returns:
            Agent that returns SSLAnalysisOutput Pydantic model
        """
        from tlscan.analyzer.agents.prompts.ssl import (
            get_ssl_system_prompt,
            get_ssl_ablation_prompt,
        )

        if no_rules:
            system_prompt = get_ssl_ablation_prompt(library_name)
        else:
            system_prompt = get_ssl_system_prompt(security_rules_content, library_name)

        # Filter out tools not needed for SSL analysis
        exclude_tools = [
            "get_entry_points",
            "is_entry_point",
            "list_imports",
            "convert_number",
            "disassemble_function",
            "get_global_variable_value_by_name",
            "get_global_variable_value_at_address",
            "set_comment",
            "get_current_address",
        ]
        filtered_tools = self._filter_tools(tools, exclude=exclude_tools)

        # Get temperature for SSL analysis agent
        temperature = self._config.get_agent_temperature('ssl_analysis')

        # Bind temperature to LLM
        llm_with_temp = self._llm.bind(temperature=temperature)

        # Prepare LLM for sequential tool calling (prevents SSE timeouts)
        llm_with_tools = self._prepare_llm_for_sequential_tools(llm_with_temp, filtered_tools)

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches SSLAnalysisOutput schema
        agent = create_agent(
            model=llm_with_tools,
            tools=filtered_tools,
            middleware=[handle_tool_errors],
            system_prompt=system_prompt
        )

        return agent

    def create_dataflow_agent(
        self,
        tools: List[any],
    ) -> any:
        """Create dataflow analysis agent with structured output.

        Args:
            tools: IDA tools from Static Analysis Engine

        Returns:
            Agent that returns DataflowAnalysisOutput Pydantic model
        """
        from tlscan.analyzer.agents.prompts.dataflow import DATAFLOW_SYSTEM_PROMPT

        # Default exclusions for dataflow agent
        exclude_tools = [
            "get_function_by_address", 
            "get_entry_points", 
            "is_entry_point",
            "list_imports", 
            "convert_number", 
            "disassemble_function",
            "set_comment",
            "get_current_address",
        ]

        # Filter tools before binding
        filtered_tools = self._filter_tools(tools, exclude=exclude_tools)

        # Get temperature for dataflow agent
        temperature = self._config.get_agent_temperature('dataflow')

        # Bind temperature to LLM
        llm_with_temp = self._llm.bind(temperature=temperature)

        # Prepare LLM for sequential tool calling (prevents SSE timeouts)
        llm_with_tools = self._prepare_llm_for_sequential_tools(llm_with_temp, filtered_tools)

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches DataflowAnalysisOutput schema
        agent = create_agent(
            model=llm_with_tools,
            tools=filtered_tools,
            middleware=[handle_tool_errors],
            system_prompt=DATAFLOW_SYSTEM_PROMPT
        )

        return agent

    def create_verification_agent(
        self,
        tools: List[any],
    ) -> any:
        """Create verification agent that audits SSL rule verdicts.

        The agent re-fetches cited code locations and runs three checks:
        evidence grounding, logical soundness, and condition adequacy.

        Args:
            tools: IDA tools from Static Analysis Engine

        Returns:
            Agent that returns VerificationOutput Pydantic model
        """
        from tlscan.analyzer.agents.prompts.verification import VERIFICATION_SYSTEM_PROMPT

        # Verification only needs read-only code-inspection tools
        include_tools = [
            "decompile_function",
            "get_function_by_name",
            "get_function_by_address",
            "get_xrefs_to",
            "get_callers",
            "list_functions_filter",
            "list_strings_filter",
            "get_struct_info_simple",
        ]
        filtered_tools = self._filter_tools(tools, include=include_tools)

        temperature = self._config.get_agent_temperature('ssl_analysis')
        llm_with_temp = self._llm.bind(temperature=temperature)
        llm_with_tools = self._prepare_llm_for_sequential_tools(llm_with_temp, filtered_tools)

        agent = create_agent(
            model=llm_with_tools,
            tools=filtered_tools,
            middleware=[handle_tool_errors],
            system_prompt=VERIFICATION_SYSTEM_PROMPT
        )

        return agent

    def create_trace_verification_agent(
        self,
        tools: List[any],
    ) -> any:
        """Create the agent that audits dataflow traces by forward replay.

        The agent re-fetches every cited instruction and walks the dataflow
        forward from the reported terminal to the original condition variable,
        running three checks: step grounding, forward replay, and terminal
        soundness.

        Args:
            tools: IDA tools from Static Analysis Engine, or firmware tools for
                script traces

        Returns:
            Agent that returns TraceVerificationOutput Pydantic model
        """
        from tlscan.analyzer.agents.prompts.trace_verification import (
            TRACE_VERIFICATION_SYSTEM_PROMPT,
        )

        # Replay only needs read-only code-inspection tools. get_function_by_address
        # is kept (unlike the dataflow agent) because steps are cited by address.
        include_tools = [
            "decompile_function",
            "get_function_by_name",
            "get_function_by_address",
            "get_xrefs_to",
            "get_callers",
            "get_callees",
            "list_functions_filter",
            "list_strings_filter",
            "get_struct_info_simple",
            "get_global_variable_value_by_name",
            "get_global_variable_value_at_address",
        ]
        filtered_tools = self._filter_tools(tools, include=include_tools)

        # Script traces run on firmware tools, whose names do not overlap the
        # allowlist above. Falling back to the full set keeps replay possible.
        if not filtered_tools:
            filtered_tools = tools

        temperature = self._config.get_agent_temperature('dataflow')
        llm_with_temp = self._llm.bind(temperature=temperature)
        llm_with_tools = self._prepare_llm_for_sequential_tools(llm_with_temp, filtered_tools)

        agent = create_agent(
            model=llm_with_tools,
            tools=filtered_tools,
            middleware=[handle_tool_errors],
            system_prompt=TRACE_VERIFICATION_SYSTEM_PROMPT
        )

        return agent

    def create_firmware_agent(
        self,
        firmware_tools: List[any],
        firmware_path: str
    ) -> any:
        """Create firmware exploration agent with structured output.

        Args:
            firmware_tools: Firmware file system tools (not IDA tools)
            firmware_path: Path to firmware root

        Returns:
            Agent that returns FirmwareSearchResult Pydantic model
        """
        from tlscan.analyzer.agents.prompts.firmware import get_firmware_system_prompt
        from tlscan.analyzer.static_engine.middleware import wrap_all_tools

        # Wrap all tools with token limit middleware (10K token limit per tool call)
        wrapped_tools = wrap_all_tools(firmware_tools, max_tokens=5000)

        system_prompt = get_firmware_system_prompt(firmware_path)

        # Get temperature for firmware exploration agent
        temperature = self._config.get_agent_temperature('firmware_exploration')

        # Bind temperature to LLM
        llm_with_temp = self._llm.bind(temperature=temperature)

        # Prepare LLM for sequential tool calling (prevents SSE timeouts)
        llm_with_tools = self._prepare_llm_for_sequential_tools(llm_with_temp, wrapped_tools)

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches FirmwareSearchResult schema
        agent = create_agent(
            model=llm_with_tools,
            tools=wrapped_tools,
            middleware=[handle_tool_errors],
            system_prompt=system_prompt
        )

        return agent
