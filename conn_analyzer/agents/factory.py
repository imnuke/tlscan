"""Agent Factory with structured output support.

This factory creates agents that return Pydantic model outputs instead of
free-form text. It works with the Static Analysis Engine to get tools.
"""

from typing import List, Optional
from langchain.agents import create_agent

from conn_analyzer.agents.core.middleware import handle_tool_errors
from conn_analyzer.graph.models import (
    SSLAnalysisOutput,
    DataflowAnalysisOutput,
    FirmwareSearchResult,
)


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

    def __init__(self, llm: any):
        """Initialize the agent factory.

        Args:
            llm: Language model instance to use for all agents
        """
        self._llm = llm

    def create_ssl_agent(
        self,
        tools: List[any],
        security_rules_content: str = ""
    ) -> any:
        """Create SSL analysis agent with structured output.

        Args:
            tools: IDA tools from Static Analysis Engine
            security_rules_content: Security rules to inject into prompt

        Returns:
            Agent that returns SSLAnalysisOutput Pydantic model
        """
        from conn_analyzer.agents.prompts.ssl_prompt import get_ssl_system_prompt

        system_prompt = get_ssl_system_prompt(security_rules_content)

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches SSLAnalysisOutput schema
        agent = create_agent(
            model=self._llm,
            tools=tools,
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
        from conn_analyzer.agents.prompts.dataflow_prompt import DATAFLOW_SYSTEM_PROMPT

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches DataflowAnalysisOutput schema
        agent = create_agent(
            model=self._llm,
            tools=tools,
            middleware=[handle_tool_errors],
            system_prompt=DATAFLOW_SYSTEM_PROMPT
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
        from conn_analyzer.agents.prompts.firmware_prompt import get_firmware_system_prompt

        system_prompt = get_firmware_system_prompt(firmware_path)

        # Create base agent with raw LLM (not wrapped with structured output)
        # The agent will output JSON that matches FirmwareSearchResult schema
        agent = create_agent(
            model=self._llm,
            tools=firmware_tools,
            middleware=[handle_tool_errors],
            system_prompt=system_prompt
        )

        return agent
