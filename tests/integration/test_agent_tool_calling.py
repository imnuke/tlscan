#!/usr/bin/env python3
"""
Simple test script demonstrating LangChain agent with tool calling.

Shows:
- One simple tool
- Agent creation with sequential tool calling
- Raw message printing from stream
- Loading API keys from llm_config.yaml

Usage:
    uv run python -m tests.integration.test_agent_tool_calling

Note: Requires DeepSeek API key configured in llm_config.yaml
"""

import asyncio
import json
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from langchain.agents import create_agent
from langchain_deepseek import ChatDeepSeek
from tlscan.config.loader import get_config


# Simple calculator tool
@tool
def calculator(a: float, b: float, operation: str) -> str:
    """
    Perform a calculation on two numbers.

    Args:
        a: First number
        b: Second number
        operation: Operation to perform (add, subtract, multiply, divide)

    Returns:
        The result of the calculation
    """
    if operation == "add":
        result = a + b
    elif operation == "subtract":
        result = a - b
    elif operation == "multiply":
        result = a * b
    elif operation == "divide":
        result = a / b if b != 0 else "Error: Division by zero"
    else:
        result = "Error: Unknown operation"

    return f"Result: {result}"


def serialize_chunk(chunk):
    """Convert chunk to JSON-serializable format."""
    if isinstance(chunk, dict):
        serialized = {}
        for key, value in chunk.items():
            if key == "messages" and isinstance(value, list):
                # Convert message objects to dicts
                serialized[key] = [
                    msg.dict() if hasattr(msg, 'dict') else str(msg)
                    for msg in value
                ]
            else:
                serialized[key] = value
        return serialized
    return chunk


async def main():
    """Run the demo."""

    print("\n" + "="*60)
    print("Agent Tool Calling Demo")
    print("="*60 + "\n")

    # Initialize LLM with config from llm_config.yaml
    config = get_config()
    deepseek_config = config.get_provider_config("deepseek")

    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=deepseek_config["api_key"],
        base_url=deepseek_config.get("api_base"),
        temperature=0,
    )

    # Create agent with tool
    tools = [calculator]
    llm_with_tools = llm.bind_tools(tools, parallel_tool_calls=False)

    agent = create_agent(
        model=llm_with_tools,
        tools=tools,
        system_prompt="You are a helpful calculator assistant. Use the calculator tool to perform calculations."
    )

    # Run agent with a task
    task = "Calculate (15 + 27) * 3"
    print(f"Task: {task}\n")
    print("="*60)
    print("Raw Message Stream:")
    print("="*60 + "\n")

    messages = [HumanMessage(content=task)]

    # Stream and print all messages
    async for chunk in agent.astream(
        {"messages": messages},
        stream_mode="values",
        config={"recursion_limit": 50}
    ):
        # Format chunk as pretty JSON
        serialized = serialize_chunk(chunk)
        print(json.dumps(serialized, indent=2, default=str))
        print("-" * 60)


    print("\n" + "="*60)
    print("Demo Complete")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
