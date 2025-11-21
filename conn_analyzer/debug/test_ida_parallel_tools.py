#!/usr/bin/env python3
"""
Simple test for parallel tool calling to IDA Pro MCP server.

Usage:
    1. Start IDA MCP server: uv run --directory /path/to/ida-pro-mcp idalib-mcp --host localhost --port 9000 /path/to/binary.so
    2. Edit MCP_SERVER_PORT below if needed
    3. Run: uv run conn_analyzer/debug/test_ida_parallel_tools.py
"""

import asyncio
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.messages import HumanMessage
from langchain.agents import create_agent
from langchain_deepseek import ChatDeepSeek
from conn_analyzer.config_loader import get_config

# ============================================================================
# CONFIGURATION
# ============================================================================
MCP_SERVER_HOST = "localhost"
MCP_SERVER_PORT = 9000

# ============================================================================
# MAIN
# ============================================================================

async def main():
    print("\n" + "="*80)
    print("Parallel Tool Calling Test")
    print("="*80 + "\n")

    # Initialize LLM
    config = get_config()
    deepseek_config = config.get_provider_config("deepseek")
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=deepseek_config["api_key"],
        base_url=deepseek_config.get("api_base"),
        temperature=0,
    )

    # Connect to MCP server
    server_config = {
        "ida": {
            "transport": "sse",
            "url": f"http://{MCP_SERVER_HOST}:{MCP_SERVER_PORT}/sse"
        }
    }
    mcp_client = MultiServerMCPClient(server_config)
    tools = await mcp_client.get_tools()
    print(f"Connected to MCP server, got {len(tools)} tools\n")

    # Create agent with parallel tool calling
    # NOTE: Confirmed that the parallel_tool_calls parameter not working for deepseek-chat model.
    # NOTE: Not tested with other LLMs yet.
    llm_with_tools = llm.bind_tools(tools, parallel_tool_calls=True)
    agent = create_agent(
        model=llm_with_tools,
        tools=tools,
        system_prompt="You are an IDA Pro assistant. Use tools to analyze functions."
    )

    # Run query
    messages = [HumanMessage(content="Get information for functions upscli_init and upscli_sslinit")]

    print("Streaming agent response...\n")
    print("="*80)

    chunk_num = 0
    async for chunk in agent.astream(
        {"messages": messages},
        stream_mode="values",
        config={"recursion_limit": 50}
    ):
        chunk_num += 1
        print(f"\nCHUNK {chunk_num}:")
        print("-" * 80)

        if "messages" in chunk:
            print(f"Total messages in state: {len(chunk['messages'])}\n")

            # Print ALL messages (not just the last one)
            for i, msg in enumerate(chunk["messages"]):
                msg_type = getattr(msg, "type", "unknown")
                print(f"  Message {i}: type={msg_type}")

                if msg_type == "ai" and hasattr(msg, "tool_calls") and msg.tool_calls:
                    print(f"    → {len(msg.tool_calls)} tool calls:")
                    for tc in msg.tool_calls:
                        print(f"       - {tc['name']}: {tc['args']}")

                elif msg_type == "tool":
                    print(f"    → Tool result: {msg.name}")
                    print(f"       Content: {msg.content[:100]}...")

                elif msg_type == "ai" and hasattr(msg, "content"):
                    print(f"    → Content: {msg.content[:100]}...")

        print("-" * 80)

    print("\n" + "="*80)
    print("Done")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
