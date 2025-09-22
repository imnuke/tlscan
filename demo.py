import os
import json
import asyncio
from langchain.chat_models import init_chat_model
from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

DEEPSEEK_KEY = "sk-1bd3cd5c4a164b51ababb4529a68305d"
os.environ["DEEPSEEK_API_KEY"] = DEEPSEEK_KEY

async def main():
    try:
        client = MultiServerMCPClient(
            {
                "idapro": {
                    "transport": "sse",
                    "url": "http://localhost:8745/sse"
                }
            }
        )

        tools = await client.get_tools()
        print(f"Successfully loaded {len(tools)} tools from MCP server")
    except Exception as e:
        print(f"Failed to connect to MCP server: {e}")
        print("Using fallback tools instead...")
        tools = []

    agent = create_agent(
        model="deepseek-chat",
        tools=tools,
        prompt=""
    )

    out = await agent.ainvoke({
        "messages": [{"role": "user", "content": f"Give me the pseudocode of function sub_4185C1"}],
    })

    print(json.dumps(out, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main())
