#!/usr/bin/env python3
"""Plain LLM demo for binary TLS security analysis with IDA Pro MCP.

This demo shows baseline LLM+tools performance on TLS security analysis
WITHOUT any security rules - just a simple prompt and IDA Pro tools.

The LLM is given tools to explore the binary and must autonomously
discover and analyze TLS-related code.

Purpose: Academic comparison against the multi-agent system with rules.
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from rich.console import Console

from tlscan.analyzer.static_engine import StaticAnalysisEngine
from tlscan.analyzer.static_engine.ida.ports import PortManager
from tlscan.analyzer.agents.core.middleware import handle_tool_errors
from tlscan.config.loader import ConfigurationError, LLMConfig

console = Console()

# Simple prompt without security rules
# SYSTEM_PROMPT = """You are a security analyst examining a binary for TLS/SSL vulnerabilities.

# Use the available IDA Pro tools to:
# 1. Find SSL/TLS related functions (look for SSL_*, TLS_*, curl_*, etc.)
# 2. Decompile and analyze these functions
# 3. Identify any security issues or misconfigurations

# Report your findings including:
# - What TLS library is used
# - Certificate verification settings
# - Any vulnerabilities found
# """

SYSTEM_PROMPT = """You are a security analyst examining a binary for TLS/SSL vulnerabilities.
Use the available IDA Pro tools to identify any security issues or misconfigurations of TLS/SSL client.
"""

# USER_PROMPT = """Analyze this binary for TLS/SSL security issues.

# Start by listing functions to find TLS-related code, then decompile and analyze them.
# Look for certificate verification, hostname verification, protocol versions, etc.
# """

USER_PROMPT = """Analyze this binary for TLS/SSL security issues.
"""



def create_llm(model_spec: str, config: LLMConfig, api_key: str | None = None):
    """Create an LLM instance based on model specification."""
    if ":" not in model_spec:
        raise ValueError(
            f"Invalid model format: {model_spec}. Expected 'provider:model_name'"
        )

    provider, model_name = model_spec.split(":", 1)
    provider_config = config.get_provider_config(provider)

    if provider == "deepseek":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name,
            api_key=api_key or provider_config["api_key"],
            base_url=provider_config.get("api_base", "https://api.deepseek.com"),
            temperature=0,
        )
    elif provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name,
            api_key=api_key or provider_config["api_key"],
            temperature=0,
        )
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model_name,
            api_key=api_key or provider_config["api_key"],
            temperature=0,
        )
    elif provider == "qwen":
        from langchain_qwq import ChatQwen

        return ChatQwen(
            model=model_name,
            api_key=api_key or provider_config["api_key"],
            api_base=provider_config["api_base"],
            temperature=0,
        )
    else:
        raise ValueError(f"Unknown provider: {provider}")


async def run_analysis(binary_path: Path, model_spec: str, api_key: str | None = None):
    """Run TLS security analysis on a binary."""
    port_manager = None
    static_engine = None

    try:
        # Load LLM config
        config = LLMConfig()
        llm = create_llm(model_spec, config, api_key)

        # Initialize static analysis engine
        port_manager = PortManager()
        port_manager.cleanup_stale_locks()

        static_engine = StaticAnalysisEngine(
            firmware_path=None,
            port_manager=port_manager
        )

        # Get IDA tools via static engine (handles server startup internally)
        tools = await static_engine.get_tools(str(binary_path))

        # List available tools
        console.print("\n[bold]Available tools:[/bold]")
        for tool in tools:
            console.print(f"  • {tool.name}")

        # Create agent with tools
        console.print(f"\n[cyan]🤖[/cyan] Creating agent with model: {model_spec}")
        llm_with_tools = llm.bind_tools(tools)
        agent = create_agent(
            model=llm_with_tools,
            tools=tools,
            middleware=[handle_tool_errors],
            system_prompt=SYSTEM_PROMPT
        )

        # Run analysis
        console.print("\n" + "=" * 60)
        console.print("[bold]Starting TLS Security Analysis[/bold]")
        console.print("=" * 60 + "\n")

        messages = [HumanMessage(content=USER_PROMPT)]

        # Token tracking
        total_input_tokens = 0
        total_output_tokens = 0
        tool_result_chars = 0

        # Stream the agent's response
        async for chunk in agent.astream(
            {"messages": messages},
            stream_mode="values",
            config={"recursion_limit": 1000}
        ):
            if "messages" in chunk:
                # Get the latest message
                latest_msg = chunk["messages"][-1]
                msg_type = getattr(latest_msg, "type", "unknown")

                if msg_type == "ai":
                    # Extract thinking and text content
                    content = latest_msg.content
                    thinking_text = ""
                    response_text = ""

                    if isinstance(content, list):
                        # Claude-style content blocks
                        for block in content:
                            if isinstance(block, dict):
                                if block.get("type") == "thinking":
                                    thinking_text += block.get("thinking", "")
                                elif block.get("type") == "text":
                                    response_text += block.get("text", "")
                            elif isinstance(block, str):
                                response_text += block
                    elif isinstance(content, str):
                        response_text = content

                    # Print thinking content if present
                    if thinking_text:
                        console.print(f"\n[magenta]🧠 Extended Thinking:[/magenta]")
                        # Truncate very long thinking
                        if len(thinking_text) > 1000:
                            console.print(thinking_text[:1000] + "...[truncated]")
                        else:
                            console.print(thinking_text)

                    # Print response content
                    if response_text:
                        has_tool_calls = hasattr(latest_msg, "tool_calls") and latest_msg.tool_calls
                        if has_tool_calls:
                            # This is reasoning before tool calls
                            console.print(f"\n[cyan]💭 Thinking:[/cyan]")
                            console.print(response_text)
                        else:
                            # Final response (no tool calls)
                            console.print("\n[bold green]Analysis Result:[/bold green]")
                            console.print(response_text)

                    # Extract token usage from AI message
                    usage = getattr(latest_msg, "usage_metadata", None)
                    if usage:
                        input_tokens = usage.get("input_tokens", 0)
                        output_tokens = usage.get("output_tokens", 0)
                        total_input_tokens += input_tokens
                        total_output_tokens += output_tokens
                        console.print(
                            f"[dim]   📊 Tokens: input={input_tokens}, "
                            f"output={output_tokens} "
                            f"(cumulative: {total_input_tokens}+{total_output_tokens}="
                            f"{total_input_tokens + total_output_tokens})[/dim]"
                        )

                    # Then show tool calls
                    if hasattr(latest_msg, "tool_calls") and latest_msg.tool_calls:
                        for tc in latest_msg.tool_calls:
                            console.print(
                                f"\n[yellow]🔧 Tool call:[/yellow] {tc['name']}"
                            )
                            # Print args if not too long
                            args_str = str(tc['args'])
                            if len(args_str) > 100:
                                args_str = args_str[:100] + "..."
                            console.print(f"   Args: {args_str}")

                elif msg_type == "tool":
                    # Tool result
                    content_len = len(latest_msg.content) if latest_msg.content else 0
                    tool_result_chars += content_len
                    # Rough token estimate: ~4 chars per token
                    est_tokens = content_len // 4
                    result_preview = latest_msg.content[:200] if latest_msg.content else ""
                    if content_len > 200:
                        result_preview += "..."
                    console.print(
                        f"[dim]   → Result ({content_len} chars, ~{est_tokens} tokens): "
                        f"{result_preview}[/dim]"
                    )

        # Print token summary
        console.print("\n" + "=" * 60)
        console.print("[bold]Token Usage Summary[/bold]")
        console.print("=" * 60)
        console.print(f"  LLM Input tokens:  {total_input_tokens:,}")
        console.print(f"  LLM Output tokens: {total_output_tokens:,}")
        console.print(f"  Tool result chars: {tool_result_chars:,} (~{tool_result_chars // 4:,} tokens)")
        console.print(f"  [bold]Total LLM tokens:   {total_input_tokens + total_output_tokens:,}[/bold]")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠[/yellow] Interrupted by user")

    finally:
        # Cleanup via static engine
        if static_engine:
            static_engine.cleanup_all()


def main():
    parser = argparse.ArgumentParser(
        description="Plain LLM demo for binary TLS security analysis (with IDA Pro MCP)"
    )
    parser.add_argument(
        "binary_path",
        type=Path,
        help="Path to the binary file to analyze",
    )
    parser.add_argument(
        "-m",
        "--model",
        required=True,
        help="LLM model in format 'provider:model_name' (e.g., deepseek:deepseek-chat)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key for the LLM provider (overrides llm_config.yaml)",
    )

    args = parser.parse_args()

    # Validate binary path
    if not args.binary_path.exists():
        console.print(f"[red]Error:[/red] Binary not found: {args.binary_path}")
        sys.exit(1)

    console.print(f"[bold]Binary:[/bold] {args.binary_path}")
    console.print(f"[bold]Model:[/bold] {args.model}")

    # Run async analysis
    try:
        asyncio.run(run_analysis(args.binary_path, args.model, args.api_key))
    except ConfigurationError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise


if __name__ == "__main__":
    main()
