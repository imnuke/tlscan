#!/usr/bin/env python3
"""Plain LLM demo for dataflow analysis with IDA Pro MCP.

This demo shows baseline LLM+tools performance on dataflow analysis
WITHOUT structured output or security rules - just a simple prompt and IDA Pro tools.

The LLM is given tools to explore the binary and must autonomously
trace the source of a specified variable.

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
from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console

from tlscan.analyzer.static_engine.ida.ports import PortManager
from tlscan.analyzer.static_engine.ida.server import start_headless_ida_server
from tlscan.analyzer.agents.core.middleware import handle_tool_errors
from tlscan.config.loader import ConfigurationError, LLMConfig

console = Console()

# Simple prompt without security rules or structured output
SYSTEM_PROMPT = """You are a binary analyst performing dataflow analysis.
Use the available IDA Pro tools to trace the source of a variable.
Start from the specified function and variable, trace backward through
assignments to find where the value originates (constant, config file,
environment variable, function parameter, etc.).
"""


def build_user_prompt(
    variable: str,
    function: str,
    function_address: str | None = None,
    usage_address: str | None = None,
) -> str:
    """Build the user prompt for dataflow analysis."""
    # Base prompt
    if function_address:
        prompt = f"Trace the source of variable '{variable}' in function '{function}' at address {function_address}.\n"
    else:
        prompt = f"Trace the source of variable '{variable}' in function '{function}'.\n"

    # Add usage context if provided
    if usage_address:
        prompt += f"\nNote: The variable is used at {usage_address}. Only trace assignments before this point.\n"

    # Add guidance
    prompt += """
Find where this variable's value comes from - it could be:
- A constant/literal value
- Read from a config file
- An environment variable
- A command-line argument
- A parameter from an external caller

Report your findings including the complete trace path from the variable to its source.
"""
    return prompt


def create_llm(model_spec: str, config: LLMConfig):
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
            api_key=provider_config["api_key"],
            base_url=provider_config.get("api_base", "https://api.deepseek.com"),
            temperature=0,
        )
    elif provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name,
            api_key=provider_config["api_key"],
            temperature=0,
        )
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model_name,
            api_key=provider_config["api_key"],
            temperature=0,
        )
    elif provider == "qwen":
        from langchain_qwq import ChatQwen

        return ChatQwen(
            model=model_name,
            api_key=provider_config["api_key"],
            api_base=provider_config["api_base"],
            temperature=0,
        )
    else:
        raise ValueError(f"Unknown provider: {provider}")


async def run_analysis(
    binary_path: Path,
    variable: str,
    function: str,
    model_spec: str,
    function_address: str | None = None,
    usage_address: str | None = None,
    port: int | None = None,
):
    """Run dataflow analysis on a binary."""
    server_process = None
    allocated_port = None
    port_manager = None

    try:
        # Load LLM config
        config = LLMConfig()
        llm = create_llm(model_spec, config)

        # Allocate port if not specified
        if port is None:
            port_manager = PortManager()
            port_manager.cleanup_stale_locks()
            allocated_port = port_manager.allocate_port(str(binary_path))
            port = allocated_port
            console.print(f"[cyan]Allocated port: {port}[/cyan]")

        # Start IDA Pro MCP server
        console.print()
        server_process = start_headless_ida_server(str(binary_path), port=port)

        # Connect to MCP server
        console.print(f"\n[cyan]Connecting to MCP server...[/cyan]")
        server_config = {
            "ida": {
                "transport": "sse",
                "url": f"http://localhost:{port}/sse"
            }
        }
        mcp_client = MultiServerMCPClient(server_config)
        tools = await mcp_client.get_tools()
        console.print(f"[green]Connected, got {len(tools)} tools[/green]")

        # List available tools
        console.print("\n[bold]Available tools:[/bold]")
        for tool in tools:
            console.print(f"  - {tool.name}")

        # Create agent with tools
        console.print(f"\n[cyan]Creating agent with model: {model_spec}[/cyan]")
        llm_with_tools = llm.bind_tools(tools)
        agent = create_agent(
            model=llm_with_tools,
            tools=tools,
            middleware=[handle_tool_errors],
            system_prompt=SYSTEM_PROMPT
        )

        # Build user prompt
        user_prompt = build_user_prompt(
            variable=variable,
            function=function,
            function_address=function_address,
            usage_address=usage_address,
        )

        # Run analysis
        console.print("\n" + "=" * 60)
        console.print("[bold]Starting Dataflow Analysis[/bold]")
        console.print("=" * 60)
        console.print(f"\n[bold]Target:[/bold]")
        console.print(f"  Variable: {variable}")
        console.print(f"  Function: {function}")
        if function_address:
            console.print(f"  Function address: {function_address}")
        if usage_address:
            console.print(f"  Usage address: {usage_address}")
        console.print()

        messages = [HumanMessage(content=user_prompt)]

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
                        console.print(f"\n[magenta]Extended Thinking:[/magenta]")
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
                            console.print(f"\n[cyan]Thinking:[/cyan]")
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
                            f"[dim]   Tokens: input={input_tokens}, "
                            f"output={output_tokens} "
                            f"(cumulative: {total_input_tokens}+{total_output_tokens}="
                            f"{total_input_tokens + total_output_tokens})[/dim]"
                        )

                    # Then show tool calls
                    if hasattr(latest_msg, "tool_calls") and latest_msg.tool_calls:
                        for tc in latest_msg.tool_calls:
                            console.print(
                                f"\n[yellow]Tool call:[/yellow] {tc['name']}"
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
                        f"[dim]   -> Result ({content_len} chars, ~{est_tokens} tokens): "
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
        console.print("\n[yellow]Interrupted by user[/yellow]")

    finally:
        # Cleanup
        if server_process:
            console.print("\n[cyan]Cleaning up IDA server...[/cyan]")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except Exception:
                server_process.kill()

            # Close log file if exists
            if hasattr(server_process, '_log_file'):
                try:
                    server_process._log_file.close()
                except Exception:
                    pass

        if allocated_port and port_manager:
            port_manager.release_port(allocated_port)
            console.print(f"[green]Released port {allocated_port}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Plain LLM demo for dataflow analysis (with IDA Pro MCP)"
    )
    parser.add_argument(
        "binary_path",
        type=Path,
        help="Path to the binary file to analyze",
    )
    parser.add_argument(
        "-v", "--variable",
        required=True,
        help="Variable name to trace (e.g., 'verify_mode', 'a2')",
    )
    parser.add_argument(
        "-f", "--function",
        required=True,
        help="Function name where the variable is located",
    )
    parser.add_argument(
        "--function-address",
        default=None,
        help="Hex address of the function (e.g., '0x401234')",
    )
    parser.add_argument(
        "--usage-address",
        default=None,
        help="Address where the variable is used (restricts trace)",
    )
    parser.add_argument(
        "-m", "--model",
        required=True,
        help="LLM model in format 'provider:model_name' (e.g., deepseek:deepseek-chat)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="MCP server port (default: auto-allocate)",
    )

    args = parser.parse_args()

    # Validate binary path
    if not args.binary_path.exists():
        console.print(f"[red]Error:[/red] Binary not found: {args.binary_path}")
        sys.exit(1)

    console.print(f"[bold]Binary:[/bold] {args.binary_path}")
    console.print(f"[bold]Model:[/bold] {args.model}")
    console.print(f"[bold]Variable:[/bold] {args.variable}")
    console.print(f"[bold]Function:[/bold] {args.function}")

    # Run async analysis
    try:
        asyncio.run(run_analysis(
            args.binary_path,
            args.variable,
            args.function,
            args.model,
            function_address=args.function_address,
            usage_address=args.usage_address,
            port=args.port,
        ))
    except ConfigurationError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise


if __name__ == "__main__":
    main()
