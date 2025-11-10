"""
Agent middleware.

Provides error handling and retry logic for agent tool calls.
"""

import asyncio
import httpx
from langchain_core.messages import ToolMessage
from langchain.agents.middleware import wrap_tool_call
from rich.console import Console
from rich.panel import Panel

# Initialize console
console = Console()

# Global flag to track connection failures
connection_failed = False


@wrap_tool_call
async def handle_tool_errors(request, handler):
    """Handle tool execution errors gracefully with timeout retry logic."""
    global connection_failed

    max_retries = 3
    for attempt in range(max_retries):
        try:
            return await handler(request)
        except (asyncio.TimeoutError, httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            # Timeout error - retry with exponential backoff
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # 1s, 2s, 4s
                console.print(f"[yellow]⚠️  Timeout on attempt {attempt + 1}/{max_retries}, retrying in {wait_time}s...[/yellow]")
                await asyncio.sleep(wait_time)
                continue
            else:
                # Final attempt failed - fatal error
                tool_name = request.tool_call.get('name', 'unknown')
                error_msg = f"Tool execution timed out after {max_retries} attempts"
                console.print()
                console.print(Panel(
                    f"[bold red]✗ Timeout Error[/bold red]\n\n"
                    f"The operation timed out after {max_retries} retry attempts.\n"
                    f"Tool: {tool_name}\n"
                    f"Error: {str(e)}\n\n"
                    "This may indicate:\n"
                    "- The binary is too large or complex for analysis\n"
                    "- IDA Pro is taking too long to process the request\n"
                    "- The MCP server is overloaded\n\n"
                    "Terminating analysis...",
                    border_style="red",
                    title="[bold]MCP Timeout Error[/bold]"
                ))
                console.print()
                raise  # Fatal - stop analysis
        except ConnectionRefusedError as e:
            # Connection refused error
            connection_failed = True
            console.print()
            console.print(Panel(
                "[bold red]✗ Connection Refused[/bold red]\n\n"
                "The MCP server is not running. Please start it by:\n"
                "1. Opening IDA Pro\n"
                "2. Going to Edit → Plugins → MCP (Ctrl+Alt+M)\n"
                "3. Starting the server\n\n"
                "Terminating agent execution...",
                border_style="red",
                title="[bold]MCP Server Error[/bold]"
            ))
            console.print()
            return ToolMessage(
                content="Connection refused - MCP server is not running. Please start the server and try again.",
                tool_call_id=request.tool_call["id"],
                status="error"
            )
        except Exception as e:
            error_str = str(e)

            # Check for timeout in error string (fallback detection)
            if "timeout" in error_str.lower() or "timed out" in error_str.lower():
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    console.print(f"[yellow]⚠️  Timeout detected in error message, retrying in {wait_time}s...[/yellow]")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    # Final attempt failed - fatal error
                    tool_name = request.tool_call.get('name', 'unknown')
                    console.print()
                    console.print(Panel(
                        f"[bold red]✗ Timeout Error[/bold red]\n\n"
                        f"The operation timed out after {max_retries} retry attempts.\n"
                        f"Tool: {tool_name}\n"
                        f"Error: {str(e)}\n\n"
                        "Terminating analysis...",
                        border_style="red",
                        title="[bold]MCP Timeout Error[/bold]"
                    ))
                    console.print()
                    raise  # Fatal - stop analysis

            # Check for connection refused in error string
            if "[Errno 111] Connection refused" in error_str:
                connection_failed = True
                console.print()
                console.print(Panel(
                    "[bold red]✗ Connection Refused[/bold red]\n\n"
                    "The MCP server is not running. Please start it by:\n"
                    "1. Opening IDA Pro\n"
                    "2. Going to Edit → Plugins → MCP (Ctrl+Alt+M)\n"
                    "3. Starting the server\n\n"
                    "Terminating agent execution...",
                    border_style="red",
                    title="[bold]MCP Server Error[/bold]"
                ))
                console.print()
                return ToolMessage(
                    content="Connection refused - MCP server is not running. Please start the server and try again.",
                    tool_call_id=request.tool_call["id"],
                    status="error"
                )

            # For other errors, continue as before
            error_msg = f"Tool execution failed: {str(e)}"
            console.print(f"[bold yellow]⚠️  TOOL ERROR:[/bold yellow] {error_msg}")
            return ToolMessage(
                content=error_msg,
                tool_call_id=request.tool_call["id"],
                status="error"
            )
