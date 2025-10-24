import os
import sys
import json
import asyncio
import argparse
from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain_core.messages import ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console
from rich.markdown import Markdown, Heading
from rich.panel import Panel
from rich import box

# multiple agents:
# - function and variable renaming agent
# - ssl security analysis agent

# Initialize Rich console for beautiful output
console = Console()

# Global flag to track connection failures
connection_failed = False

# Custom Heading class with left alignment instead of center
class LeftAlignedHeading(Heading):
    """Custom heading that renders left-aligned instead of centered."""

    def __rich_console__(self, console, options):
        text = self.text
        text.justify = "left"  # Changed from "center" to "left"
        if self.tag == "h1":
            # Draw a border around h1s
            yield Panel(
                text,
                box=box.HEAVY,
                style="markdown.h1.border",
            )
        else:
            # Styled text for h2 and beyond
            if self.tag == "h2":
                from rich.text import Text
                yield Text("")
            yield text

def create_markdown(content: str) -> Markdown:
    """Create a Markdown instance with left-aligned headings."""
    md = Markdown(content)
    # Override the heading element to use our custom left-aligned version
    md.elements["heading_open"] = LeftAlignedHeading
    return md

@wrap_tool_call
async def handle_tool_errors(request, handler):
    """Handle tool execution errors gracefully without terminating the workflow."""
    global connection_failed

    try:
        return await handler(request)
    except Exception as e:
        error_str = str(e)

        # Check if this is a connection refused error (MCP server not running)
        if isinstance(e, ConnectionRefusedError) or "[Errno 111] Connection refused" in error_str:
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

async def main(function_name: str = "sub_4124E3", model: str = "deepseek-chat"):
    """
    Main function to analyze SSL/TLS connections.

    Args:
        function_name: Name of the function to analyze (default: "sub_4124E3")
        model: LLM model to use (default: "deepseek-chat")
    """
    connection_type = 'stdio'
    server_script = '/home/peng/Projects/others/ida-pro-mcp/src/ida_pro_mcp/server.py'
    try:
        if connection_type == 'stdio':
            server_config = {
                "idapro": {
                    "transport": "stdio",
                    "command": "python",
                    "args": [
                        server_script
                    ]
                }
            }
        else:
            server_config = {
                "idapro": {
                    "transport": "sse",
                    "url": "http://localhost:8745/sse"
                }
            }

        client = MultiServerMCPClient(server_config)

        tools = await client.get_tools()
        console.print(f"[green]✓[/green] Successfully loaded [bold]{len(tools)}[/bold] tools from MCP server")
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to connect to MCP server: {e}")
        console.print("[yellow]Using fallback tools instead...[/yellow]")
        tools = []

    agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are a helpful assistant with access to IDA Pro tools. "
            "Help users analyze code, rename variables, explain functions, and more.\n\n"
            "IMPORTANT GUIDELINES:\n"
            "1. Use IDA Pro tools strategically to gather information needed to answer questions\n"
            "2. After gathering sufficient information, synthesize your findings into a clear answer\n"
            "3. Avoid calling the same tool repeatedly with similar parameters\n"
            "4. If you cannot find what you're looking for after 3-5 tool calls, explain what you found and what might be missing\n"
            "5. Always provide a final answer based on the information gathered, even if incomplete\n"
            "6. Focus on answering the user's specific question rather than exhaustively exploring the binary\n"
            "7. If a tool returns an error, try alternative approaches or work with the information you have"
        )
    )

    # TODO: rule: called function but not properly checked the result

    rules = (
        "Default verification (RECOMMENDED): Default verification should be performed using SSL_CTX_set_verify or equivalent custom code.\n"
        "Hostname verification (MUST): Hostname verification should be performed using X509_check_host or equivalent custom code.\n"
        "Result checking (MUST): When SSL_CTX_set_verify or SSL_set_verify sets SSL_VERIFY_NONE(0), SSL_get_verify_result must be called to check the verification status.\n"
        "Certificate expiration (RECOMMENDED): Certificate expiration checks should be implemented using X509_get_notAfter or equivalent custom code.\n"
        "Certificate revocation (RECOMMENDED): Certificate revocation checks should be implemented using OCSP or CRL checks.\n"
    )

    oneshot_example = (
        "The output should be like this:\n\n"

        "Connection establishing flow: \n"
        "- upscli_init (0x5b96): creates ssl_ctx via TLS_client_method/SSL_CTX_new, calls SSL_CTX_load_verify_locations when a CA path is provided, and calls SSL_CTX_set_verify(ssl_ctx, (_DWORD)a1 != 0, 0).\n"
        "    - Code lines of interest (decompiled):\n"
        "       - SSL_CTX_load_verify_locations(ssl_ctx, 0, a2) if a2 != 0\n"
        "       - SSL_CTX_set_verify(ssl_ctx, (_DWORD)a1 != 0, 0)\n"
        "- upscli_sslinit (0x6465): performs STARTTLS, then SSL_new(ssl_ctx), SSL_set_fd, then calls:\n"
        "    - if (a2) SSL_set_verify(ssl, 1, 0);\n"
        "    - else SSL_set_verify(ssl, 0, 0);\n"
        "    - then calls SSL_connect and returns based on the SSL_connect result.\n"
        "- upscli_tryconnect (0x6796): decides whether to call upscli_sslinit based on configuration/flags; logs \"Certificate verification is disabled\" when verification flag is false.\n"
        "- upscli_add_host_cert and upscli_find_host_cert are stubs (no-op / return 0), so there is no per-host certificate pinning implemented.\n"

        "Rule checks performed:\n"
        "Hostname verification (MUST):\n"
        "- Findings:\n"
        "  - No call to X509_check_host, X509_check_cert or any hostname check exists in the codebase I could find. Search for \"X509\" and \"X509_check_host\" returned nothing."
        "  - After SSL_connect the code does not extract the peer certificate and check the certificate's subject/SAN against the server hostname. So it does not perform hostname verification — this violates the MUST."
        "Result checking (MUST): When SSL_CTX_set_verify or SSL_set_verify sets SSL_VERIFY_NONE(0), SSL_get_verify_result must be called to check the verification status"
        "- Findings:\n"
        "  - The code uses SSL_CTX_set_verify(..., mode, 0) and per-connection SSL_set_verify(..., mode, 0). When mode is 0 the code effectively disables verification."
        "  - There is no use/import of SSL_get_verify_result in the binary (no symbol and no string usage)"
        "The code does not call SSL_get_verify_result after SSL_connect to check the verification result even in the branch where verification is enabled. Therefore it does not explicitly check verification status after the handshake — this violates the MUST (no verification result check is done)."

        "More dependencies need to be checked:\n"
        "- upscli_init receives parameters a1 and a2: a2 is used as the CA path passed to SSL_CTX_load_verify_locations; a1 controls the boolean passed to SSL_CTX_set_verify."
        "- upscli_tryconnect uses flags (a4 and host_cert) to decide whether to perform SSL at all and whether to require verification. The log lines show that verification is enabled/disabled by configuration flags (and host_cert would influence this)."

        "Results Summary (in table):\n"
        "| Rule | Status |\n"
        "|------|--------|\n"
        "| Hostname verification | Violation |\n"
        "| Result checking | Violation on condition |\n"

        "Additional observations:\n"
        "<Any other relevant findings or notes>"
    )

    # TODO: The LLM should ask for external file access if needed.

    user_prompt = (
        f"There is a network connection established from function {function_name}, "
        "I need you to analyze it and tell me if the code violates any SSL/TLS security best practices based on the following rules:\n"
        + rules + 
        "If there are custom implementations of these checks, explain how they work in detail.\n"
        "If the security relies on external information like config file or command-line arguments, please mention it.\n"
        + oneshot_example
    )

    console.print(Panel.fit("[bold cyan]Starting Agent Execution[/bold cyan]", border_style="cyan"))
    console.print()

    async for chunk in agent.astream(
        {"messages": [{"role": "user", "content": user_prompt}]},
        stream_mode="values",
        config={"recursion_limit": 50}
    ):
        # Check if connection failed - terminate immediately
        if connection_failed:
            break

        # Get the last message in the current state
        if "messages" in chunk and chunk["messages"]:
            last_message = chunk["messages"][-1]

            # Check if it's an AI message with tool calls
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                console.print("[bold magenta]🔧 TOOL CALLS:[/bold magenta]")
                for tool_call in last_message.tool_calls:
                    console.print(f"  • [cyan]{tool_call['name']}[/cyan]")
                    console.print(f"    [dim]Args: {json.dumps(tool_call['args'], indent=6)}[/dim]")
                console.print()

            # Check if it's a tool message (result)
            elif hasattr(last_message, "type") and last_message.type == "tool":
                # Check if it's an error result
                if hasattr(last_message, "status") and last_message.status == "error":
                    console.print(f"[bold yellow]⚠️  TOOL ERROR ({last_message.name}):[/bold yellow]")
                    console.print(f"  [yellow]{last_message.content}[/yellow]")
                else:
                    console.print(f"[bold green]📊 TOOL RESULT ([cyan]{last_message.name}[/cyan]):[/bold green]")
                    console.print(f"  [dim]{last_message.content[:500]}...[/dim]")  # Show first 500 chars
                console.print()

            # Check if it's an AI message with content (thinking)
            elif hasattr(last_message, "content") and last_message.content and hasattr(last_message, "type") and last_message.type == "ai":
                if last_message.content.strip():
                    console.print("[bold blue]💭 LLM THINKING:[/bold blue]")
                    # Render markdown content with left-aligned headings
                    md = create_markdown(last_message.content)
                    console.print(md)
                    console.print()

    console.print()
    # Show different message based on whether we terminated early
    if connection_failed:
        console.print(Panel.fit("[bold red]✗ Agent Execution Terminated[/bold red]", border_style="red"))
    else:
        console.print(Panel.fit("[bold green]✓ Agent Execution Complete[/bold green]", border_style="green"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze SSL/TLS connections in binary functions using IDA Pro MCP tools"
    )
    parser.add_argument(
        "-f", "--function",
        type=str,
        default="sub_4124E3",
        help="Name of the function to analyze (default: sub_4124E3)"
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default="deepseek-chat",
        help="LLM model to use (default: deepseek-chat). Examples: openai:gpt-4o, anthropic:claude-sonnet-4-5, deepseek-chat"
    )
    args = parser.parse_args()

    asyncio.run(main(args.function, args.model))
