import os
import sys
import json
import re
import asyncio
import argparse
import subprocess
import time
import requests
import logging

# Suppress verbose HTTP logs from MCP client (SSE transport)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("mcp").setLevel(logging.WARNING)

from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain_core.messages import ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console
from rich.markdown import Markdown, Heading
from rich.panel import Panel
from rich import box

# Import firmware_tools BEFORE generate_call_graph
# (IDA modules modify sys.path and remove current directory)
import firmware_tools

from generate_call_graph import (
    IDABackend,
    export_to_json,
    draw_call_graph,
    ssl_function_patterns
)

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

def format_call_graph(call_graph_data: dict) -> str:
    """
    Format call graph data into a readable text representation.

    Args:
        call_graph_data: Dictionary containing call graph metadata, nodes, and edges

    Returns:
        Formatted string representation of the call graph
    """
    if not call_graph_data:
        return ""

    output = ["# Call Graph Information\n"]

    # Add metadata
    metadata = call_graph_data.get("metadata", {})
    output.append("## Metadata")
    output.append(f"- Binary: {metadata.get('binary', 'N/A')}")
    output.append(f"- Total functions: {metadata.get('node_count', 0)}")
    output.append(f"- Total call relationships: {metadata.get('edge_count', 0)}")

    ssl_patterns = metadata.get('ssl_patterns', [])
    if ssl_patterns:
        output.append(f"- SSL/TLS patterns: {', '.join(ssl_patterns)}")
    output.append("")

    # List all nodes
    nodes = call_graph_data.get("nodes", [])
    if nodes:
        output.append("## Nodes (Functions)")
        output.append(f"Total: {len(nodes)} functions")
        output.append("")
        for node in nodes:
            name = node.get("name", "")
            address = node.get("address", "")
            output.append(f"- {name} ({address})")
        output.append("")

    # List all edges
    edges = call_graph_data.get("edges", [])
    if edges:
        output.append("## Edges (Call Relationships)")
        output.append(f"Total: {len(edges)} edges")
        output.append("")
        for edge in edges:
            caller = edge.get("caller", "")
            callee = edge.get("callee", "")
            call_site = edge.get("call_site", "")
            output.append(f"- {caller} → {callee} (at {call_site})")
        output.append("")

    return "\n".join(output)

def load_security_rules(library_name: str = "openssl") -> str:
    """
    Load SSL/TLS security rules from markdown file.

    Args:
        library_name: Name of the SSL/TLS library (openssl, curl, libcurl, gnutls, mbedtls, php_curl, wget)

    Returns:
        Content of the rules file, or empty string if file not found
    """
    rule_file = os.path.join("security_rules", f"rule_{library_name}.md")

    if os.path.exists(rule_file):
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()
            console.print(f"[green]✓[/green] Loaded security rules from [bold]{rule_file}[/bold]")
            return content
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow]  Failed to load security rules from {rule_file}: {e}")
            return ""
    else:
        console.print(f"[yellow]⚠[/yellow]  Security rules file not found: {rule_file}")
        return ""

def start_headless_ida_server(binary_path: str, host: str = "localhost", port: int = 8745) -> subprocess.Popen:
    """
    Start headless IDA server process.

    Args:
        binary_path: Path to binary to analyze
        host: Server host (default: localhost)
        port: Server port (default: 8745)

    Returns:
        Server process handle
    """
    ida_pro_mcp_dir = '/home/peng/Projects/others/ida-pro-mcp'

    console.print(f"[cyan]⚙[/cyan]  Starting headless IDA server for [bold]{binary_path}[/bold]...")

    cmd = [
        "uv", "run",
        "--directory", ida_pro_mcp_dir,
        "idalib-mcp",
        "--host", host,
        "--port", str(port),
        binary_path
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait for server to be ready (poll SSE endpoint)
        url = f"http://{host}:{port}/sse"
        console.print(f"[cyan]⏳[/cyan]  Waiting for server at {url}...")

        for i in range(30):  # Wait up to 30 seconds
            # Check if process crashed
            if process.poll() is not None:
                # Process exited, capture output
                stdout, stderr = process.communicate()
                console.print(f"[bold red]✗[/bold red] Headless IDA server process exited with code {process.returncode}")
                console.print()
                if stderr:
                    console.print("[bold red]Server Error Output:[/bold red]")
                    console.print(Panel(stderr, border_style="red", title="stderr"))
                if stdout:
                    console.print("[bold yellow]Server Output:[/bold yellow]")
                    console.print(Panel(stdout, border_style="yellow", title="stdout"))
                raise RuntimeError(f"Headless IDA server failed to start (exit code {process.returncode})")

            time.sleep(1)
            try:
                response = requests.head(url, timeout=1)
                if response.status_code in [200, 405, 400]:  # Server responding
                    console.print(f"[green]✓[/green] Headless IDA server ready")
                    return process
            except requests.RequestException:
                pass

        # Timeout - check if process is still running
        if process.poll() is not None:
            # Process died during wait
            stdout, stderr = process.communicate()
            console.print(f"[bold red]✗[/bold red] Server process died during startup (exit code {process.returncode})")
            if stderr:
                console.print("[bold red]Error Output:[/bold red]")
                console.print(Panel(stderr, border_style="red"))
            if stdout:
                console.print("[bold yellow]Output:[/bold yellow]")
                console.print(Panel(stdout, border_style="yellow"))
            raise RuntimeError(f"Server process failed during startup (exit code {process.returncode})")
        else:
            # Still running but not responding
            process.terminate()
            console.print(f"[bold red]✗[/bold red] Server did not respond within 30 seconds (process still running)")
            console.print("[yellow]⚠[/yellow]  Check if port 8745 is already in use or server is slow to start")
            raise TimeoutError(f"Headless IDA server did not start within 30 seconds")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to start headless IDA server: {e}")
        raise

def prune_message_history(messages: list, max_recent: int = 5) -> list:
    """
    Keep recent messages and summarize older ones to save context.

    Strategy:
    - Keep: Initial user query + last N messages
    - For older messages: Keep AI synthesis, remove detailed tool results
    - Replace tool result content with summary to save tokens

    Args:
        messages: List of message objects
        max_recent: Number of recent messages to keep completely (default: 5)

    Returns:
        Pruned message list
    """
    if len(messages) <= max_recent + 1:
        # Not enough messages to prune
        return messages

    # Always keep first message (original user query)
    pruned = [messages[0]]

    # Process middle messages (between first and last N)
    middle_messages = messages[1:-max_recent]

    for msg in middle_messages:
        if hasattr(msg, "type"):
            if msg.type == "ai":
                # Keep AI synthesis messages, but create a copy without tool_calls details
                pruned.append(msg)
            elif msg.type == "tool":
                # Replace tool result content with summary
                from langchain_core.messages import ToolMessage
                summary_content = f"[Tool result cleared for context management - Tool: {msg.name}]"
                pruned.append(ToolMessage(
                    content=summary_content,
                    tool_call_id=msg.tool_call_id if hasattr(msg, "tool_call_id") else "",
                    name=msg.name if hasattr(msg, "name") else ""
                ))
            elif msg.type == "human":
                # Keep human messages
                pruned.append(msg)

    # Keep last N messages completely intact (current working context)
    pruned.extend(messages[-max_recent:])

    return pruned

def cleanup_old_tool_results(messages: list, keep_last_n: int = 3) -> list:
    """
    Clear tool result content from older messages, keeping only recent ones.

    This is called after an agent synthesizes findings to reduce context usage.

    Args:
        messages: List of message objects
        keep_last_n: Number of most recent tool results to keep intact

    Returns:
        Cleaned message list
    """
    from langchain_core.messages import ToolMessage

    # Find all tool message indices
    tool_indices = []
    for i, msg in enumerate(messages):
        if hasattr(msg, "type") and msg.type == "tool":
            tool_indices.append(i)

    if len(tool_indices) <= keep_last_n:
        # Not enough tool results to clean
        return messages

    # Indices of tool results to clear (all except last N)
    clear_indices = set(tool_indices[:-keep_last_n])

    # Create new list with cleared tool results
    cleaned = []
    for i, msg in enumerate(messages):
        if i in clear_indices:
            # Replace this tool result with summary
            summary_content = f"[Tool result cleared - Tool: {msg.name if hasattr(msg, 'name') else 'unknown'}]"
            cleaned.append(ToolMessage(
                content=summary_content,
                tool_call_id=msg.tool_call_id if hasattr(msg, "tool_call_id") else "",
                name=msg.name if hasattr(msg, "name") else ""
            ))
        else:
            cleaned.append(msg)

    return cleaned

async def stream_and_log_agent(agent, messages: list, agent_name: str, agent_emoji: str = "🤖", config: dict = None) -> str:
    """
    Stream an agent's execution and log all intermediate steps.

    Args:
        agent: The agent to execute
        messages: List of messages to send to the agent
        agent_name: Display name of the agent (e.g., "Dataflow Agent")
        agent_emoji: Emoji to use for this agent (e.g., "🔍")
        config: Optional config dict for the agent

    Returns:
        The final AI message content
    """
    global connection_failed

    # Print agent header
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]{agent_emoji} {agent_name} Executing[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    # Prune message history if it's getting long to save context
    if len(messages) > 10:
        original_count = len(messages)
        messages = prune_message_history(messages, max_recent=5)
        console.print(f"[dim]  ℹ  Message history pruned: {original_count} → {len(messages)} messages (context management)[/dim]")
        console.print()

    final_content = ""
    config = config or {"recursion_limit": 100}

    async for chunk in agent.astream(
        {"messages": messages},
        stream_mode="values",
        config=config
    ):
        # Check if connection failed - terminate immediately
        if connection_failed:
            break

        # Get the last message in the current state
        if "messages" in chunk and chunk["messages"]:
            last_message = chunk["messages"][-1]

            # Check if it's an AI message with tool calls
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                console.print(f"[bold magenta]🔧 {agent_name} TOOL CALLS:[/bold magenta]")
                for tool_call in last_message.tool_calls:
                    console.print(f"  • [cyan]{tool_call['name']}[/cyan]")
                    console.print(f"    [dim]Args: {json.dumps(tool_call['args'], indent=6)}[/dim]")
                console.print()

            # Check if it's a tool message (result)
            elif hasattr(last_message, "type") and last_message.type == "tool":
                # Check if it's an error result
                if hasattr(last_message, "status") and last_message.status == "error":
                    console.print(f"[bold yellow]⚠️  {agent_name} TOOL ERROR ({last_message.name}):[/bold yellow]")
                    console.print(f"  [yellow]{last_message.content}[/yellow]")
                else:
                    console.print(f"[bold green]📊 {agent_name} TOOL RESULT ([cyan]{last_message.name}[/cyan]):[/bold green]")
                    content_preview = last_message.content[:500] if len(last_message.content) > 500 else last_message.content
                    console.print(f"  [dim]{content_preview}{'...' if len(last_message.content) > 500 else ''}[/dim]")
                console.print()

            # Check if it's an AI message with content (thinking)
            elif hasattr(last_message, "content") and last_message.content and hasattr(last_message, "type") and last_message.type == "ai":
                if last_message.content.strip():
                    console.print(f"[bold blue]💭 {agent_name} THINKING:[/bold blue]")
                    # Render markdown content with left-aligned headings
                    md = create_markdown(last_message.content)
                    console.print(md)
                    console.print()
                    final_content = last_message.content

    console.print(Panel.fit(
        f"[bold green]✓ {agent_name} Complete[/bold green]",
        border_style="green"
    ))
    console.print()

    return final_content

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

# Global agent instances - will be initialized in main()
supervisor_agent = None
dataflow_agent = None
firmware_traverse_agent = None

# Tool wrappers for supervisor to call worker agents
@tool
async def call_dataflow_agent(request: str, context: str = "") -> str:
    """
    Perform dataflow analysis (forward/backward slicing, inter-procedural).

    Use this tool to trace:
    - Where a variable's value flows TO (forward slicing)
    - Where a variable's value comes FROM (backward slicing)
    - Dataflow across function boundaries (inter-procedural analysis)

    Args:
        request: Specific dataflow analysis question
        context: Relevant code/function information from IDA for analysis

    Returns:
        Dataflow analysis results with sources, sinks, and paths
    """
    full_request = f"{request}\n\nContext:\n{context}" if context else request
    result = await stream_and_log_agent(
        agent=dataflow_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Dataflow Analysis Agent",
        agent_emoji="🔍"
    )
    return result

@tool
async def call_firmware_agent(request: str, context: str = "") -> str:
    """
    Analyze firmware filesystem: config files, cross-binary relationships, scripts.

    Use this tool to:
    - Find which binary defines/calls a function (cross-binary analysis)
    - Read configuration files that might affect SSL/TLS behavior
    - Search for strings/patterns in firmware files
    - Analyze startup scripts or shell scripts that configure services

    Args:
        request: Firmware analysis question (what to find/analyze)
        context: Relevant context from IDA analysis (function names, addresses, etc.)

    Returns:
        Analysis results from firmware filesystem exploration
    """
    full_request = f"{request}\n\nContext:\n{context}" if context else request
    result = await stream_and_log_agent(
        agent=firmware_traverse_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Firmware Filesystem Agent",
        agent_emoji="📁"
    )
    return result

def generate_call_graph_for_binary(binary_path: str, output_json_path: str = "temp_files/call_graph.json", enable_ida_msg: bool = False) -> dict:
    """
    Generate call graph for SSL/TLS functions in the binary.

    Args:
        binary_path: Path to the binary file to analyze
        output_json_path: Path to output JSON file (default: "temp_files/call_graph.json")
        enable_ida_msg: Enable IDA console messages (default: False)

    Returns:
        Call graph data as dictionary

    Raises:
        RuntimeError: If call graph generation fails
    """
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]📊 Generating Call Graph[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    backend = None
    try:
        # Initialize IDA backend (opens database)
        console.print(f"[cyan]⚙[/cyan]  Opening binary with IDA: [bold]{binary_path}[/bold]...")
        backend = IDABackend(binary_path, enable_ida_msg=enable_ida_msg)

        # Filter SSL/TLS functions
        console.print("[cyan]🔍[/cyan]  Filtering SSL/TLS functions...")
        pattern = re.compile("|".join(ssl_function_patterns))
        all_functions = backend.get_func_list_in_name()
        ssl_functions = [f for f in all_functions if pattern.search(f)]
        console.print(f"[green]✓[/green] Found [bold]{len(ssl_functions)}[/bold] SSL/TLS functions")

        if ssl_functions:
            console.print(f"[dim]   Functions: {', '.join(ssl_functions[:5])}{'...' if len(ssl_functions) > 5 else ''}[/dim]")

        # Generate call graph
        console.print("[cyan]🕸[/cyan]  Generating call graph...")
        call_graph = backend.generate_call_graph(filtered_functions=ssl_functions)
        console.print(f"[green]✓[/green] Call graph generated: [bold]{len(call_graph.nodes)}[/bold] nodes, [bold]{len(call_graph.edges)}[/bold] edges")

        # Export to JSON
        console.print(f"[cyan]💾[/cyan]  Exporting to [bold]{output_json_path}[/bold]...")
        export_to_json(call_graph, binary_path, output_json_path)
        console.print(f"[green]✓[/green] Exported to JSON")

        # Draw PDF
        pdf_path = output_json_path.replace('.json', '.pdf')
        console.print(f"[cyan]🎨[/cyan]  Drawing call graph to [bold]{pdf_path}[/bold]...")
        draw_call_graph(call_graph, output_file=pdf_path, highlight_nodes=ssl_functions)
        console.print(f"[green]✓[/green] PDF visualization created")

        # Load the generated JSON to return
        with open(output_json_path, 'r') as f:
            call_graph_data = json.load(f)

        console.print()
        console.print(Panel.fit(
            f"[bold green]✓ Call Graph Generation Complete[/bold green]",
            border_style="green"
        ))
        console.print()

        return call_graph_data

    except Exception as e:
        console.print()
        console.print(Panel(
            f"[bold red]✗ Call Graph Generation Failed[/bold red]\n\n{str(e)}",
            border_style="red",
            title="[bold]Error[/bold]"
        ))
        console.print()
        raise RuntimeError(f"Failed to generate call graph: {e}")

    finally:
        # CRITICAL: Close IDA database before MCP server starts
        if backend is not None:
            console.print("[cyan]🔒[/cyan]  Closing IDA database...")
            del backend
            console.print("[green]✓[/green] Database closed")
            console.print()

async def main(file_path: str, model: str = "deepseek-chat", conn_type: str = "plugin", call_graph_path: str = "call_graph.json", firmware_path: str = None, rules: str = "openssl"):
    """
    Main function to analyze SSL/TLS connections using multi-agent system.

    Args:
        model: LLM model to use (default: "deepseek-chat")
        call_graph_path: Path to call graph JSON file (default: "call_graph.json")
        firmware_path: Path to firmware filesystem root (optional, enables firmware agent)
        rules: SSL/TLS library rules to use (default: "openssl")
    """
    # Load security rules for the specified library
    security_rules_content = load_security_rules(rules)

    # Generate or load call graph based on connection type
    call_graph_data = None
    server_process = None  # Track server process for cleanup
    server_script = '/home/peng/Projects/others/ida-pro-mcp/src/ida_pro_mcp/server.py'

    try:
        if conn_type == 'headless_ida':
            # Generate call graph BEFORE starting MCP server
            # (Both use idalib and can't run simultaneously)
            try:
                call_graph_data = generate_call_graph_for_binary(
                    binary_path=file_path,
                    output_json_path=call_graph_path,
                    enable_ida_msg=False
                )
            except Exception as e:
                console.print(f"[bold red]✗[/bold red] Cannot continue without call graph. Exiting.")
                raise

            # Now start headless IDA server (database is closed from graph generation)
            # Auto-start headless IDA server
            server_process = start_headless_ida_server(file_path)

            server_config = {
                "idapro": {
                    "transport": "sse",
                    "url": "http://localhost:8745/sse"
                }
            }
        elif conn_type == 'plugin':
            # Use IDA GUI plugin (manual startup required)
            # Load call graph from existing file (user should generate separately)
            if call_graph_path and os.path.exists(call_graph_path):
                try:
                    with open(call_graph_path, 'r') as f:
                        call_graph_data = json.load(f)
                    console.print(f"[green]✓[/green] Loaded call graph from [bold]{call_graph_path}[/bold]")
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow]  Failed to load call graph: {e}")
            elif call_graph_path:
                console.print(f"[yellow]⚠[/yellow]  Call graph file not found: {call_graph_path}")
                console.print(f"[dim]   ℹ  Run generate_call_graph.py separately or use --conn-type=headless_ida for auto-generation[/dim]")

            server_config = {
                "idapro": {
                    "transport": "stdio",
                    "command": "python",
                    "args": [server_script]
                }
            }
        else:
            raise ValueError(f"Invalid connection type: {conn_type}")

        client = MultiServerMCPClient(server_config)
        tools = await client.get_tools()
        console.print(f"[green]✓[/green] Successfully loaded [bold]{len(tools)}[/bold] tools from MCP server")

    except Exception as e:
        if server_process:
            console.print("[yellow]⚠[/yellow]  Terminating headless server due to error...")
            server_process.terminate()
            server_process.wait()
        console.print(f"[bold red]✗[/bold red] Failed to connect to MCP server: {e}")
        console.print("[bold red]✗[/bold red] Cannot continue without MCP tools. Exiting.")
        raise  # Re-raise exception to terminate

    # Initialize all agents
    global dataflow_agent, supervisor_agent, firmware_traverse_agent

    # 1. Dataflow Analysis Agent - performs slicing and dataflow analysis
    dataflow_agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are a dataflow analysis expert with direct access to IDA Pro MCP tools. "
            "Your specialization is program slicing, taint analysis, and tracking how data flows through binaries.\n\n"
            "IDA TOOLS AVAILABLE:\n"
            "You have direct access to all IDA Pro tools to query the binary as needed:\n"
            "- Get function details, decompilation, disassembly\n"
            "- Find cross-references (xrefs), callers, and callees\n"
            "- Search for functions, strings, and globals\n"
            "- Analyze structures, variables, and data types\n\n"
            "DATAFLOW CAPABILITIES:\n"
            "- Forward slicing: Track where a variable's value flows TO (uses/dependencies downstream)\n"
            "- Backward slicing: Track where a variable comes FROM (sources/definitions upstream)\n"
            "- Inter-procedural analysis: Track dataflow across function boundaries\n"
            "- Identify data sources: Config files, command-line args, function parameters, globals\n\n"
            "ANALYSIS APPROACH:\n"
            "1. Use IDA tools to get function code and understand the context\n"
            "2. Identify the variable/parameter of interest\n"
            "3. Trace backward to find all possible sources (assignments, parameters, returns)\n"
            "4. Trace forward to find all uses and propagations\n"
            "5. Track across function calls using IDA's caller/callee tools\n"
            "6. Distinguish between:\n"
            "   - Direct dataflow (assignment, parameter passing)\n"
            "   - Control-flow dependencies (conditionals, loops)\n"
            "   - Aliasing (pointers, references)\n\n"
            "OUTPUT FORMAT:\n"
            "- List all dataflow paths clearly with addresses and function names\n"
            "- Identify ultimate sources (config, argv, stdin, network, etc.)\n"
            "- Highlight security-relevant flows\n"
            "- Note any ambiguities or limitations in the analysis"
        )
    )

    # Conditionally create firmware agent if firmware path provided
    if firmware_path:
        console.print(f"[green]✓[/green] Firmware agent enabled (path: [bold]{firmware_path}[/bold])")

        # Initialize firmware tools with the firmware root path
        firmware_tools.set_firmware_root(firmware_path)

        # Get firmware analysis tools
        fw_tools = [
            firmware_tools.search_files_by_name,
            firmware_tools.search_files_by_content,
            firmware_tools.read_file,
            firmware_tools.list_binary_symbols,
            firmware_tools.find_binaries_with_symbol,
            firmware_tools.find_function_references
        ]

        firmware_traverse_agent = create_agent(
            model=model,
            tools=fw_tools,
            middleware=[handle_tool_errors],
            system_prompt=(
                f"You are a firmware filesystem expert specializing in cross-binary analysis, configuration files, and scripts. "
                f"Your role is to analyze firmware files at: {firmware_path}\n\n"
            "PRIMARY USE CASES:\n"
            "1. Cross-binary analysis: Trace functions across multiple binaries in the firmware\n"
            "2. Configuration analysis: Find and analyze config files that affect SSL/TLS behavior\n"
            "3. Script analysis: Examine startup/shell scripts that configure services\n\n"
            "TOOLS AND THEIR USES:\n"
            "1. search_files_by_name(pattern) - Find files by name/glob pattern\n"
            "   - Examples: '*.conf', 'libssl*', 'startup*'\n"
            "   - Use for: finding configs, scripts, specific binaries\n\n"
            "2. search_files_by_content(pattern, file_pattern=None) - Find files containing text/regex\n"
            "   - Examples: 'SSL_verify', 'verify.*=.*0', 'curl_easy_setopt'\n"
            "   - Use for: finding SSL keywords, config options, function calls\n\n"
            "3. read_file(path, start_line=None, end_line=None) - Read file contents\n"
            "   - Use for: reading configs, scripts, text files\n"
            "   - Supports line ranges for large files\n\n"
            "4. list_binary_symbols(path, symbol_filter=None) - List functions in binary (nm)\n"
            "   - Examples: list_binary_symbols('usr/lib/libssl.so', 'SSL_')\n"
            "   - Use for: finding what functions a binary defines/imports\n\n"
            "5. find_binaries_with_symbol(symbol_name, binary_pattern='*') - Cross-binary search\n"
            "   - Examples: find_binaries_with_symbol('SSL_verify_callback')\n"
            "   - Use for: finding which binary implements a function\n\n"
            "6. find_function_references(function_name) - Unified search (text + binaries)\n"
            "   - Use for: comprehensive function tracing across all firmware files\n\n"
            "ANALYSIS WORKFLOW:\n"
            "1. Start with search_files_by_name or search_files_by_content to find relevant files\n"
            "2. Use read_file to examine configuration files and scripts\n"
            "3. Use list_binary_symbols to analyze individual binaries\n"
            "4. Use find_binaries_with_symbol for cross-binary function tracing\n"
            "5. Use find_function_references for comprehensive analysis across all file types\n\n"
            "OUTPUT FORMAT:\n"
            "- File paths with line numbers (e.g., 'etc/ssl.conf:42')\n"
            "- Relevant excerpts with surrounding context (3-5 lines)\n"
            "- Binary relationships: 'binary_A imports SSL_verify from binary_B'\n"
            "- Security implications: How findings affect SSL/TLS security\n"
            "- Cross-references: 'Function X defined in libssl.so, called by httpd and ftpd'\n\n"
            "EXAMPLE SCENARIOS:\n"
            "- Finding config files: search_files_by_name('*.conf') → read_file('etc/ssl.conf')\n"
            "- Finding SSL settings: search_files_by_content('ssl_verify') → read_file to check values\n"
            "- Cross-binary trace: find_binaries_with_symbol('SSL_verify_callback') → shows which bins have it\n"
            "- Function analysis: find_function_references('SSL_CTX_set_verify') → full firmware trace\n"
            )
        )
    else:
        console.print(f"[dim]ℹ[/dim]  Firmware agent disabled (use --firmware-path to enable)")
        firmware_traverse_agent = None

    vulnerability_result_agent = create_agent(
        model=model,
        tools=[],
        middleware=[handle_tool_errors],
        system_prompt=(
        )
    )

    # Format call graph for system prompt if available
    call_graph_context = ""
    if call_graph_data:
        call_graph_text = format_call_graph(call_graph_data)
        call_graph_context = (
            "\n\nCALL GRAPH CONTEXT:\n"
            "Below is the call graph extracted from the binary showing SSL/TLS function usage and call relationships. "
            "Use this to guide your analysis and avoid unnecessary exploration.\n\n"
            + call_graph_text
        )

    # 3. Supervisor Agent - performs SSL analysis and coordinates dataflow analysis
    # Build supervisor tools list conditionally
    supervisor_tools = tools + [call_dataflow_agent]
    if firmware_traverse_agent is not None:
        supervisor_tools.append(call_firmware_agent)

    # Build firmware-related prompt sections conditionally
    firmware_capability = ""
    firmware_trigger_section = ""
    firmware_workflow = ""
    firmware_dataflow_note = ""
    firmware_examples = ""

    if firmware_traverse_agent is not None:
        firmware_capability = (
            "3. Delegate firmware filesystem analysis to specialized agent:\n"
            "   - Call call_firmware_agent for cross-binary function tracing\n"
            "   - Analyze configuration files that affect SSL/TLS behavior\n"
            "   - Examine startup scripts that configure services\n"
            "   - Find which binaries import/export SSL/TLS functions\n\n"
        )
        firmware_trigger_section = (
            "WHEN TO USE FIRMWARE AGENT (call_firmware_agent):\n"
            "You MUST call call_firmware_agent in these scenarios:\n"
            "1. Dataflow ends at FILE I/O functions:\n"
            "   - Functions like: fopen(), open(), read(), fread(), read_config(), parse_config(), load_config()\n"
            "   - Action: Use firmware agent to locate the file path and read its contents\n"
            "   - Example: 'verify_flag comes from read_config(\"/etc/ssl.conf\")' → call firmware agent to read /etc/ssl.conf\n\n"
            "2. Dataflow ends at ENVIRONMENT access:\n"
            "   - Functions like: getenv(), environ, secure_getenv()\n"
            "   - Action: Use firmware agent to search scripts/configs that set these env vars\n"
            "   - Example: 'verify_mode = getenv(\"SSL_VERIFY\")' → find where SSL_VERIFY is set\n\n"
            "3. CROSS-BINARY dependencies:\n"
            "   - Cannot find function definition in current binary\n"
            "   - Action: Use firmware agent to search which binary implements the function\n"
            "   - Example: 'SSL_verify_callback not found in binary' → find in other .so files\n\n"
            "4. DATA from external sources:\n"
            "   - Configuration files, startup scripts, command-line parsing\n"
            "   - Action: Use firmware agent to analyze these external sources\n\n"
        )
        firmware_workflow = (
            "2. When functions might be in other binaries:\n"
            "   - Call call_firmware_agent to find cross-binary dependencies\n"
            "   - Identify which binaries implement/call SSL/TLS functions\n"
            "   - Example: Custom SSL_verify_callback might be in a separate library\n\n"
        )
        firmware_dataflow_note = (
            "\n   - **IMPORTANT**: If dataflow traces to file I/O functions (fopen, read, open, read_config, parse_config, etc.) "
            "or environment access (getenv, environ), you MUST call call_firmware_agent to locate and analyze the external file/config"
        )
        firmware_examples = (
            "Example 1 - Conditional security with config file:\n"
            "- You: Search for SSL_set_verify usage using IDA tools\n"
            "- You: Find SSL_set_verify uses parameter 'verify_flag' at 0x12345 (CONDITIONAL)\n"
            "- You: Call call_dataflow_agent to trace verify_flag\n"
            "- Dataflow agent: 'verify_flag comes from read_config() at 0x23456'\n"
            "- You: Call call_firmware_agent to find and analyze config file\n"
            "- Firmware agent: 'Config at /etc/ssl.conf sets verify_flag=0 (disabled)'\n"
            "- You: Report complete findings with config file context\n\n"
            "Example 2 - Cross-binary SSL implementation:\n"
            "- You: Analyze SSL_connect but can't find SSL_verify_callback in current binary\n"
            "- You: Call call_firmware_agent to find SSL_verify_callback implementation\n"
            "- Firmware agent: 'SSL_verify_callback defined in libcustom_ssl.so'\n"
            "- You: Report cross-binary architecture and its security implications\n\n"
        )

    supervisor_agent = create_agent(
        model=model,
        tools=supervisor_tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are an SSL/TLS security analyst with direct access to IDA Pro tools and specialized worker agents.\n\n"
            "YOUR CAPABILITIES:\n"
            "1. Direct IDA Pro MCP access for binary analysis:\n"
            "   - Get function details, decompilation, disassembly\n"
            "   - Find cross-references (xrefs), callers, and callees\n"
            "   - Search for SSL/TLS functions, strings, and globals\n"
            "   - Analyze structures, variables, and data types\n\n"
            "2. Delegate dataflow analysis to specialized agent:\n"
            "   - Call call_dataflow_agent to trace variables to their sources\n"
            "   - Get forward/backward slicing results\n"
            "   - Track data across function boundaries\n\n"
            + firmware_capability +
            firmware_trigger_section +
            (security_rules_content + "\n\n" if security_rules_content else "") +
            "ANALYSIS WORKFLOW:\n"
            "1. Use IDA tools to search for SSL/TLS functions and analyze their usage\n"
            "   - Leverage the call graph context below to focus your analysis\n"
            "   - Decompile relevant functions to examine SSL/TLS code\n"
            "   - Check each security rule systematically\n\n"
            + firmware_workflow +
            ("2" if not firmware_workflow else "3") + ". Identify conditional security behavior:\n"
            "   - Flag parameters/variables that control security decisions\n"
            "   - Note when verification depends on runtime values (config flags, parameters, etc.)\n\n"
            + ("3" if not firmware_workflow else "4") + ". When you find conditional security:\n"
            "   - Call call_dataflow_agent to trace the controlling variable to its source"
            + firmware_dataflow_note + "\n"
            "   - Determine ultimate source: config file, command-line arg, hardcoded, etc.\n\n"
            + ("4" if not firmware_workflow else "5") + ". Synthesize comprehensive security report:\n"
            "   - Connection establishment flow" + (" (including cross-binary calls)" if firmware_workflow else "") + "\n"
            "   - Rule-by-rule analysis with PASS/FAIL/CONDITIONAL status\n"
            "   - For CONDITIONAL: include dataflow trace showing the variable source\n"
            "   - Highlight critical vulnerabilities vs. best practice recommendations\n\n"
            + ("EXAMPLE WORKFLOW:\n" if not firmware_examples else "EXAMPLE WORKFLOWS:\n")
            + firmware_examples
            + call_graph_context
        )
    )

    # TODO: The LLM should ask for external file access if needed.

    # Build user prompt conditionally based on firmware agent availability
    dataflow_instruction = (
        "3. When you find conditional security behavior (e.g., verification depends on a config flag), "
        "use the dataflow agent to trace where the controlling variable comes from"
    )

    if firmware_traverse_agent is not None:
        dataflow_instruction += (
            "\n   **CRITICAL**: If dataflow traces to file I/O (fopen, read_config, etc.) or environment access (getenv), "
            "you MUST use call_firmware_agent to find and analyze the configuration file or script. "
            "Do not skip this step - config file analysis is essential for determining actual security behavior."
        )

    user_prompt = (
        "Analyze the SSL/TLS security of this binary. The binary may use OpenSSL or similar libraries "
        "to establish secure connections.\n\n"
        "Your task:\n"
        "1. Use IDA tools to analyze the SSL/TLS implementation (leverage the call graph context in your system prompt)\n"
        "2. Check compliance with SSL/TLS security best practices\n"
        + dataflow_instruction + "\n"
        "4. Provide a comprehensive security report with:\n"
        "   - Connection establishment flow\n"
        "   - Security rule compliance (PASS/FAIL/CONDITIONAL)\n"
        "   - Dataflow traces for security-critical variables"
        + ("\n   - Configuration file analysis results (if applicable)" if firmware_traverse_agent is not None else "")
    )

    try:
        await stream_and_log_agent(
            agent=supervisor_agent,
            messages=[{"role": "user", "content": user_prompt}],
            agent_name="Supervisor Agent",
            agent_emoji="🎯"
        )
    finally:
        # Clean up headless server
        if conn_type == 'headless_ida' and server_process:
            console.print()
            console.print("[cyan]🛑[/cyan]  Shutting down headless IDA server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
                console.print("[green]✓[/green] Server terminated successfully")
            except subprocess.TimeoutExpired:
                console.print("[yellow]⚠[/yellow]  Server did not terminate, forcing kill...")
                server_process.kill()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze SSL/TLS security using multi-agent system with IDA Pro"
    )
    parser.add_argument(
        "binary_path",
        type=str,
        help="Path to binary file to analyze"
    )
    parser.add_argument(
        "-c", "--conn-type",
        type=str,
        default="headless_ida",
        choices=["plugin", "headless_ida"],
        help="IDA connection type: 'plugin' (IDA GUI with MCP plugin) or 'headless_ida' (automatic headless server) (default: headless_ida)"
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default="deepseek-chat",
        help="LLM model to use (default: deepseek-chat). Examples: openai:gpt-4o, anthropic:claude-sonnet-4-5, deepseek-chat"
    )
    parser.add_argument(
        "-g", "--call-graph",
        type=str,
        default="call_graph.json",
        help="Path to call graph JSON file (default: call_graph.json)"
    )
    parser.add_argument(
        "-f", "--firmware-path",
        type=str,
        default=None,
        help="Path to firmware filesystem root (enables firmware analysis agent)"
    )
    parser.add_argument(
        "-r", "--rules",
        type=str,
        default="openssl",
        choices=["openssl", "curl", "libcurl", "gnutls", "mbedtls", "php_curl", "wget"],
        help="SSL/TLS library rules to use (default: openssl)"
    )
    args = parser.parse_args()

    asyncio.run(main(
        file_path=args.binary_path,
        model=args.model,
        conn_type=args.conn_type,
        call_graph_path=args.call_graph,
        firmware_path=args.firmware_path,
        rules=args.rules
    ))
