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
import hashlib
from pathlib import Path

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

# Import firmware_tools BEFORE static_analyzer
# (IDA modules modify sys.path and remove current directory)
import firmware_tools

from static_analyzer import (
    IDABackend,
    export_to_json,
    draw_call_graph,
    get_function_patterns,
    requires_binary_analysis,
    trim_call_graph,
    DEFAULT_MAX_HOPS,
    TRIM_THRESHOLD_NODES,
    CENTRALITY_PERCENTILE
)

# multiple agents:
# - function and variable renaming agent
# - ssl security analysis agent

# Initialize Rich console for beautiful output
console = Console()

# Global flag to track connection failures
connection_failed = False

def compute_call_graph_path(binary_path: str) -> str:
    """
    Compute unique call graph path based on binary content hash.

    Uses MD5 hash of binary contents to generate a unique filename.
    Format: temp_files/{basename}_{hash6}_call_graph.json

    Args:
        binary_path: Path to binary file

    Returns:
        Unique call graph path in temp_files/ directory
    """
    # Extract binary basename (without directory)
    basename = os.path.basename(binary_path)

    # Compute MD5 hash of binary contents
    md5_hash = hashlib.md5()
    with open(binary_path, 'rb') as f:
        # Read in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(8192), b''):
            md5_hash.update(chunk)

    # Get first 6 characters of hex digest
    hash6 = md5_hash.hexdigest()[:6]

    # Ensure temp_files directory exists
    temp_dir = Path("temp_files")
    temp_dir.mkdir(exist_ok=True)

    # Return unique path
    return str(temp_dir / f"{basename}_{hash6}_call_graph.json")

def resolve_binary_path(binary_path: str, firmware_path: str = None) -> str:
    """
    Resolve binary path to absolute path with validation.

    If binary_path is absolute, use as-is.
    If binary_path is relative:
      - Combine with firmware_path if provided
      - Otherwise resolve from current working directory

    Args:
        binary_path: Path to binary (absolute or relative)
        firmware_path: Optional firmware root path for relative resolution

    Returns:
        Absolute path to binary

    Raises:
        FileNotFoundError: If resolved path does not exist
    """
    # Check if path is already absolute
    if os.path.isabs(binary_path):
        resolved_path = binary_path
    else:
        # Relative path - combine with firmware_path or CWD
        if firmware_path:
            resolved_path = os.path.join(firmware_path, binary_path)
            console.print(f"[dim]📍 Resolving relative path: {binary_path} → {resolved_path}[/dim]")
        else:
            resolved_path = os.path.abspath(binary_path)
            console.print(f"[dim]📍 Resolving from CWD: {binary_path} → {resolved_path}[/dim]")

    # Validate that the binary exists
    if not os.path.exists(resolved_path):
        console.print()
        console.print(Panel(
            f"[bold red]✗ Binary Not Found[/bold red]\n\n"
            f"Resolved path: {resolved_path}\n"
            f"Original path: {binary_path}\n"
            + (f"Firmware root: {firmware_path}\n" if firmware_path else "") +
            "\nPlease check:\n"
            "• Binary path is correct\n"
            "• Firmware path is correct (if using relative path)\n"
            "• File has not been moved or deleted",
            border_style="red",
            title="[bold]File Error[/bold]"
        ))
        console.print()
        raise FileNotFoundError(f"Binary not found: {resolved_path}")

    return resolved_path

def count_tokens(text: str, model: str = "gpt-4") -> int:
    """
    Count tokens in text using tiktoken.

    Args:
        text: Text to count tokens for
        model: Model name for tokenizer (default: gpt-4)

    Returns:
        Token count
    """
    try:
        import tiktoken
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception:
        # Fallback: rough estimate (1 token ≈ 4 chars)
        return len(text) // 4

# Token count warning threshold
TOKEN_WARNING_THRESHOLD = 8000

def format_token_count(count: int, threshold: int = TOKEN_WARNING_THRESHOLD) -> str:
    """
    Format token count with highlighting if it exceeds threshold.

    Args:
        count: Token count to format
        threshold: Warning threshold (default: TOKEN_WARNING_THRESHOLD)

    Returns:
        Formatted string with color coding for high counts
    """
    if count > threshold:
        return f"[bold yellow]⚠️ {count:,}[/bold yellow]"
    else:
        return f"{count:,}"

def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string like "2m 34s" or "15.3s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"

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

def start_headless_ida_server(binary_path: str, host: str = "localhost", port: int = 8800) -> subprocess.Popen:
    """
    Start headless IDA server process.

    Args:
        binary_path: Path to binary to analyze
        host: Server host (default: localhost)
        port: Server port (default: 8800)

    Returns:
        Server process handle
    """
    ida_pro_mcp_dir = '/home/peng/Projects/others/ida-pro-mcp'

    start_time = time.perf_counter()
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
                    elapsed = time.perf_counter() - start_time
                    console.print(f"[green]✓[/green] Headless IDA server ready ({format_duration(elapsed)})")
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
            console.print(f"[yellow]⚠[/yellow]  Check if port {port} is already in use or server is slow to start")
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

    start_time = time.perf_counter()

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
                    # Escape square brackets in JSON output to prevent Rich markup parsing errors
                    args_json = json.dumps(tool_call['args'], indent=6).replace("[", r"\[").replace("]", r"\]")
                    console.print(f"    [dim]Args: {args_json}[/dim]")
                console.print()

            # Check if it's a tool message (result)
            elif hasattr(last_message, "type") and last_message.type == "tool":
                # Check if it's an error result
                if hasattr(last_message, "status") and last_message.status == "error":
                    console.print(f"[bold yellow]⚠️  {agent_name} TOOL ERROR ({last_message.name}):[/bold yellow]")
                    # Escape square brackets in error messages to prevent Rich markup parsing errors
                    escaped_error = last_message.content.replace("[", r"\[").replace("]", r"\]")
                    console.print(f"  [yellow]{escaped_error}[/yellow]")
                else:
                    # Count tokens in tool result
                    tool_tokens = count_tokens(last_message.content)
                    console.print(f"[bold green]📊 {agent_name} TOOL RESULT ([cyan]{last_message.name}[/cyan]) - {format_token_count(tool_tokens)} tokens:[/bold green]")
                    content_preview = last_message.content[:500] if len(last_message.content) > 500 else last_message.content
                    # Escape square brackets to prevent Rich markup parsing errors
                    escaped_preview = content_preview.replace("[", r"\[").replace("]", r"\]")
                    console.print(f"  [dim]{escaped_preview}{'...' if len(last_message.content) > 500 else ''}[/dim]")
                console.print()

            # Check if it's an AI message with content (thinking)
            elif hasattr(last_message, "content") and last_message.content and hasattr(last_message, "type") and last_message.type == "ai":
                if last_message.content.strip():
                    # Count tokens in agent synthesis
                    synthesis_tokens = count_tokens(last_message.content)
                    console.print(f"[bold blue]💭 {agent_name} THINKING - {format_token_count(synthesis_tokens)} tokens:[/bold blue]")
                    # Render markdown content with left-aligned headings
                    md = create_markdown(last_message.content)
                    console.print(md)
                    console.print()
                    final_content = last_message.content

    elapsed = time.perf_counter() - start_time
    console.print(Panel.fit(
        f"[bold green]✓ {agent_name} Complete ({format_duration(elapsed)})[/bold green]",
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
ssl_analyzing_agent = None
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

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 Dataflow Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=dataflow_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Dataflow Analysis Agent",
        agent_emoji="🔍"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 Dataflow Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total Dataflow Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

    return result

@tool
async def call_ssl_agent(request: str, call_graph_context: str = "") -> str:
    """
    Perform SSL/TLS security analysis on the binary.

    Use this tool to:
    - Validate binary contains client-side SSL/TLS code
    - Check compliance with SSL/TLS security rules
    - Identify conditional security behavior
    - Get rule-by-rule security analysis results

    The SSL agent can request help (dataflow tracing or firmware analysis) if needed.
    It will return one of these statuses:
    - STATUS: COMPLETE - Full analysis results ready
    - STATUS: NEED_DATAFLOW - Needs variable tracing
    - STATUS: NEED_FIRMWARE - Needs config/script analysis
    - STATUS: NOT_APPLICABLE - Binary doesn't contain client SSL code

    Args:
        request: SSL analysis request (usually "Analyze SSL/TLS security")
        call_graph_context: Call graph summary to guide analysis

    Returns:
        SSL security analysis results or help request
    """
    full_request = f"{request}\n\nCall Graph Context:\n{call_graph_context}" if call_graph_context else request

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 SSL Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=ssl_analyzing_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="SSL Security Analyzing Agent",
        agent_emoji="🔐"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 SSL Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total SSL Analysis Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

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

    # Log request token count
    request_tokens = count_tokens(full_request)
    console.print(f"[dim]📤 Firmware Agent Request: {format_token_count(request_tokens)} tokens[/dim]")
    console.print()

    result = await stream_and_log_agent(
        agent=firmware_traverse_agent,
        messages=[{"role": "user", "content": full_request}],
        agent_name="Firmware Filesystem Agent",
        agent_emoji="📁"
    )

    # Log response token count
    response_tokens = count_tokens(result)
    console.print()
    console.print(f"[dim]📥 Firmware Agent Response: {format_token_count(response_tokens)} tokens[/dim]")
    console.print(f"[dim]💰 Total Firmware Round: {format_token_count(request_tokens + response_tokens)} tokens[/dim]")
    console.print()

    return result

def generate_call_graph_for_binary(binary_path: str, output_json_path: str, library: str = "openssl", enable_ida_msg: bool = False, max_hops: int = DEFAULT_MAX_HOPS, trim_threshold: int = TRIM_THRESHOLD_NODES, disable_trim: bool = False) -> dict:
    """
    Generate call graph for SSL/TLS functions in the binary.

    Args:
        binary_path: Path to the binary file to analyze
        output_json_path: Path to output JSON file (required)
        library: SSL/TLS library name for pattern filtering (default: "openssl")
        enable_ida_msg: Enable IDA console messages (default: False)
        max_hops: Maximum hops from SSL functions when trimming (default: DEFAULT_MAX_HOPS)
        trim_threshold: Auto-trim if graph exceeds this many nodes (default: TRIM_THRESHOLD_NODES)
        disable_trim: Disable automatic trimming (default: False)

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

    start_time = time.perf_counter()
    backend = None
    try:
        # Initialize IDA backend (opens database)
        console.print(f"[cyan]⚙[/cyan]  Opening binary with IDA: [bold]{binary_path}[/bold]...")
        backend = IDABackend(binary_path, enable_ida_msg=enable_ida_msg)

        # Filter library-specific functions
        console.print(f"[cyan]🔍[/cyan]  Filtering {library} functions...")
        patterns = get_function_patterns(library)
        all_functions = backend.get_func_list_in_name()
        if patterns:
            pattern = re.compile("|".join(patterns))
            ssl_functions = [f for f in all_functions if pattern.search(f)]
        else:
            ssl_functions = all_functions
        console.print(f"[green]✓[/green] Found [bold]{len(ssl_functions)}[/bold] {library} functions")

        if ssl_functions:
            # Escape square brackets in function names to prevent Rich markup parsing errors
            escaped_functions = [func.replace("[", r"\[").replace("]", r"\]") for func in ssl_functions[:5]]
            console.print(f"[dim]   Functions: {', '.join(escaped_functions)}{'...' if len(ssl_functions) > 5 else ''}[/dim]")

        # Generate call graph
        console.print("[cyan]🕸[/cyan]  Generating call graph...")
        call_graph = backend.generate_call_graph(filtered_functions=ssl_functions)
        console.print(f"[green]✓[/green] Call graph generated: [bold]{len(call_graph.nodes)}[/bold] nodes, [bold]{len(call_graph.edges)}[/bold] edges")

        # Auto-trim if enabled and threshold exceeded
        trim_stats = None
        if not disable_trim and len(call_graph.nodes) > trim_threshold:
            console.print(f"[cyan]✂[/cyan]  Graph has {len(call_graph.nodes)} nodes (threshold: {trim_threshold}). Trimming...")
            call_graph, trim_stats = trim_call_graph(
                call_graph,
                ssl_functions,
                max_hops=max_hops,
                centrality_percentile=CENTRALITY_PERCENTILE
            )
            console.print(f"[green]✓[/green] Trimmed: [bold]{trim_stats['trimmed_nodes']}[/bold] nodes (removed {trim_stats['nodes_removed']}), [bold]{trim_stats['trimmed_edges']}[/bold] edges (removed {trim_stats['edges_removed']})")
        elif disable_trim:
            console.print("[dim]  Trimming disabled by user[/dim]")
        else:
            console.print(f"[dim]  Graph has {len(call_graph.nodes)} nodes (threshold: {trim_threshold}). No trimming needed[/dim]")

        # Export to JSON
        console.print(f"[cyan]💾[/cyan]  Exporting to [bold]{output_json_path}[/bold]...")
        export_to_json(call_graph, binary_path, output_json_path, trim_stats=trim_stats)
        console.print(f"[green]✓[/green] Exported to JSON")

        # Draw PDF
        pdf_path = output_json_path.replace('.json', '.pdf')
        console.print(f"[cyan]🎨[/cyan]  Drawing call graph to [bold]{pdf_path}[/bold]...")
        draw_call_graph(call_graph, output_file=pdf_path, highlight_nodes=ssl_functions)
        console.print(f"[green]✓[/green] PDF visualization created")

        # Load the generated JSON to return
        with open(output_json_path, 'r') as f:
            call_graph_data = json.load(f)

        elapsed = time.perf_counter() - start_time
        console.print()
        console.print(Panel.fit(
            f"[bold green]✓ Call Graph Generation Complete ({format_duration(elapsed)})[/bold green]",
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

async def main(file_path: str, model: str = "deepseek-chat", conn_type: str = "plugin", call_graph_path: str = None, firmware_path: str = None, rules: str = "openssl", port: int = 8800, max_hops: int = DEFAULT_MAX_HOPS, trim_threshold: int = TRIM_THRESHOLD_NODES, disable_trim: bool = False):
    """
    Main function to analyze SSL/TLS connections using multi-agent system.

    Args:
        model: LLM model to use (default: "deepseek-chat")
        call_graph_path: Path to call graph JSON file (default: auto-generated based on binary hash)
        firmware_path: Path to firmware filesystem root (optional, enables firmware agent)
        rules: SSL/TLS library rules to use (default: "openssl")
        max_hops: Maximum hops from SSL functions when trimming (default: DEFAULT_MAX_HOPS)
        trim_threshold: Auto-trim if graph exceeds this many nodes (default: TRIM_THRESHOLD_NODES)
        disable_trim: Disable automatic call graph trimming (default: False)
    """
    total_start_time = time.perf_counter()

    # Resolve binary path (handles relative paths against firmware_path or CWD)
    start_time = time.perf_counter()
    file_path = resolve_binary_path(file_path, firmware_path)
    elapsed = time.perf_counter() - start_time
    console.print(f"[dim]⏱  Binary path resolution: {format_duration(elapsed)}[/dim]")
    console.print()

    # Auto-generate unique call graph path if not provided
    if call_graph_path is None:
        call_graph_path = compute_call_graph_path(file_path)
        console.print(f"[dim]📊 Call graph path: {call_graph_path}[/dim]")

    # Load security rules for the specified library
    start_time = time.perf_counter()
    security_rules_content = load_security_rules(rules)
    elapsed = time.perf_counter() - start_time
    console.print(f"[dim]⏱  Security rules loading: {format_duration(elapsed)}[/dim]")
    console.print()

    # Generate or load call graph based on connection type
    call_graph_data = None
    server_process = None  # Track server process for cleanup
    server_script = '/home/peng/Projects/others/ida-pro-mcp/src/ida_pro_mcp/server.py'

    # Check if library requires binary analysis (call graph generation)
    needs_call_graph = requires_binary_analysis(rules)
    if not needs_call_graph:
        console.print(f"[cyan]ℹ[/cyan]  Library '{rules}' is script-based, skipping call graph generation")
        console.print()

    try:
        if conn_type == 'headless_ida':
            # Generate call graph BEFORE starting MCP server (only for binary libraries)
            # (Both use idalib and can't run simultaneously)
            if needs_call_graph:
                try:
                    call_graph_data = generate_call_graph_for_binary(
                        binary_path=file_path,
                        output_json_path=call_graph_path,
                        library=rules,
                        enable_ida_msg=False,
                        max_hops=max_hops,
                        trim_threshold=trim_threshold,
                        disable_trim=disable_trim
                    )
                except Exception as e:
                    console.print(f"[bold red]✗[/bold red] Cannot continue without call graph. Exiting.")
                    raise

            # Now start headless IDA server (database is closed from graph generation)
            # Auto-start headless IDA server
            server_process = start_headless_ida_server(file_path, port=port)

            server_config = {
                "idapro": {
                    "transport": "sse",
                    "url": f"http://localhost:{port}/sse"
                }
            }
        elif conn_type == 'plugin':
            # Use IDA GUI plugin (manual startup required)
            # Load call graph from existing file (only for binary libraries)
            if needs_call_graph and call_graph_path and os.path.exists(call_graph_path):
                try:
                    with open(call_graph_path, 'r') as f:
                        call_graph_data = json.load(f)
                    console.print(f"[green]✓[/green] Loaded call graph from [bold]{call_graph_path}[/bold]")
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow]  Failed to load call graph: {e}")
            elif needs_call_graph and call_graph_path:
                console.print(f"[yellow]⚠[/yellow]  Call graph file not found: {call_graph_path}")
                console.print(f"[dim]   ℹ  Run static_analyzer.py separately or use --conn-type=headless_ida for auto-generation[/dim]")

            server_config = {
                "idapro": {
                    "transport": "stdio",
                    "command": "python",
                    "args": [server_script]
                }
            }
        else:
            raise ValueError(f"Invalid connection type: {conn_type}")

        start_time = time.perf_counter()
        client = MultiServerMCPClient(server_config)
        tools = await client.get_tools()
        elapsed = time.perf_counter() - start_time
        console.print(f"[green]✓[/green] Successfully loaded [bold]{len(tools)}[/bold] tools from MCP server ({format_duration(elapsed)})")

    except Exception as e:
        if server_process:
            console.print("[yellow]⚠[/yellow]  Terminating headless server due to error...")
            server_process.terminate()
            server_process.wait()
        console.print(f"[bold red]✗[/bold red] Failed to connect to MCP server: {e}")
        console.print("[bold red]✗[/bold red] Cannot continue without MCP tools. Exiting.")
        raise  # Re-raise exception to terminate

    # Initialize all agents
    global dataflow_agent, ssl_analyzing_agent, supervisor_agent, firmware_traverse_agent

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
            "6. When dataflow reaches a FUNCTION PARAMETER, AUTOMATICALLY trace through callers:\n"
            "   a. Use get_callers(function_address) IDA tool to find ALL callers in current binary\n"
            "   b. For EACH caller found:\n"
            "      - Decompile the caller function\n"
            "      - Identify which argument value is passed to this parameter position\n"
            "      - Recursively trace that argument's source (repeat from step 3)\n"
            "      - Track each caller as a SEPARATE dataflow path\n"
            "   c. If multiple callers found → return MULTIPLE paths in output\n"
            "   d. Only stop at EXPORTED_FUNCTION_PARAM when get_callers() returns ZERO callers\n\n"
            "   Example - Multiple callers scenario:\n"
            "   - Variable 'verify_mode' traced to parameter 1 of init_ssl()\n"
            "   - get_callers(init_ssl) returns: [caller_a at 0x1000, caller_b at 0x2000]\n"
            "   - Caller_a analysis: passes constant SSL_VERIFY_PEER (0x01) as argument 1\n"
            "   - Caller_b analysis: passes value from read_config(\"/etc/ssl.conf\", \"verify\") as argument 1\n"
            "   - Result: Return 2 paths (see output format below)\n\n"
            "7. Continue tracing until the dataflow TERMINATES at one of these points:\n"
            "   - CONSTANT: Value comes from a constant/literal in the binary\n"
            "   - CONFIG_FILE: Value read from a configuration file (fopen, read_config, etc.)\n"
            "   - ENVIRONMENT_VARIABLE: Value from getenv(), secure_getenv(), environ\n"
            "   - COMMAND_LINE_ARG: Value from argv/argc parsing\n"
            "   - EXPORTED_FUNCTION_PARAM (with 0 callers): Traced to parameter of exported function with NO callers in current binary\n"
            "   - UNDETERMINED: Dataflow tracking stopped but source type unclear (e.g., indirect call, complex control flow)\n\n"
            "SOURCE TYPE CATEGORIZATION (CRITICAL):\n"
            "You MUST categorize the ultimate source into one of the above types. For each path:\n"
            "- CONSTANT: Report the constant value (e.g., 'SSL_VERIFY_NONE (0x00)')\n"
            "- EXPORTED_FUNCTION_PARAM: Report function name, parameter position, and number of callers (e.g., 'secure_connect (parameter 2: verify_mode, 0 callers in current binary)')\n"
            "- CONFIG_FILE: Report config file path if identifiable (e.g., '/etc/ssl.conf' from read_config())\n"
            "- ENVIRONMENT_VARIABLE: Report variable name (e.g., 'SSL_VERIFY' from getenv())\n"
            "- COMMAND_LINE_ARG: Report argument position or parsing logic\n"
            "- UNDETERMINED: Report where tracking stopped and why (e.g., 'Lost at indirect call through function pointer')\n\n"
            "OUTPUT FORMAT:\n"
            "For SINGLE-PATH analysis (only one source found):\n\n"
            "### Variable: [variable_name]\n"
            "**Source Type:** [CONSTANT|EXPORTED_FUNCTION_PARAM|CONFIG_FILE|ENVIRONMENT_VARIABLE|COMMAND_LINE_ARG|UNDETERMINED]\n"
            "**Source Details:** [Specific details based on type]\n"
            "**Dataflow Path:**\n"
            "  1. [address] [function_name]: [operation]\n"
            "  2. [address] [function_name]: [operation]\n"
            "  ...\n"
            "  N. [address] [function_name]: [terminal operation]\n\n"
            "**Analysis Notes:** [Any ambiguities, assumptions, or limitations]\n\n"
            "For MULTI-PATH analysis (multiple callers/sources found):\n\n"
            "### Variable: [variable_name]\n"
            "**Multiple Paths Found:** [count] distinct dataflow paths traced through [count] callers\n\n"
            "#### Path 1 (via [caller_function_name]):\n"
            "**Source Type:** [type]\n"
            "**Source Details:** [details]\n"
            "**Dataflow Path:**\n"
            "  1. [address] [caller_function]: [how argument is passed]\n"
            "  2. [address] [intermediate_function]: [operation]\n"
            "  ...\n"
            "  N. [address] [function]: [terminal operation]\n\n"
            "#### Path 2 (via [caller_function_name]):\n"
            "**Source Type:** [type]\n"
            "**Source Details:** [details]\n"
            "**Dataflow Path:**\n"
            "  ...\n\n"
            "[Repeat for each path]\n\n"
            "**Analysis Notes:** [Cross-path observations, whether different paths lead to different security outcomes, etc.]\n\n"
            "Example single-path outputs:\n"
            "- Source Type: CONSTANT | Source Details: SSL_VERIFY_NONE (0x00) at 0x401234\n"
            "- Source Type: CONFIG_FILE | Source Details: /etc/app.conf (key='verify_mode') from read_config() at 0x405678\n"
            "- Source Type: EXPORTED_FUNCTION_PARAM | Source Details: ssl_connect (parameter 2: verify_mode, 0 callers in current binary)\n"
            "- Source Type: UNDETERMINED | Source Details: Tracking stopped at indirect call via vtable at 0x407890\n\n"
            "Example multi-path output:\n"
            "### Variable: verify_mode\n"
            "**Multiple Paths Found:** 2 distinct dataflow paths traced through 2 callers\n\n"
            "#### Path 1 (via http_connect at 0x401000):\n"
            "**Source Type:** CONSTANT\n"
            "**Source Details:** SSL_VERIFY_PEER (0x01)\n"
            "**Dataflow Path:**\n"
            "  1. 0x401000 http_connect: calls init_ssl_ctx(SSL_VERIFY_PEER)\n"
            "  2. 0x401200 init_ssl_ctx: verify_mode parameter = SSL_VERIFY_PEER (0x01)\n"
            "  3. 0x401250 init_ssl_ctx: passes verify_mode to SSL_CTX_set_verify\n\n"
            "#### Path 2 (via ftp_connect at 0x402000):\n"
            "**Source Type:** CONFIG_FILE\n"
            "**Source Details:** /etc/ftp.conf (key='ssl_verify') from load_config()\n"
            "**Dataflow Path:**\n"
            "  1. 0x402000 ftp_connect: config_verify = load_config(\"/etc/ftp.conf\", \"ssl_verify\")\n"
            "  2. 0x402010 ftp_connect: calls init_ssl_ctx(config_verify)\n"
            "  3. 0x401200 init_ssl_ctx: verify_mode parameter = config_verify\n"
            "  4. 0x401250 init_ssl_ctx: passes verify_mode to SSL_CTX_set_verify\n\n"
            "**Analysis Notes:** Different callers use different sources - http_connect uses hardcoded secure value, ftp_connect depends on config file"
        )
    )

    # 2. SSL/TLS Security Analyzing Agent - specialized SSL security expert
    console.print("[cyan]🔐[/cyan]  Creating SSL analyzing agent...")
    ssl_analyzing_agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are an SSL/TLS security analysis expert with direct access to IDA Pro MCP tools. "
            "Your SOLE responsibility is to analyze binaries for SSL/TLS security vulnerabilities and check compliance with security rules.\n\n"
            "IDA TOOLS AVAILABLE:\n"
            "You have direct access to all IDA Pro tools to query the binary as needed:\n"
            "- Get function details, decompilation, disassembly\n"
            "- Find cross-references (xrefs), callers, and callees\n"
            "- Search for SSL/TLS functions, strings, and globals\n"
            "- Analyze structures, variables, and data types\n\n"
            + (security_rules_content + "\n\n" if security_rules_content else "") +
            "CRITICAL INITIAL CHECK - Client Code Validation:\n"
            "Before detailed SSL/TLS analysis, FIRST verify this binary contains client code:\n\n"
            "CLIENT CODE INDICATORS (search using IDA tools):\n"
            "- SSL_connect() - Client TLS handshake\n"
            "- TLS_client_method(), DTLS_client_method() - Client SSL methods\n"
            "- curl_easy_perform(), curl_multi_perform() - libcurl client\n"
            "- X509_check_host(), SSL_set1_host() - Hostname verification\n"
            "- connect() to remote servers\n\n"
            "SERVER CODE INDICATORS (to exclude):\n"
            "- SSL_accept() - Server TLS handshake\n"
            "- bind(), listen(), accept() - Server socket setup\n"
            "- TLS_server_method(), DTLS_server_method() - Server SSL methods\n\n"
            "VALIDATION WORKFLOW:\n"
            "1. Search for client functions: use list_functions() or search for SSL_connect/curl_*\n"
            "2. Search for server functions: use list_functions() or search for SSL_accept/bind/listen\n\n"
            "IF SERVER-ONLY (has SSL_accept but no SSL_connect):\n"
            "   - TERMINATE analysis immediately\n"
            "   - Return: 'STATUS: NOT_APPLICABLE\\nThis binary contains server-side SSL code only.'\n\n"
            "IF NO SSL/TLS CODE AT ALL:\n"
            "   - TERMINATE with: 'STATUS: NOT_APPLICABLE\\nNo SSL/TLS code detected in binary'\n\n"
            "IF MIXED (both client and server) OR CLIENT-ONLY:\n"
            "   - Continue analysis\n"
            "   - Focus ONLY on client-side code paths\n\n"
            "ANALYSIS WORKFLOW:\n"
            "1. Use IDA tools to search for SSL/TLS functions and analyze their usage\n"
            "2. Leverage the call graph context (provided by supervisor) to focus analysis\n"
            "3. Decompile relevant functions to examine SSL/TLS code\n"
            "4. Check each security rule systematically\n"
            "5. For each rule, determine: PASS | FAIL | CONDITIONAL\n"
            "6. When you encounter CONDITIONAL behavior:\n"
            "   - Identify the controlling variable/parameter\n"
            "   - Analyze the code to understand what values are possible\n"
            "   - Determine if you can trace the variable yourself OR need help:\n"
            "     * If variable source is UNCLEAR: Request dataflow help\n"
            "     * If variable comes from CONFIG/ENV/ARG but you don't have firmware access: Request firmware help\n"
            "     * If you can determine everything with IDA tools alone: Complete the analysis\n\n"
            "REQUESTING HELP FROM OTHER AGENTS:\n"
            "You can request help from supervisor-coordinated agents when needed:\n\n"
            "Request Dataflow Help (when variable source is unclear):\n"
            "  Format: STATUS: NEED_DATAFLOW\n"
            "          Variable: [variable_name]\n"
            "          Context: [where/how it's used]\n"
            "          Reason: [why tracing is needed]\n"
            "          [Your analysis so far]\n\n"
            "Request Cross-Binary Analysis (when dataflow returns EXPORTED_FUNCTION_PARAM with 0 callers):\n"
            "  Format: STATUS: NEED_CROSS_BINARY_ANALYSIS\n"
            "          Function: [exported_function_name]\n"
            "          Parameter: [parameter_position] ([parameter_name])\n"
            "          Context: [what this parameter controls in SSL security]\n"
            "          Binary: [current binary being analyzed]\n"
            "          [Your analysis so far]\n\n"
            "  When to use: After dataflow agent returns \"EXPORTED_FUNCTION_PARAM with 0 callers\"\n"
            "  Supervisor will: Find caller binaries, trace parameter in each, aggregate results\n\n"
            "Request Config/Script Analysis (when dataflow returns CONFIG_FILE, ENV_VAR, or CMD_ARG):\n"
            "  Format: STATUS: NEED_CONFIG_ANALYSIS\n"
            "          Source Type: [CONFIG_FILE|ENVIRONMENT_VARIABLE|COMMAND_LINE_ARG]\n"
            "          Source Details: [file path, variable name, or argument pattern from dataflow]\n"
            "          Setting: [what to look for - e.g., 'ssl_verify_mode', 'TLS_REQCERT']\n"
            "          Context: [what this setting controls in SSL security]\n"
            "          [Your analysis so far]\n\n"
            "  When to use: After dataflow agent returns CONFIG_FILE, ENVIRONMENT_VARIABLE, or COMMAND_LINE_ARG\n"
            "  Supervisor will: Read config/script, parse it, extract the actual default value\n\n"
            "Request Firmware Help (when you need file system access but dataflow hasn't traced yet):\n"
            "  Format: STATUS: NEED_FIRMWARE\n"
            "          Request: [what you need - config file, startup script, etc.]\n"
            "          Context: [why you need it]\n"
            "          [Your analysis so far]\n\n"
            "Complete Analysis (when all rules checked):\n"
            "  Format: STATUS: COMPLETE\n"
            "          [Full analysis results]\n\n"
            "OUTPUT FORMAT FOR COMPLETE ANALYSIS:\n"
            "When STATUS: COMPLETE, provide these sections:\n\n"
            "SECTION 1 - Client Summary:\n"
            "  * Purpose: What this client is used for\n"
            "  * Connection flow: Steps to establish SSL/TLS connection\n"
            "  * Dependencies: Config files or command-line arguments (if identified)\n\n"
            "SECTION 2 - Rule Checking Results:\n"
            "  * Rule-by-rule analysis with status: PASS | FAIL | CONDITIONAL\n"
            "  * ALL results MUST include Evidence field:\n"
            "    - For PASS: Show function calls, parameters proving secure implementation\n"
            "    - For FAIL: Show missing security calls, insecure parameters\n"
            "    - For CONDITIONAL: Show conditional logic, controlling variables\n\n"
            "  * For CONDITIONAL rules, include these 3 parts:\n"
            "    1. Condition Statement: Clear statement of what determines behavior\n"
            "       ✗ BAD: 'Depends on v58'\n"
            "       ✓ GOOD: 'Certificate verification depends on verify_mode in /etc/ssl.conf'\n\n"
            "    2. Value-Result Mapping: Complete mapping of each value to security result\n"
            "       ✓ REQUIRED:\n"
            "         - verify_mode=0 (SSL_VERIFY_NONE): FAIL - Disables verification\n"
            "         - verify_mode=1 (SSL_VERIFY_PEER): PASS - Enables verification\n\n"
            "    3. Firmware Default: Actual default value and its security result\n"
            "       ✓ GOOD: 'Default: FAIL - verify_mode=0 configured in /etc/ssl.conf (line 34)'\n"
            "       ✓ ACCEPTABLE: 'Default: Not determined - Need firmware access'\n\n"
            "    CRITICAL: Never use cryptic variable names like 'v58' in final output!\n\n"
            "  * For MULTI-SOURCE CONDITIONAL rules (when dataflow returns multiple paths):\n"
            "    Report EACH source's outcome separately:\n\n"
            "    1. Condition Statement: Explain that behavior depends on multiple sources/callers\n"
            "       ✓ REQUIRED: 'Certificate verification has different behavior depending on caller'\n\n"
            "    2. Per-Source Analysis: For EACH source, provide:\n"
            "       - Source identification (caller binary, config file, etc.)\n"
            "       - Value used by that source\n"
            "       - Security result (PASS/FAIL) for that source\n\n"
            "       Example format:\n"
            "       **Caller 1: /usr/bin/httpclient**\n"
            "         - Value: verify_mode=0 (SSL_VERIFY_NONE, hardcoded constant)\n"
            "         - Result: FAIL - Disables all certificate verification\n\n"
            "       **Caller 2: /usr/sbin/ftpd**\n"
            "         - Value: verify_mode=1 (from /etc/ftpd.conf, TLS_REQCERT=demand)\n"
            "         - Result: PASS - Requires valid certificate\n\n"
            "    3. Overall Assessment: Summarize security posture across all sources\n"
            "       ✓ REQUIRED: State how many sources PASS vs FAIL\n"
            "       Example: 'Overall: 1/2 callers FAIL - httpclient uses insecure settings, ftpd is secure'\n\n"
            "    CRITICAL:\n"
            "    - MUST analyze EVERY source/path returned by dataflow agent\n"
            "    - If different sources have different outcomes, clearly attribute each\n"
            "    - Don't aggregate into single PASS/FAIL - show per-source results\n\n"
            "SECTION 3 - Dataflow Analysis:\n"
            "  * Complete dataflow traces for security-critical variables (if any were traced)\n"
            "  * Show: source → transformations → sink\n\n"
            "IMPORTANT GUIDELINES:\n"
            "- Focus on SSL/TLS security analysis ONLY - don't suggest improvements or recommendations\n"
            "- Use IDA tools extensively to understand code behavior\n"
            "- Request help when you need variable tracing or external file access\n"
            "- Provide clear, actionable results with specific evidence\n"
            "- When uncertain about variable sources, request dataflow help rather than guessing\n"
        )
    )
    console.print("[green]✓[/green] SSL analyzing agent created")

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
            "   - CRITICAL: Use SPECIFIC patterns to avoid 100+ matches and token bloat!\n"
            "   - GOOD patterns (specific + file_pattern):\n"
            "     * 'SSL_CTX_set_verify' with file_pattern='*.c' → finds SSL setup in code\n"
            "     * 'verify\\\\s*=\\\\s*[0-1]' with file_pattern='*.conf' → finds verify settings\n"
            "     * 'curl_easy_setopt' with file_pattern='*.c' → finds CURL options\n"
            "   - BAD patterns (too broad, causes 100+ matches):\n"
            "     * 'ssl|SSL|tls|TLS' → matches everything, produces hundreds of results\n"
            "     * '.*verify.*' → too generic, matches unrelated content\n"
            "     * Patterns without file_pattern → searches all files including docs/logs\n"
            "   - ALWAYS use file_pattern to filter: '*.conf', '*.c', '*.sh'\n"
            "   - Pattern strategy: specific_keyword + file_pattern beats broad_pattern_alone\n"
            "   - Use for: finding specific SSL keywords, config options, function calls\n\n"
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
            "CONFIGURATION FILE ANALYSIS (CRITICAL):\n"
            "When asked to find config values (e.g., 'Find verify_mode in /etc/ssl.conf'):\n"
            "1. Use search_files_by_name or direct read_file to locate the config\n"
            "2. Parse the config format (key=value, key: value, XML, JSON, etc.)\n"
            "3. Extract the SPECIFIC key's value\n"
            "4. Report clearly:\n"
            "   ✓ GOOD: 'Found /etc/ssl.conf line 34: verify_mode=0'\n"
            "   ✓ GOOD: 'verify_mode not found in /etc/ssl.conf (defaults to 0 per code)'\n"
            "   ✓ GOOD: 'Config file /etc/ssl.conf does not exist in firmware'\n"
            "   ✗ BAD: Just returning entire config file without highlighting the value\n"
            "   ✗ BAD: 'See config file' without extracting the value\n"
            "5. If config file doesn't exist, explicitly state: 'File [path] not found in firmware'\n\n"
            "STARTUP SCRIPT ANALYSIS:\n"
            "When asked to find environment variables or command-line arguments:\n"
            "1. Search common locations:\n"
            "   - /etc/profile, /etc/environment, /etc/init.d/*, /etc/rc.d/*\n"
            "   - systemd: /etc/systemd/system/*.service, /lib/systemd/system/*.service\n"
            "   - init scripts: /etc/init/*.conf\n"
            "   - cron: /etc/cron.*, /etc/crontab\n"
            "2. For environment variables: Look for 'export VAR=value' or 'VAR=value' in scripts\n"
            "3. For command-line args: Look for how binaries are invoked (e.g., 'start-stop-daemon --exec /usr/bin/app -- --arg=value')\n"
            "4. Report findings clearly:\n"
            "   ✓ GOOD: 'Found in /etc/init.d/sslclient line 45: export SSL_VERIFY=0'\n"
            "   ✓ GOOD: 'Binary started with: /usr/bin/app --verify-ssl=false in /etc/systemd/system/app.service'\n"
            "   ✓ GOOD: 'SSL_VERIFY not found in any startup scripts (defaults to unset/0)'\n"
            "   ✗ BAD: Returning entire script without highlighting the relevant line\n"
            "5. If not found after searching, explicitly state: 'Variable [name] not set in any startup scripts'\n\n"
            "CROSS-BINARY CALLER ANALYSIS:\n"
            "When asked to find which binaries call a function (e.g., 'Find callers of secure_connect'):\n"
            "1. Use find_binaries_with_symbol to find binaries that reference the function\n"
            "2. Use list_binary_symbols on caller binaries to verify they import/call it\n"
            "3. If possible, examine how they call it (parameters, context)\n"
            "4. Report: 'Function [name] called by: [binary_path] at [address/context]'\n"
            "5. If no callers found: 'No binaries in firmware call [function_name]'\n\n"
            "OUTPUT FORMAT:\n"
            "- File paths with line numbers (e.g., 'etc/ssl.conf:42')\n"
            "- Extracted values (e.g., 'verify_mode=0', 'export SSL_VERIFY=1')\n"
            "- Relevant excerpts with surrounding context (3-5 lines)\n"
            "- Binary relationships: 'binary_A imports SSL_verify from binary_B'\n"
            "- Security implications: How findings affect SSL/TLS security\n"
            "- Cross-references: 'Function X defined in libssl.so, called by httpd and ftpd'\n"
            "- EXPLICIT 'not found' statements when files/values don't exist\n\n"
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
    # DISABLED: Call graph context removed to reduce token usage and improve performance
    call_graph_context = ""
    # if call_graph_data:
    #     call_graph_text = format_call_graph(call_graph_data)
    #     call_graph_context = (
    #         "\n\nCALL GRAPH CONTEXT:\n"
    #         "Below is the call graph extracted from the binary showing SSL/TLS function usage and call relationships. "
    #         "Use this to guide your analysis and avoid unnecessary exploration.\n\n"
    #         + call_graph_text
    #     )

    # 3. Supervisor Agent - orchestrates SSL analysis and coordinates helper agents
    # Build supervisor tools list conditionally
    supervisor_tools = tools + [call_ssl_agent, call_dataflow_agent]
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
            "Example 1 - CONSTANT source (not truly conditional):\n"
            "- You: Find SSL_CTX_set_verify at 0x12345 with mode parameter\n"
            "- You: Call call_dataflow_agent to trace mode parameter\n"
            "- Dataflow agent reports:\n"
            "  Variable: mode\n"
            "  Source Type: CONSTANT\n"
            "  Source Details: SSL_VERIFY_NONE (0x00) at 0x12340\n"
            "  Dataflow Path: Direct assignment from constant\n"
            "- You: Determine this is FAIL (not conditional, always insecure)\n"
            "- You: Report:\n"
            "  Rule 2: Certificate Chain and Validity Checking\n"
            "  Status: FAIL\n"
            "  Evidence:\n"
            "    - SSL_CTX_set_verify at 0x12345: always called with SSL_VERIFY_NONE (constant 0x00)\n"
            "    - No conditional logic - hardcoded to disable verification\n\n"
            "Example 2 - CONFIG_FILE source with firmware analysis:\n"
            "- You: Find SSL_set_verify with parameter verify_flag at 0x12345\n"
            "- You: Call call_dataflow_agent to trace verify_flag\n"
            "- Dataflow agent reports:\n"
            "  Variable: verify_flag\n"
            "  Source Type: CONFIG_FILE\n"
            "  Source Details: /etc/ssl.conf (key='verify_mode') from read_config() at 0x23456\n"
            "  Dataflow Path:\n"
            "    1. 0x12345 init_ssl: verify_flag passed to SSL_set_verify\n"
            "    2. 0x23456 read_config: verify_flag = parse_config(\"/etc/ssl.conf\", \"verify_mode\")\n"
            "- You: Call call_firmware_agent: 'Find /etc/ssl.conf and extract verify_mode value'\n"
            "- Firmware agent: 'Found /etc/ssl.conf line 34: verify_mode=0'\n"
            "- You: Analyze code to understand value meanings (0=SSL_VERIFY_NONE, 1=SSL_VERIFY_PEER)\n"
            "- You: Report:\n"
            "  Rule 2: Certificate Chain and Validity Checking\n"
            "  Status: CONDITIONAL\n"
            "  Evidence:\n"
            "    - SSL_set_verify at 0x12345: mode parameter from verify_flag variable\n"
            "    - read_config at 0x23456: loads verify_flag from /etc/ssl.conf key 'verify_mode'\n"
            "    - Decompiled: if(verify_flag == 1) { SSL_set_verify(SSL_VERIFY_PEER); } else { SSL_set_verify(SSL_VERIFY_NONE); }\n"
            "  Condition: Certificate verification depends on verify_mode value in /etc/ssl.conf\n"
            "  Value-Result Mapping:\n"
            "    - verify_mode=0: FAIL - Disables all certificate verification (SSL_VERIFY_NONE)\n"
            "    - verify_mode=1: PASS - Enables full verification (SSL_VERIFY_PEER)\n"
            "  Default: FAIL - verify_mode=0 configured in /etc/ssl.conf (line 34)\n\n"
            "Example 3 - ENVIRONMENT_VARIABLE source:\n"
            "- You: Find SSL_CTX_set_options with check_hostname variable\n"
            "- You: Call call_dataflow_agent to trace check_hostname\n"
            "- Dataflow agent reports:\n"
            "  Variable: check_hostname\n"
            "  Source Type: ENVIRONMENT_VARIABLE\n"
            "  Source Details: SSL_CHECK_HOSTNAME from getenv() at 0x45678\n"
            "  Dataflow Path:\n"
            "    1. 0x34567 setup_ssl: check_hostname controls X509_check_host call\n"
            "    2. 0x45678 init_options: check_hostname = atoi(getenv(\"SSL_CHECK_HOSTNAME\"))\n"
            "- You: Call call_firmware_agent: 'Search startup scripts for SSL_CHECK_HOSTNAME default value'\n"
            "- Firmware agent: 'Not found in /etc/profile, /etc/init.d/*, or systemd files. Environment variable not set by default.'\n"
            "- You: Analyze code behavior when getenv returns NULL (defaults to 0)\n"
            "- You: Report:\n"
            "  Rule 3: Hostname Verification\n"
            "  Status: CONDITIONAL\n"
            "  Evidence:\n"
            "    - X509_check_host at 0x34567: only called if check_hostname != 0\n"
            "    - getenv at 0x45678: reads SSL_CHECK_HOSTNAME, defaults to NULL\n"
            "    - Decompiled: check_hostname = getenv(\"SSL_CHECK_HOSTNAME\") ? atoi(...) : 0;\n"
            "  Condition: Hostname verification depends on SSL_CHECK_HOSTNAME environment variable\n"
            "  Value-Result Mapping:\n"
            "    - SSL_CHECK_HOSTNAME unset or =0: FAIL - Hostname verification disabled\n"
            "    - SSL_CHECK_HOSTNAME=1: PASS - Hostname verification enabled\n"
            "  Default: FAIL - SSL_CHECK_HOSTNAME not set in startup scripts (defaults to 0/disabled)\n\n"
            "Example 4 - COMMAND_LINE_ARG source:\n"
            "- You: Find SSL_CTX_set_min_proto_version with min_version parameter\n"
            "- You: Call call_dataflow_agent to trace min_version\n"
            "- Dataflow agent reports:\n"
            "  Variable: min_version\n"
            "  Source Type: COMMAND_LINE_ARG\n"
            "  Source Details: Parsed from argv[2] in parse_args() at 0x56789\n"
            "  Dataflow Path:\n"
            "    1. 0x45678 init_tls: min_version passed to SSL_CTX_set_min_proto_version\n"
            "    2. 0x56789 parse_args: min_version from argv[2] (--min-tls option)\n"
            "- You: Call call_firmware_agent: 'Search startup scripts for how this binary is invoked and what --min-tls value is used'\n"
            "- Firmware agent: 'Found in /etc/init.d/sslclient: starts with --min-tls 1.0'\n"
            "- You: Map TLS versions (1.0=vulnerable, 1.2+=secure)\n"
            "- You: Report:\n"
            "  Rule 4: Strong TLS Version\n"
            "  Status: CONDITIONAL\n"
            "  Evidence:\n"
            "    - SSL_CTX_set_min_proto_version at 0x45678: min_version from command-line\n"
            "    - parse_args at 0x56789: min_version = parse_tls_version(argv[2])\n"
            "    - Supports versions: TLS 1.0 (0x0301), TLS 1.1 (0x0302), TLS 1.2 (0x0303), TLS 1.3 (0x0304)\n"
            "  Condition: Minimum TLS version depends on --min-tls command-line argument\n"
            "  Value-Result Mapping:\n"
            "    - --min-tls 1.0 or 1.1: FAIL - Allows vulnerable TLS versions\n"
            "    - --min-tls 1.2 or 1.3: PASS - Enforces secure TLS versions only\n"
            "  Default: FAIL - /etc/init.d/sslclient starts with --min-tls 1.0 (line 45)\n\n"
            "Example 5 - EXPORTED_FUNCTION_PARAM (library boundary):\n"
            "- You: Analyzing libssl_wrapper.so (a library, not standalone binary)\n"
            "- You: Find SSL_CTX_set_verify with verify_mode parameter in exported function secure_connect()\n"
            "- You: Call call_dataflow_agent to trace verify_mode\n"
            "- Dataflow agent reports:\n"
            "  Variable: verify_mode\n"
            "  Source Type: EXPORTED_FUNCTION_PARAM\n"
            "  Source Details: secure_connect() (parameter 2: verify_mode)\n"
            "  Dataflow Path:\n"
            "    1. 0x12345 secure_connect: verify_mode is function parameter\n"
            "    2. 0x12350 init_ssl_ctx: verify_mode passed to SSL_CTX_set_verify\n"
            "- You: Call call_firmware_agent: 'Find binaries that call secure_connect and analyze parameter values'\n"
            "- Firmware agent: 'secure_connect called by /usr/bin/httpclient at 0x67890, passes constant 0 (SSL_VERIFY_NONE)'\n"
            "- You: Analyze the caller binary's behavior\n"
            "- You: Report:\n"
            "  Rule 2: Certificate Chain and Validity Checking\n"
            "  Status: CONDITIONAL\n"
            "  Evidence:\n"
            "    - SSL_CTX_set_verify at 0x12350: mode from verify_mode parameter\n"
            "    - secure_connect at 0x12345: exported library function, verify_mode is caller-controlled\n"
            "    - Caller analysis: /usr/bin/httpclient at 0x67890 calls secure_connect(ctx, 0)\n"
            "  Condition: Certificate verification depends on verify_mode parameter passed by caller to secure_connect()\n"
            "  Value-Result Mapping:\n"
            "    - verify_mode=0 (SSL_VERIFY_NONE): FAIL - Disables verification\n"
            "    - verify_mode=1 (SSL_VERIFY_PEER): PASS - Enables verification\n"
            "  Default: FAIL - Primary caller /usr/bin/httpclient passes verify_mode=0\n\n"
            "Example 6 - UNDETERMINED (tracking failed):\n"
            "- You: Find SSL_CTX_set_verify with mode parameter at 0x12345\n"
            "- You: Call call_dataflow_agent to trace mode\n"
            "- Dataflow agent reports:\n"
            "  Variable: mode\n"
            "  Source Type: UNDETERMINED\n"
            "  Source Details: Tracking stopped at indirect call via function pointer at 0x23456\n"
            "  Dataflow Path:\n"
            "    1. 0x12345 init_ssl: mode passed to SSL_CTX_set_verify\n"
            "    2. 0x23400 get_security_mode: mode from callback_table[config_type]()\n"
            "    3. 0x23456: indirect call through function pointer - multiple possible targets\n"
            "  Analysis Notes: Cannot determine which callback is invoked at runtime\n"
            "- You: Cannot verify security behavior due to complex control flow\n"
            "- You: Apply conservative security posture (unknown = insecure)\n"
            "- You: Report:\n"
            "  Rule 2: Certificate Chain and Validity Checking\n"
            "  Status: FAIL\n"
            "  Evidence:\n"
            "    - SSL_CTX_set_verify at 0x12345: mode from get_security_mode()\n"
            "    - get_security_mode at 0x23400: calls function pointer from callback_table\n"
            "    - Dataflow tracking stopped at 0x23456: indirect call through function pointer, multiple possible targets\n"
            "    - Cannot determine which callback is invoked or what values it returns\n"
            "    - Unable to verify that certificate verification is correctly implemented\n\n"
            "Example 7 - Cross-binary SSL implementation (PASS case):\n"
            "- You: Analyze SSL_connect but can't find SSL_verify_callback in current binary\n"
            "- You: Call call_firmware_agent: 'Find SSL_verify_callback implementation'\n"
            "- Firmware agent: 'SSL_verify_callback defined in libcustom_ssl.so at 0x8000'\n"
            "- You: Analyze callback and report:\n"
            "  Rule 3: Hostname Verification\n"
            "  Status: PASS\n"
            "  Evidence:\n"
            "    - SSL_set_verify at 0x4560: sets SSL_VERIFY_PEER with custom callback\n"
            "    - SSL_verify_callback at 0x8000 (libcustom_ssl.so): calls SSL_get_peer_certificate\n"
            "    - Callback implementation: checks X509_check_host for hostname match\n"
            "    - Always returns failure if hostname doesn't match certificate\n\n"
        )

    supervisor_agent = create_agent(
        model=model,
        tools=supervisor_tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are the SUPERVISOR AGENT - an orchestrator coordinating specialized agents to analyze SSL/TLS security.\n\n"
            "YOUR ROLE: Orchestration and Validation (NOT direct SSL analysis)\n"
            "You do NOT perform SSL analysis yourself. Instead, you:\n"
            "1. Fetch basic binary information using IDA tools\n"
            "2. Instruct the SSL analyzing agent to perform security analysis\n"
            "3. Validate results for completeness and clarity\n"
            "4. Coordinate helper agents (dataflow, firmware) when SSL agent requests assistance\n"
            "5. Synthesize the final comprehensive report\n\n"
            "AVAILABLE AGENTS:\n"
            "1. call_ssl_agent(request, call_graph_context) - SSL security expert\n"
            "   Returns: STATUS: COMPLETE | NEED_DATAFLOW | NEED_CROSS_BINARY_ANALYSIS | NEED_CONFIG_ANALYSIS | NEED_FIRMWARE | NOT_APPLICABLE\n\n"
            "2. call_dataflow_agent(request, context) - Variable tracing expert\n"
            "   Returns: Dataflow traces with categorized source types (may include multiple paths)\n\n"
            + firmware_capability +
            "\nORCHESTRATION WORKFLOW:\n\n"
            "STEP 1: Call SSL Analyzing Agent IMMEDIATELY\n"
            "   - YOUR FIRST ACTION MUST BE: call_ssl_agent('Analyze SSL/TLS security for this binary', call_graph_context)\n"
            "   - Do NOT gather info yourself first - the SSL agent will do that with its IDA tools\n"
            "   - The call graph context is already in your system prompt below - use it\n"
            "   - This is NOT optional - you MUST call the SSL agent as your first action\n\n"
            "STEP 2: Handle SSL Agent Response\n"
            "   - After calling call_ssl_agent, it will return one of 6 statuses:\n"
            "     * STATUS: COMPLETE - Analysis finished, results ready\n"
            "     * STATUS: NEED_DATAFLOW - Needs variable tracing\n"
            "     * STATUS: NEED_CROSS_BINARY_ANALYSIS - Needs caller binary analysis\n"
            "     * STATUS: NEED_CONFIG_ANALYSIS - Needs config/script parsing\n"
            "     * STATUS: NEED_FIRMWARE - Needs firmware file access\n"
            "     * STATUS: NOT_APPLICABLE - Not a client SSL binary\n\n"
            "   IF STATUS: COMPLETE:\n"
            "      → Proceed to validation (STEP 3)\n\n"
            "   IF STATUS: NEED_DATAFLOW:\n"
            "      → SSL agent will specify: Variable name, Context, Reason\n"
            "      → Call call_dataflow_agent with the request\n"
            "      → Dataflow agent returns categorized source type (may be single or multiple paths)\n"
            "      → Pass dataflow results back to SSL agent by calling it again with:\n"
            "        'Continue analysis with dataflow results: [paste dataflow output]'\n"
            "      → SSL agent may return COMPLETE or request more help (e.g., NEED_CROSS_BINARY_ANALYSIS if result is EXPORTED_FUNCTION_PARAM)\n"
            "      → Repeat until STATUS: COMPLETE\n\n"
            "   IF STATUS: NEED_CROSS_BINARY_ANALYSIS:\n"
            "      → SSL agent will specify: Function name, Parameter position, Context\n"
            + ("      → CROSS-BINARY ANALYSIS WORKFLOW:\n"
               "         1. Call call_firmware_agent: 'Find binaries that call [function_name]'\n"
               "         2. Firmware agent returns list of caller binaries (e.g., '/usr/bin/app1', '/usr/sbin/app2')\n"
               "         3. For EACH caller binary found:\n"
               "            a. Call call_dataflow_agent: 'In binary [caller_path], trace argument [N] passed to [function_name] call'\n"
               "            b. Dataflow may return: CONSTANT, CONFIG_FILE, ENVIRONMENT_VARIABLE, or another EXPORTED_FUNCTION_PARAM\n"
               "            c. If CONFIG_FILE/ENV_VAR returned → may need NEED_CONFIG_ANALYSIS for that caller\n"
               "            d. If EXPORTED_FUNCTION_PARAM returned → recurse (repeat cross-binary analysis for that function)\n"
               "            e. Track result for each caller: {caller_binary: result}\n"
               "         4. Aggregate ALL caller results into comprehensive report\n"
               "         5. Pass aggregated results back to SSL agent:\n"
               "            'Cross-binary analysis complete. Results for each caller:\n"
               "             Caller 1: [binary_path] → [dataflow result]\n"
               "             Caller 2: [binary_path] → [dataflow result]\n"
               "             ...'\n"
               "         6. SSL agent analyzes each caller's security outcome\n"
               "         7. Repeat until STATUS: COMPLETE\n\n"
               "      → CIRCULAR DEPENDENCY PREVENTION:\n"
               "         - Track analyzed binaries in a list\n"
               "         - If binary already analyzed → skip, report: 'Circular dependency detected'\n\n"
               "      → DEPTH TRACKING:\n"
               "         - Allow unlimited depth (follow chains until reaching concrete values)\n"
               "         - Stop recursion only when reaching: CONSTANT, CONFIG_FILE, ENV_VAR, CMD_ARG, or UNDETERMINED\n\n" if firmware_path else
               "      → Firmware agent not available - cannot perform cross-binary analysis\n"
               "      → Inform SSL agent: 'Cross-binary analysis not available - firmware agent required'\n"
               "      → SSL agent will mark as UNDETERMINED for that rule\n\n") +
            "   IF STATUS: NEED_CONFIG_ANALYSIS:\n"
            "      → SSL agent will specify: Source Type, Source Details (file path/env var/arg pattern), Setting name\n"
            + ("      → CONFIG/SCRIPT PARSING WORKFLOW:\n"
               "         1. Identify source type from SSL agent's request:\n"
               "            - CONFIG_FILE: file path (e.g., /etc/ssl.conf)\n"
               "            - ENVIRONMENT_VARIABLE: variable name (e.g., SSL_VERIFY)\n"
               "            - COMMAND_LINE_ARG: argument pattern\n\n"
               "         2. Call call_firmware_agent with specific request:\n"
               "            - For CONFIG_FILE: 'Read [file_path]'\n"
               "            - For ENV_VAR: 'Search startup scripts for export [var_name]='\n"
               "            - For CMD_ARG: 'Search scripts for binary invocations with [arg_pattern]'\n\n"
               "         3. Firmware agent returns:\n"
               "            - File contents with line numbers\n"
               "            - Script excerpts showing variable assignments\n"
               "            - Binary invocation commands\n\n"
               "         4. PARSE THE CONTENT using LLM reasoning:\n"
               "            - For config files: Parse key=value, key: value, XML, JSON, etc.\n"
               "            - For scripts: Extract export VAR=value or binary command-line args\n"
               "            - Identify the ACTUAL DEFAULT VALUE for the setting\n\n"
               "         5. Handle MULTIPLE CONFIGS (if firmware agent returns multiple files):\n"
               "            - Parse EACH config separately\n"
               "            - Track: {config_file: value}\n"
               "            - If different values → report ALL: 'Config A: value1, Config B: value2'\n\n"
               "         6. Pass parsed results back to SSL agent:\n"
               "            'Config analysis complete:\n"
               "             Source: [file/var/arg]\n"
               "             Setting: [setting_name]\n"
               "             Value: [actual_value]\n"
               "             Location: [file:line or script:line]'\n"
               "            OR for multiple configs:\n"
               "            'Config analysis complete - multiple sources:\n"
               "             Config 1 ([path]): [setting]=[value1] (line [N])\n"
               "             Config 2 ([path]): [setting]=[value2] (line [N])'\n\n"
               "         7. SSL agent uses parsed value to determine security outcome\n"
               "         8. Repeat until STATUS: COMPLETE\n\n" if firmware_path else
               "      → Firmware agent not available - cannot read config files\n"
               "      → Inform SSL agent: 'Config analysis not available - firmware agent required'\n"
               "      → SSL agent will report: 'Default: Not determined - firmware not accessible'\n\n") +
            "   IF STATUS: NEED_FIRMWARE:\n"
            "      → SSL agent will specify what it needs (config file, startup script, etc.)\n"
            + ("      → Call call_firmware_agent with the specific request\n"
               "      → Firmware agent returns file contents, config values, or script analysis\n"
               "      → Pass firmware results back to SSL agent by calling it again with:\n"
               "        'Continue analysis with firmware results: [paste firmware output]'\n"
               "      → SSL agent may return COMPLETE or request more help\n"
               "      → Repeat until STATUS: COMPLETE\n\n" if firmware_path else
               "      → Firmware agent not available\n"
               "      → Inform SSL agent: 'Firmware analysis not available'\n"
               "      → SSL agent will complete analysis with 'Not determined' for defaults\n\n") +
            "   IF STATUS: NOT_APPLICABLE:\n"
            "      → Binary is not an SSL client or has no SSL code\n"
            "      → Terminate with SSL agent's message\n\n"
            "STEP 3: Validate SSL Agent Results\n"
            "   When STATUS: COMPLETE, check the results for quality:\n\n"
            "   VALIDATION CHECKLIST:\n"
            "   ✓ All security rules addressed?\n"
            "   ✓ Each rule has PASS/FAIL/CONDITIONAL status?\n"
            "   ✓ Each rule has Evidence field?\n"
            "   ✓ For SINGLE-SOURCE CONDITIONAL rules, all 3 parts present?\n"
            "      - Condition Statement (clear, not cryptic like 'v58')\n"
            "      - Value-Result Mapping (complete with security implications)\n"
            "      - Firmware Default (actual value or 'Not determined' with reason)\n"
            "   ✓ For MULTI-SOURCE CONDITIONAL rules (multiple callers/configs):\n"
            "      - Condition Statement explains multiple sources exist\n"
            "      - Per-Source Analysis for EACH source (caller/config)\n"
            "      - Each source shows: identification, value, security result (PASS/FAIL)\n"
            "      - Overall Assessment summarizing PASS/FAIL count across sources\n"
            "   ✓ No cryptic variable names in final output?\n"
            "   ✓ Dataflow section included if variables were traced?\n"
            "   ✓ If multiple dataflow paths were found, all paths analyzed?\n\n"
            "   IF INCOMPLETE OR UNCLEAR:\n"
            "      → Call SSL agent again: 'Results incomplete. Please address: [specific issues]'\n"
            "      → Example: 'Rule 2 is marked CONDITIONAL but missing Firmware Default field'\n"
            "      → Example: 'Condition statement says \"depends on v58\" - clarify what v58 represents'\n"
            "      → Example: 'Dataflow returned 3 paths but only 1 path analyzed - analyze all paths'\n"
            "      → Example: 'Multi-source rule missing per-source security outcomes'\n\n"
            "   IF COMPLETE AND CLEAR:\n"
            "      → Proceed to STEP 4\n\n"
            "STEP 4: Synthesize Final Report\n"
            "   Generate the final report with EXACTLY these 3 sections:\n\n"
            "   SECTION 1 - Client Summary:\n"
            "     * Purpose: What this client is used for (e.g., HTTP client, FTP client, custom protocol)\n"
            "     * Connection flow: Steps to establish SSL/TLS connection (function call sequence)\n"
            "     * Dependencies: Config files or command-line arguments that control SSL/TLS behavior\n"
            "   SECTION 2 - Rule Checking Results:\n"
            "     * Rule-by-rule analysis with status: PASS | FAIL | CONDITIONAL\n"
            "     * PASS: Rule always respected, no conditions\n"
            "     * FAIL: Rule never respected, always violated\n"
            "     * CONDITIONAL: Rule respected only under certain conditions\n"
            "     * ALL results (PASS/FAIL/CONDITIONAL) MUST include an Evidence field with detailed supporting data:\n"
            "       - Evidence Format:\n"
            "         Evidence:\n"
            "           - [Function name at 0xADDRESS]: [observed behavior, parameters, or findings]\n"
            "           - [Code observation or decompiled snippet if relevant]\n"
            "           - [Constants, configurations, or dataflow findings]\n"
            "       - For PASS: Show function calls, parameter values, and code that prove secure implementation\n"
            "         Example: \"SSL_CTX_set_verify at 0x4015a0: called with SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT\"\n"
            "       - For FAIL: Show missing security calls, insecure parameters, or code bypassing security\n"
            "         Example: \"SSL_CTX_set_verify at 0x401620: called with SSL_VERIFY_NONE (0), disables all verification\"\n"
            "       - For CONDITIONAL: Show conditional branch/check, controlling variables, dataflow trace, config values\n"
            "         Example: \"SSL_CTX_set_verify at 0x401700: mode parameter from verify_mode variable (traced to config file)\"\n"
            "     * For CONDITIONAL: MUST include ALL three parts below:\n"
            "       1. Condition Statement: CLEAR, CONCRETE statement - NOT cryptic variable names\n"
            "          ✗ UNACCEPTABLE: \"Condition: Depends on v58\" or \"Condition: Depends on config\"\n"
            "          ✓ REQUIRED: Specify exactly what determines the behavior:\n"
            "            - \"Condition: Certificate verification depends on TLS_REQCERT value in /usr/etc.base/openldap/ldap.conf\"\n"
            "            - \"Condition: TLS version depends on min_protocol parameter from command-line --ssl-version argument\"\n"
            "            - \"Condition: Hostname verification depends on CHECK_HOSTNAME environment variable\"\n"
            "          Must include: What behavior + what source (config file path/env var/arg/etc.)\n\n"
            "       2. Value-Result Mapping: COMPLETE mapping with security interpretation for each value\n"
            "          ✗ UNACCEPTABLE: \"verify_mode: varies\" or \"Depends on configuration setting\"\n"
            "          ✓ REQUIRED: List each possible value with its security meaning:\n"
            "            - TLS_REQCERT=never (0): FAIL - Disables all certificate verification (SSL_VERIFY_NONE)\n"
            "            - TLS_REQCERT=allow (1): FAIL - Verification optional, accepts invalid certs\n"
            "            - TLS_REQCERT=try (2): FAIL - Attempts verification but doesn't enforce\n"
            "            - TLS_REQCERT=demand (3): PASS - Requires valid certificate (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)\n"
            "          Must include: Value + Numeric equivalent (if applicable) + PASS/FAIL + Security explanation\n\n"
            "       3. Firmware Default: ACTUAL default value found in firmware and its security result\n"
            "          ✗ UNACCEPTABLE: \"Depends on configuration\" or \"See config file\" or \"Variable v58\"\n"
            "          ✓ REQUIRED when firmware accessible:\n"
            "            - \"Default: FAIL - TLS_REQCERT=never (0) configured in /usr/etc.base/openldap/ldap.conf (line 34)\"\n"
            "            - \"Default: PASS - /etc/init.d/sslclient starts with --verify-ssl=strict\"\n"
            "            - \"Default: FAIL - CHECK_HOSTNAME not set in startup scripts (defaults to 0/disabled)\"\n"
            "          ✓ ACCEPTABLE when firmware NOT accessible:\n"
            "            - \"Default: Not determined - Configuration file /etc/app.conf not accessible without firmware\"\n"
            "            - \"Default: Not determined - Startup scripts not accessible\"\n"
            "          Must include: PASS/FAIL determination + Actual value + Source location (file path + line if possible)\n\n"
            "       CRITICAL REQUIREMENTS:\n"
            "       - NEVER use cryptic names like 'v58', 'a1', 'var_123' in Condition or Default fields\n"
            "       - ALWAYS provide actual default PASS/FAIL determination, not just 'conditional'\n"
            "       - If any part cannot be determined, MUST state \"Not determined: [specific reason]\"\n"
            "       - Do NOT omit any of the 3 parts - state uncertainty explicitly rather than omitting\n\n"
            "     * For MULTI-SOURCE CONDITIONAL (when multiple callers/configs with different outcomes):\n"
            "       Format differently - show per-source results:\n\n"
            "       1. Condition Statement: Explain multiple sources exist\n"
            "          ✓ REQUIRED: \"Certificate verification behavior depends on calling binary\" or\n"
            "                      \"Certificate verification depends on which configuration file is used\"\n\n"
            "       2. Per-Source Analysis: For EACH source, provide:\n"
            "          **Source 1: [identification]**\n"
            "          - Value: [actual value used]\n"
            "          - Result: PASS/FAIL - [explanation]\n"
            "          - Location: [binary path, config file:line, etc.]\n\n"
            "          **Source 2: [identification]**\n"
            "          - Value: [actual value used]\n"
            "          - Result: PASS/FAIL - [explanation]\n"
            "          - Location: [binary path, config file:line, etc.]\n\n"
            "          Example:\n"
            "          **Caller 1: /usr/bin/httpclient**\n"
            "          - Value: verify_mode=0 (SSL_VERIFY_NONE, hardcoded at 0x401000)\n"
            "          - Result: FAIL - Disables all certificate verification\n"
            "          - Location: httpclient binary, http_connect function at 0x401000\n\n"
            "          **Caller 2: /usr/sbin/ftpd**\n"
            "          - Value: verify_mode=1 (SSL_VERIFY_PEER, from /etc/ftpd.conf)\n"
            "          - Result: PASS - Requires valid certificate\n"
            "          - Location: ftpd binary, ftp_connect function reads /etc/ftpd.conf:34\n\n"
            "       3. Overall Assessment: Summarize across all sources\n"
            "          ✓ REQUIRED format:\n"
            "          \"Overall: [X]/[Total] sources FAIL, [Y]/[Total] sources PASS\"\n"
            "          \"Details: [brief summary of which sources are insecure]\"\n\n"
            "          Example:\n"
            "          \"Overall: 1/2 callers FAIL, 1/2 callers PASS\"\n"
            "          \"Details: httpclient uses insecure hardcoded settings; ftpd uses secure config-based settings\"\n\n"
            "       CRITICAL REQUIREMENTS:\n"
            "       - MUST list EVERY source/caller/config found\n"
            "       - MUST provide individual PASS/FAIL for each source\n"
            "       - MUST include overall summary statistics\n"
            "       - Do NOT aggregate into single PASS/FAIL - preserve per-source attribution\n\n"
            "   SECTION 3 - Dataflow Analysis:\n"
            "     * Complete dataflow traces for security-critical variables\n"
            "     * Show how data flows through the code (source → transformations → sink)\n"
            "   OUTPUT ONLY THESE 3 SECTIONS. Do NOT include:\n"
            "     * Recommendations\n"
            "     * Overall assessment\n"
            "     * Improvements or suggestions\n"
            "     * Best practice advice\n\n"
            "IMPORTANT REMINDERS:\n"
            "- You are an ORCHESTRATOR, not an SSL analyzer\n"
            "- YOUR FIRST TOOL CALL MUST BE: call_ssl_agent('Analyze SSL/TLS security for this binary', call_graph_context)\n"
            "- Do NOT use IDA tools yourself - the SSL agent has them and will use them\n"
            "- After SSL agent responds, validate results for completeness and clarity\n"
            "- Coordinate helper agents (dataflow/firmware) when SSL agent requests them\n"
            "- Synthesize the final report from SSL agent's complete results\n\n"
            + call_graph_context
        )
    )

    # TODO: The LLM should ask for external file access if needed.

    # Build user prompt for orchestrator role
    user_prompt = (
        "Orchestrate SSL/TLS security analysis for this binary.\n\n"
        "YOUR FIRST ACTION: Call call_ssl_agent with the call graph context from your system prompt.\n"
        "Do this IMMEDIATELY - do not gather information yourself first.\n\n"
        "After calling the SSL agent:\n"
        "- If STATUS: COMPLETE → Validate results and synthesize final report\n"
        "- If STATUS: NEED_DATAFLOW → Call dataflow agent, pass results back to SSL agent\n"
        "- If STATUS: NEED_CROSS_BINARY_ANALYSIS → Find caller binaries, analyze each, aggregate results\n"
        "- If STATUS: NEED_CONFIG_ANALYSIS → Read config/script, parse it, pass results back\n"
        "- If STATUS: NEED_FIRMWARE → Call firmware agent, pass results back to SSL agent\n"
        "- If STATUS: NOT_APPLICABLE → Report to user that binary is not applicable\n\n"
        "Final report must have EXACTLY these 3 sections:\n"
        "SECTION 1 - Client Summary\n"
        "SECTION 2 - Rule Checking Results (PASS/FAIL/CONDITIONAL with evidence)\n"
        "SECTION 3 - Dataflow Analysis\n\n"
        "Remember: The SSL agent analyzes. You orchestrate."
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

        # Display total elapsed time
        total_elapsed = time.perf_counter() - total_start_time
        console.print()
        console.print(Panel.fit(
            f"[bold blue]⏱  Total Analysis Time: {format_duration(total_elapsed)}[/bold blue]",
            border_style="blue"
        ))
        console.print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze SSL/TLS security using multi-agent system with IDA Pro"
    )
    parser.add_argument(
        "binary_path",
        type=str,
        help="Path to binary file to analyze (absolute or relative). Relative paths are resolved against --firmware-path if provided, otherwise against current working directory."
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
        default=None,
        help="Path to call graph JSON file (default: auto-generated in temp_files/)"
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
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8800,
        help="IDA headless server port (default: 8800, supports multiple instances)"
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"Maximum hops from SSL functions when trimming call graph (default: {DEFAULT_MAX_HOPS})"
    )
    parser.add_argument(
        "--trim-threshold",
        type=int,
        default=TRIM_THRESHOLD_NODES,
        help=f"Auto-trim call graph if it exceeds this many nodes (default: {TRIM_THRESHOLD_NODES})"
    )
    parser.add_argument(
        "--disable-trim",
        action="store_true",
        help="Disable automatic call graph trimming"
    )
    args = parser.parse_args()

    asyncio.run(main(
        file_path=args.binary_path,
        model=args.model,
        conn_type=args.conn_type,
        call_graph_path=args.call_graph,
        firmware_path=args.firmware_path,
        rules=args.rules,
        port=args.port,
        max_hops=args.max_hops,
        trim_threshold=args.trim_threshold,
        disable_trim=args.disable_trim
    ))
