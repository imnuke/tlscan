import os
import sys
import json
import asyncio
import argparse
import subprocess
import time
import requests
from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain_core.messages import ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console
from rich.markdown import Markdown, Heading
from rich.panel import Panel
from rich import box
from firmware_tools import (
    find_import,
    find_export,
    grep,
    read_file
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
    # Load call graph if available
    call_graph_data = None
    if call_graph_path and os.path.exists(call_graph_path):
        try:
            with open(call_graph_path, 'r') as f:
                call_graph_data = json.load(f)
            console.print(f"[green]✓[/green] Loaded call graph from [bold]{call_graph_path}[/bold]")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow]  Failed to load call graph: {e}")
    elif call_graph_path:
        console.print(f"[yellow]⚠[/yellow]  Call graph file not found: {call_graph_path}")

    server_process = None  # Track server process for cleanup
    server_script = '/home/peng/Projects/others/ida-pro-mcp/src/ida_pro_mcp/server.py'

    try:
        if conn_type == 'headless_ida':
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
        firmware_traverse_agent = create_agent(
            model=model,
            tools=[find_import, find_export, grep, read_file],
            middleware=[handle_tool_errors],
            system_prompt=(
                f"You are a firmware filesystem expert specializing in cross-binary analysis, configuration files, and scripts. "
                f"Your role is to analyze firmware files at: {firmware_path}\n\n"
            "PRIMARY USE CASES:\n"
            "1. Cross-binary analysis: Trace functions across multiple binaries in the firmware\n"
            "2. Configuration analysis: Find and analyze config files that affect SSL/TLS behavior\n"
            "3. Script analysis: Examine startup/shell scripts that configure services\n\n"
            "TOOLS AND THEIR USES:\n"
            "- find_export(function_name): Find which binary DEFINES a function (implementation location)\n"
            "  • Use when: Looking for where a function is implemented\n"
            "  • Example: find_export('SSL_verify_callback') → returns binary that contains this function\n\n"
            "- find_import(function_name): Find which binary CALLS a function (usage location)\n"
            "  • Use when: Looking for binaries that use a specific function\n"
            "  • Example: find_import('SSL_CTX_set_verify') → returns binaries calling this function\n\n"
            "- grep(pattern, file_path): Search for patterns in files\n"
            "  • Use when: Searching for config keys, function names, or security-related strings\n"
            "  • Example: grep('ssl_verify', '/etc/config.conf') → find SSL verification settings\n\n"
            "- read_file(file_path): Read full contents of a file\n"
            "  • Use when: Need complete context after finding relevant sections\n"
            "  • Example: read_file('/etc/ssl.conf') → read entire SSL configuration\n\n"
            "ANALYSIS WORKFLOW:\n"
            "1. For cross-binary tracing:\n"
            "   - Use find_export to locate function implementation\n"
            "   - Use find_import to find all callers across binaries\n"
            "   - Map the complete call chain across firmware components\n\n"
            "2. For configuration analysis:\n"
            "   - Use grep to search for SSL/TLS-related settings in config files\n"
            "   - Use read_file to get full context once relevant files are identified\n"
            "   - Identify default values, conditional settings, and security flags\n\n"
            "3. For script analysis:\n"
            "   - Use grep to find scripts that mention SSL/TLS commands or binaries\n"
            "   - Use read_file to analyze complete script logic\n"
            "   - Identify runtime configuration, environment variables, command-line args\n\n"
            "OUTPUT FORMAT:\n"
            "- File paths with line numbers (e.g., '/etc/ssl.conf:42')\n"
            "- Relevant excerpts with surrounding context (3-5 lines)\n"
            "- Binary relationships: 'binary_A imports SSL_verify from binary_B'\n"
            "- Security implications: How findings affect SSL/TLS security\n"
            "- Cross-references: 'Function X defined in libssl.so, called by httpd and ftpd'\n\n"
            "EXAMPLE SCENARIOS:\n"
            "- Q: 'Is SSL_verify_callback implemented in another binary?'\n"
            "  A: Use find_export('SSL_verify_callback') to locate implementation\n\n"
            "- Q: 'Which config file controls SSL verification behavior?'\n"
            "  A: Use grep('ssl_verify', '/etc/*') then read_file on matches\n\n"
            "- Q: 'Does any startup script disable SSL verification?'\n"
            "  A: Use grep('SSL_VERIFY_NONE|--no-verify', '/etc/init.d/*') and analyze results"
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
        firmware_workflow = (
            "2. When functions might be in other binaries:\n"
            "   - Call call_firmware_agent to find cross-binary dependencies\n"
            "   - Identify which binaries implement/call SSL/TLS functions\n"
            "   - Example: Custom SSL_verify_callback might be in a separate library\n\n"
        )
        firmware_dataflow_note = "\n   - If source appears to be external (config file, script), call call_firmware_agent"
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

    # Simplified user prompt - call graph is now in system prompt
    user_prompt = (
        "Analyze the SSL/TLS security of this binary. The binary may use OpenSSL or similar libraries "
        "to establish secure connections.\n\n"
        "Your task:\n"
        "1. Use IDA tools to analyze the SSL/TLS implementation (leverage the call graph context in your system prompt)\n"
        "2. Check compliance with SSL/TLS security best practices\n"
        "3. When you find conditional security behavior (e.g., verification depends on a config flag), "
        "use the dataflow agent to trace where the controlling variable comes from\n"
        "4. Provide a comprehensive security report with:\n"
        "   - Connection establishment flow\n"
        "   - Security rule compliance (PASS/FAIL/CONDITIONAL)\n"
        "   - Dataflow traces for security-critical variables"
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
