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

async def main(model: str = "deepseek-chat", call_graph_path: str = "call_graph.json"):
    """
    Main function to analyze SSL/TLS connections using multi-agent system.

    Args:
        model: LLM model to use (default: "deepseek-chat")
        call_graph_path: Path to call graph JSON file (default: "call_graph.json")
    """
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

    # Initialize all agents
    global dataflow_agent, supervisor_agent

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

    firmware_traverse_agent = create_agent(
        model=model,
        tools=[find_import, find_export, grep, read_file],
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are a firmware analysis expert with direct access to firmware analysis tools. "
            "Your specialization is identifying and extracting relevant information from firmware binaries.\n\n"
            "TOOLS AVAILABLE:\n"
            "You have direct access to the following tools to analyze the firmware binary:\n"
            "- find_import: Find which binary calls the given function\n"
            "- find_export: Find which binary defines the given function\n"
            "- grep: Search for a pattern in a file\n"
            "- read_file: Read the contents of a file\n\n"
            "ANALYSIS APPROACH:\n"
            "1. Use the available tools to search for functions, strings, and other relevant information\n"
            "2. Analyze the results to extract meaningful insights about the firmware\n"
            "3. Correlate findings to build a comprehensive understanding of the firmware's behavior\n\n"
            "OUTPUT FORMAT:\n"
            "- Provide clear and structured analysis results\n"
            "- Highlight key findings and their implications\n"
            "- Include code excerpts with addresses and locations"
        )
    )

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
    supervisor_agent = create_agent(
        model=model,
        tools=tools + [call_dataflow_agent],  # IDA MCP tools + dataflow delegation
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are an SSL/TLS security analyst with direct access to IDA Pro tools and dataflow analysis support.\n\n"
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
            "SSL/TLS SECURITY RULES TO CHECK:\n"
            "1. Default verification (RECOMMENDED): SSL_CTX_set_verify or custom verification\n"
            "2. Hostname verification (MUST): X509_check_host or equivalent\n"
            "3. Result checking (MUST): When SSL_VERIFY_NONE is used, SSL_get_verify_result must be called\n"
            "4. Certificate expiration (RECOMMENDED): X509_get_notAfter checks\n"
            "5. Certificate revocation (RECOMMENDED): OCSP or CRL checks\n\n"
            "ANALYSIS WORKFLOW:\n"
            "1. Use IDA tools to search for SSL/TLS functions and analyze their usage\n"
            "   - Leverage the call graph context below to focus your analysis\n"
            "   - Decompile relevant functions to examine SSL/TLS code\n"
            "   - Check each security rule systematically\n\n"
            "2. Identify conditional security behavior:\n"
            "   - Flag parameters/variables that control security decisions\n"
            "   - Note when verification depends on runtime values (config flags, parameters, etc.)\n\n"
            "3. When you find conditional security:\n"
            "   - Call call_dataflow_agent to trace the controlling variable to its source\n"
            "   - Determine ultimate source: config file, command-line arg, hardcoded, etc.\n\n"
            "4. Synthesize comprehensive security report:\n"
            "   - Connection establishment flow\n"
            "   - Rule-by-rule analysis with PASS/FAIL/CONDITIONAL status\n"
            "   - For CONDITIONAL: include dataflow trace showing the variable source\n"
            "   - Highlight critical vulnerabilities vs. best practice recommendations\n\n"
            "EXAMPLE WORKFLOW:\n"
            "- You: Search for SSL_set_verify usage using IDA tools\n"
            "- You: Find SSL_set_verify uses parameter 'verify_flag' at 0x12345 (CONDITIONAL)\n"
            "- You: Call call_dataflow_agent to trace verify_flag\n"
            "- Dataflow agent: 'verify_flag comes from config file via read_config() at 0x23456'\n"
            "- You: Report complete findings with full context"
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

    await stream_and_log_agent(
        agent=supervisor_agent,
        messages=[{"role": "user", "content": user_prompt}],
        agent_name="Supervisor Agent",
        agent_emoji="🎯"
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze SSL/TLS security using multi-agent system with IDA Pro MCP tools"
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
    args = parser.parse_args()

    asyncio.run(main(args.model, args.call_graph))
