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
ssl_analysis_agent = None

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
    result = await dataflow_agent.ainvoke(
        {"messages": [{"role": "user", "content": full_request}]}
    )
    return result["messages"][-1].content

@tool
async def call_ssl_agent(request: str, context: str = "") -> str:
    """
    Analyze SSL/TLS security practices against security rules.

    Use this tool to check if code violates SSL/TLS security best practices,
    identify conditional security behavior, and flag parameters/config that
    affect security.

    Args:
        request: SSL security analysis question
        context: Relevant SSL-related code/function information

    Returns:
        SSL security analysis with rule violations and conditional behaviors
    """
    full_request = f"{request}\n\nContext:\n{context}" if context else request
    result = await ssl_analysis_agent.ainvoke(
        {"messages": [{"role": "user", "content": full_request}]}
    )
    return result["messages"][-1].content

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
    global dataflow_agent, ssl_analysis_agent, supervisor_agent

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

    # 2. SSL Security Analysis Agent - checks SSL/TLS security rules
    ssl_analysis_agent = create_agent(
        model=model,
        tools=tools,
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are an SSL/TLS security expert with direct access to IDA Pro MCP tools. "
            "Your specialization is identifying security vulnerabilities in SSL/TLS implementations.\n\n"
            "IDA TOOLS AVAILABLE:\n"
            "You have direct access to all IDA Pro tools to query the binary as needed:\n"
            "- Get function details, decompilation, disassembly\n"
            "- Find cross-references (xrefs), callers, and callees\n"
            "- Search for SSL/TLS functions, strings, and globals\n"
            "- Analyze structures, variables, and data types\n\n"
            "SECURITY RULES TO CHECK:\n"
            "1. Default verification (RECOMMENDED): SSL_CTX_set_verify or custom verification\n"
            "2. Hostname verification (MUST): X509_check_host or equivalent\n"
            "3. Result checking (MUST): When SSL_VERIFY_NONE is used, SSL_get_verify_result must be called\n"
            "4. Certificate expiration (RECOMMENDED): X509_get_notAfter checks\n"
            "5. Certificate revocation (RECOMMENDED): OCSP or CRL checks\n\n"
            "ANALYSIS APPROACH:\n"
            "1. Use IDA tools to search for SSL/TLS functions and understand their usage\n"
            "2. Decompile relevant functions to analyze SSL/TLS code\n"
            "3. Check each security rule systematically\n"
            "4. Identify conditional security behavior (e.g., 'verification enabled only if config flag set')\n"
            "5. Flag parameters/variables that control security decisions\n"
            "6. Use xrefs and caller analysis to understand control flow\n"
            "7. Note custom implementations that might fulfill security requirements\n\n"
            "CRITICAL: When you find that security behavior depends on runtime values "
            "(parameters, config flags, globals), explicitly state:\n"
            "- The variable/parameter name\n"
            "- Which function/location uses it\n"
            "- What security decision it controls\n"
            "This signals the supervisor to request dataflow analysis.\n\n"
            "OUTPUT FORMAT:\n"
            "- Rule-by-rule analysis with PASS/FAIL/CONDITIONAL status\n"
            "- For CONDITIONAL: Describe what condition affects security\n"
            "- Highlight variables that need dataflow tracing\n"
            "- Provide code excerpts with addresses and locations"
        )
    )

    # 3. Supervisor Agent - coordinates worker agents
    supervisor_agent = create_agent(
        model=model,
        tools=[call_dataflow_agent, call_ssl_agent],
        middleware=[handle_tool_errors],
        system_prompt=(
            "You are a supervisor agent coordinating SSL/TLS security analysis. "
            "You manage two specialized worker agents, both of which have direct access to IDA Pro tools.\n\n"
            "WORKER AGENTS:\n"
            "1. SSL Security Agent (call_ssl_agent):\n"
            "   - Has direct IDA MCP access to query the binary\n"
            "   - Analyzes SSL/TLS implementations against security rules\n"
            "   - Identifies violations and conditional security behaviors\n"
            "   - Reports variables/parameters that control security decisions\n\n"
            "2. Dataflow Analysis Agent (call_dataflow_agent):\n"
            "   - Has direct IDA MCP access to query the binary\n"
            "   - Performs forward/backward slicing and inter-procedural analysis\n"
            "   - Traces variables to their ultimate sources (config, argv, network, etc.)\n"
            "   - Tracks data propagation through the program\n\n"
            "ANALYSIS WORKFLOW:\n"
            "1. Start with call_ssl_agent to analyze SSL/TLS security\n"
            "   - The SSL agent will autonomously query IDA to gather necessary code\n"
            "   - It will check each security rule and identify violations\n\n"
            "2. When SSL agent reports CONDITIONAL security behavior:\n"
            "   - The agent will highlight which variable/parameter controls security\n"
            "   - Call call_dataflow_agent to trace that variable to its source\n"
            "   - Dataflow agent will autonomously query IDA for callers, function details, etc.\n"
            "   - Determine ultimate source: config file, command-line arg, hardcoded, etc.\n\n"
            "3. Synthesize findings into comprehensive security report\n\n"
            "EXAMPLE WORKFLOW:\n"
            "- You: Call SSL agent to analyze the binary\n"
            "- SSL agent: 'SSL_set_verify uses parameter verify_flag at 0x12345 (CONDITIONAL)'\n"
            "- You: Call dataflow agent to trace verify_flag\n"
            "- Dataflow agent: 'verify_flag comes from config file via read_config() at 0x23456'\n"
            "- You: Report complete findings with full context\n\n"
            "KEY POINTS:\n"
            "- Both workers are self-sufficient and query IDA directly\n"
            "- Your role is coordination, not being a tool proxy\n"
            "- Focus on synthesizing worker outputs into clear security assessments\n\n"
            "OUTPUT REQUIREMENTS:\n"
            "- Provide a clear, structured security assessment\n"
            "- For each rule: status (PASS/FAIL/CONDITIONAL) with evidence\n"
            "- For conditional behavior: include dataflow trace showing the source\n"
            "- Highlight critical vulnerabilities vs. best practice recommendations"
        )
    )

    # TODO: The LLM should ask for external file access if needed.

    # Format call graph if available
    call_graph_section = ""
    if call_graph_data:
        call_graph_text = format_call_graph(call_graph_data)
        call_graph_section = (
            "## Available Call Graph Information\n\n"
            "Below is the call graph extracted from the binary showing SSL/TLS function usage and call relationships. "
            "Use this to guide your analysis.\n\n"
            + call_graph_text + "\n\n"
            "---\n\n"
        )

    user_prompt = (
        call_graph_section +
        "Analyze the SSL/TLS security of this binary. The binary may use OpenSSL or similar libraries "
        "to establish secure connections.\n\n"
        "Your task:\n"
        "1. Use your worker agents to thoroughly analyze the SSL/TLS implementation\n"
        "2. Check compliance with SSL/TLS security best practices\n"
        "3. When you find conditional security behavior (e.g., verification depends on a config flag), "
        "use dataflow analysis to trace where the controlling variable comes from\n"
        "4. Provide a comprehensive security report with:\n"
        "   - Connection establishment flow\n"
        "   - Security rule compliance (PASS/FAIL/CONDITIONAL)\n"
        "   - Dataflow traces for security-critical variables\n"
        "Coordinate your worker agents effectively to produce a thorough analysis."
    )

    console.print(Panel.fit("[bold cyan]Starting Supervisor Agent[/bold cyan]", border_style="cyan"))
    console.print()

    async for chunk in supervisor_agent.astream(
        {"messages": [{"role": "user", "content": user_prompt}]},
        stream_mode="values",
        config={"recursion_limit": 100}
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
