"""
Call graph generation using IDA Pro.

Provides functionality to generate and export call graphs for SSL/TLS analysis.
"""

import sys
import json
import re
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add project root to path for importing project modules
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from static_analyzer import (
    IDABackend,
    export_to_json,
    draw_call_graph,
    get_function_patterns,
    trim_call_graph,
)
from conn_analyzer.config import (
    DEFAULT_MAX_HOPS,
    TRIM_THRESHOLD_NODES,
    CENTRALITY_PERCENTILE,
)
from conn_analyzer.utils.formatting import format_duration

# Initialize console for output
console = Console()


def generate_call_graph_for_binary(
    binary_path: str,
    output_json_path: str,
    library: str = "openssl",
    enable_ida_msg: bool = False,
    max_hops: int = DEFAULT_MAX_HOPS,
    trim_threshold: int = TRIM_THRESHOLD_NODES,
    disable_trim: bool = False
) -> dict:
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
