#!/usr/bin/env python3
import argparse
import json
import logging
import re
from typing import List, Optional

import idapro
import idautils
import ida_xref
import idc
import networkx as nx

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Library-specific function patterns for call graph filtering
LIBRARY_PATTERNS = {
    "openssl": [r"\.?SSL_.*", r"\.?X509_.*", r"\.?TLS_.*", r"\.?DTLS_.*"],
    "libcurl": [r"curl_easy_.*", r"curl_multi_.*", r"curl_global_.*", r"curl_.*"],
    "gnutls": [r"gnutls_.*"],
    "mbedtls": [r"mbedtls_.*"],
    "php_curl": [],  # Script-based, no binary patterns needed
    "curl": [],      # Command-line tool, no binary patterns needed
    "wget": [],      # Command-line tool, no binary patterns needed
    "socket": [r"socket", r"connect", r"bind", r"listen", r"accept", r"send", r"recv"],
}

# Libraries that require binary analysis (IDA-based call graph)
BINARY_LIBRARIES = {"openssl", "libcurl", "gnutls", "mbedtls", "socket"}

# Libraries that use script analysis (no call graph needed)
SCRIPT_LIBRARIES = {"php_curl", "curl", "wget"}

# Legacy name for backward compatibility
ssl_function_patterns = LIBRARY_PATTERNS["openssl"]

# Call graph trimming configuration
DEFAULT_MAX_HOPS = 3  # Maximum hops from SSL functions to keep
TRIM_THRESHOLD_NODES = 100  # Auto-trim if graph exceeds this many nodes
CENTRALITY_PERCENTILE = 0.80  # Keep nodes in top 20% by betweenness centrality


def get_function_patterns(library: str) -> list[str]:
    """Get function patterns for a specific library.

    Args:
        library: Library name (e.g., "openssl", "libcurl", "gnutls")

    Returns:
        List of regex patterns for filtering library functions
    """
    return LIBRARY_PATTERNS.get(library, LIBRARY_PATTERNS["openssl"])


def requires_binary_analysis(library: str) -> bool:
    """Check if library requires binary analysis (call graph generation).

    Args:
        library: Library name

    Returns:
        True if library needs binary analysis, False for script-based libraries
    """
    return library in BINARY_LIBRARIES


class IDABackend:
    """Backend for interacting with IDA Pro to analyze binaries."""

    def __init__(self, binary_path: str, enable_ida_msg: bool = False):
        self.binary_path = binary_path
        self.enable_ida_msg = enable_ida_msg
        self.is_open = False

        idapro.enable_console_messages(self.enable_ida_msg)

        # Open the database
        if idapro.open_database(binary_path, True) == 0:
            logger.info("IDA database opened successfully.")
            self.is_open = True
        else:
            logger.error("Failed to open IDA database.")
            raise RuntimeError(f"Failed to open IDA database: {binary_path}")

    def __del__(self):
        """Close the IDA database when the object is destroyed."""
        if self.is_open:
            idapro.close_database()
            logger.info("IDA database closed.")

    def ensure_open(self):
        """Ensure the IDA database is open."""
        if not self.is_open:
            raise RuntimeError("IDA database is not open.")

    def get_func_name_by_addr(self, addr: int) -> Optional[str]:
        """Get function name by address.

        Args:
            addr: Function address

        Returns:
            Function name or None if not found
        """
        if addr == idc.BADADDR:
            return None
        name = idc.get_func_name(addr)
        return name if name else None

    def get_func_list_in_addr(self) -> list[int]:
        """Get a list of all functions in the database."""
        return list(idautils.Functions())

    def get_func_list_in_name(self) -> list[str]:
        """Get a list of all function names in the database."""
        func_names = []
        for func_addr in idautils.Functions():
            func_name = idc.get_func_name(func_addr)
            if func_name:
                func_names.append(func_name)
        return func_names

    def get_func_name_by_addr(self, addr: int) -> str:
        return idc.get_func_name(addr)

    def generate_call_graph(self, filtered_functions: list[str] = None, record_indirect_calls: bool = False) -> nx.DiGraph:
        call_graph = nx.DiGraph()

        function_list = idautils.Functions()

        if filtered_functions:
            function_list = [f for f in function_list if idc.get_func_name(
                f) in filtered_functions]

        # Iterative approach using a queue
        visited = set()
        # Initialize queue with starting functions
        to_process = list(function_list)

        while to_process:
            func_addr = to_process.pop(0)  # Get next function to process
            # logger.debug(f'Processing function at {func_addr:#x}, remaining functions in the queue: {[hex(addr) for addr in to_process]}.')
            if func_addr in visited:
                continue

            visited.add(func_addr)
            func_name = idc.get_func_name(func_addr)
            if not func_name:
                continue

            call_graph.add_node(func_name, addr=func_addr)

            # Get all cross-references from this function
            # 
            # When the function is indirectly called, there will be no result
            # returned by idautils.CodeRefsTo. We need to use idautils.XrefsTo
            # to get the references. The result might be incorrect, we need to
            # check them manually.
            # 
            # Xref type names table
            # _ref_types = {
            #     ida_xref.fl_U  : 'Data_Unknown',
            #     ida_xref.dr_O  : 'Data_Offset',
            #     ida_xref.dr_W  : 'Data_Write',
            #     ida_xref.dr_R  : 'Data_Read',
            #     ida_xref.dr_T  : 'Data_Text',
            #     ida_xref.dr_I  : 'Data_Informational',
            #     ida_xref.fl_CF : 'Code_Far_Call',
            #     ida_xref.fl_CN : 'Code_Near_Call',
            #     ida_xref.fl_JF : 'Code_Far_Jump',
            #     ida_xref.fl_JN : 'Code_Near_Jump',
            #     20 : 'Code_User',
            #     ida_xref.fl_F : 'Ordinary_Flow'
            # }
            for xref in idautils.XrefsTo(func_addr):
                call_site = xref.frm
                xref_type = xref.type
                xref_type_name = idautils.XrefTypeName(xref_type)

                # The xref in .data segment is also type of dr_O, so we need to
                # check if the reference site is in .text segment.
                if record_indirect_calls and xref_type == ida_xref.dr_O and self.is_in_text_segment(call_site):
                    logger.warning(f'Possible indirect call detected at {call_site:#x} to {func_name}. You might want to check it manually.')
                elif xref_type in [ida_xref.fl_F, ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN]:
                    pass
                else:
                    # logger.warning(f'Unknown xref type {xref_type_name} at {call_site:#x} to {func_name}. Skipping it. Please check manually.')
                    continue

                caller_name = idc.get_func_name(call_site)
                caller_addr = idc.get_func_attr(call_site, idc.FUNCATTR_START)

                if not caller_name:
                    logger.warning(f'Caller at {call_site:#x} has no name.')
                    continue

                # Add callsite address to the node attributes
                call_graph.add_node(caller_name, addr=caller_addr)
                call_graph.add_edge(caller_name, func_name,
                                    call_site=call_site)
                # logger.debug(f'Added edge from {caller_name} to {func_name}')

                # Add to queue if not visited
                if caller_addr not in visited:
                    to_process.append(caller_addr)
                    # logger.debug(f'Added new function {caller_name} to the queue.')

        logger.debug("Generated call graph with %d nodes", len(call_graph))
        return call_graph

    # ============================================================================
    # EXTENSIBILITY POINT: Future static analysis methods
    # ============================================================================
    # Add additional analysis methods here for future expansion:
    # - def extract_strings(self, patterns: list[str]) -> dict
    # - def analyze_control_flow(self, func_addr: int) -> ControlFlowGraph
    # - def trace_dataflow(self, var_name: str, func_addr: int) -> DataflowTrace
    # ============================================================================


def trim_call_graph(
    graph: nx.DiGraph,
    ssl_functions: list[str],
    max_hops: int = DEFAULT_MAX_HOPS,
    centrality_percentile: float = CENTRALITY_PERCENTILE
) -> tuple[nx.DiGraph, dict]:
    """Trim call graph to reduce complexity while preserving important nodes.

    Uses a hybrid approach combining:
    1. Hop distance from SSL functions (keep nodes within max_hops)
    2. Betweenness centrality (keep important junction nodes)

    Args:
        graph: Original call graph
        ssl_functions: List of SSL/TLS function names (leaf nodes)
        max_hops: Maximum hops from SSL functions to keep (default: 3)
        centrality_percentile: Percentile threshold for centrality (default: 0.80, keeps top 20%)

    Returns:
        Tuple of (trimmed_graph, statistics_dict)
    """
    if len(graph.nodes) == 0:
        return graph, {"trimmed": False, "reason": "empty_graph"}

    # Calculate hop distances from SSL functions using BFS
    hop_distances = {}
    for ssl_func in ssl_functions:
        if ssl_func not in graph:
            continue

        # BFS backward from SSL function to find all callers
        visited = {ssl_func: 0}
        queue = [(ssl_func, 0)]

        while queue:
            node, dist = queue.pop(0)

            # Find all callers (predecessors in the call graph)
            for predecessor in graph.predecessors(node):
                if predecessor not in visited:
                    visited[predecessor] = dist + 1
                    queue.append((predecessor, dist + 1))
                else:
                    # Update to minimum distance if we found a shorter path
                    visited[predecessor] = min(visited[predecessor], dist + 1)

        # Merge distances (keep minimum distance to any SSL function)
        for node, dist in visited.items():
            if node not in hop_distances:
                hop_distances[node] = dist
            else:
                hop_distances[node] = min(hop_distances[node], dist)

    # Calculate betweenness centrality (importance as junction points)
    try:
        centrality = nx.betweenness_centrality(graph)
        # Calculate threshold for high centrality
        centrality_values = list(centrality.values())
        if centrality_values:
            import numpy as np
            centrality_threshold = np.percentile(centrality_values, centrality_percentile * 100)
        else:
            centrality_threshold = 0
    except Exception as e:
        logger.warning(f"Failed to calculate betweenness centrality: {e}. Using hop distance only.")
        centrality = {}
        centrality_threshold = 0

    # Determine which nodes to keep
    nodes_to_keep = set()
    for node in graph.nodes():
        # Always keep SSL functions
        if node in ssl_functions:
            nodes_to_keep.add(node)
            continue

        # Keep if within hop distance
        if node in hop_distances and hop_distances[node] <= max_hops:
            nodes_to_keep.add(node)
            continue

        # Keep if high centrality (important junction point)
        if node in centrality and centrality[node] >= centrality_threshold:
            nodes_to_keep.add(node)
            continue

    # Create trimmed graph
    trimmed_graph = graph.subgraph(nodes_to_keep).copy()

    # Collect statistics
    stats = {
        "trimmed": True,
        "original_nodes": len(graph.nodes),
        "original_edges": len(graph.edges),
        "trimmed_nodes": len(trimmed_graph.nodes),
        "trimmed_edges": len(trimmed_graph.edges),
        "nodes_removed": len(graph.nodes) - len(trimmed_graph.nodes),
        "edges_removed": len(graph.edges) - len(trimmed_graph.edges),
        "max_hops_used": max_hops,
        "centrality_percentile": centrality_percentile
    }

    logger.info(f"Call graph trimmed: {stats['original_nodes']} → {stats['trimmed_nodes']} nodes "
                f"({stats['nodes_removed']} removed), "
                f"{stats['original_edges']} → {stats['trimmed_edges']} edges "
                f"({stats['edges_removed']} removed)")

    return trimmed_graph, stats


def export_to_json(graph: nx.DiGraph, binary_path: str, output_path: str, trim_stats: dict = None):
    """Export call graph to JSON format for LangChain consumption.

    Args:
        graph: NetworkX graph to export
        binary_path: Path to the binary file
        output_path: Path to output JSON file
        trim_stats: Optional trimming statistics to include in metadata
    """
    # Prepare data structure
    metadata = {
        "binary": binary_path,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "ssl_patterns": ssl_function_patterns
    }

    # Add trimming information if available
    if trim_stats:
        metadata["trimming"] = trim_stats

    data = {
        "metadata": metadata,
        "nodes": [],
        "edges": []
    }

    # Add nodes with metadata
    for node in graph.nodes():
        addr = graph.nodes[node].get("addr")
        node_data = {
            "name": node,
            "address": hex(addr) if addr is not None else "unknown",
        }
        data["nodes"].append(node_data)

    # Add edges
    for source, target in graph.edges():
        call_site = graph.edges[source, target].get("call_site")
        edge_data = {
            "caller": source,
            "callee": target,
            "call_site": hex(call_site) if call_site is not None else None
        }
        data["edges"].append(edge_data)

    # Write to file
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    logger.info(f"Call graph exported to {output_path}")


def draw_call_graph(call_graph: nx.DiGraph, root=None, output_file: Optional[str] = None, highlight_nodes: list = []) -> None:
    A = nx.nx_agraph.to_agraph(call_graph)
    A.graph_attr['ranksep'] = '2.0'  # Add vertical spacing between nodes

    # Highlight specified nodes
    for node in highlight_nodes:
        if node in A.nodes():
            A.get_node(node).attr['color'] = 'blue'
            A.get_node(node).attr['style'] = 'filled'
            A.get_node(node).attr['fillcolor'] = 'lightblue'

    A.layout('dot')
    A.draw(output_file, format='pdf')
    logger.info(f'Call graph saved to: {output_file}')


def main():
    """Main entry point for the script (CLI usage)."""
    parser = argparse.ArgumentParser(
        description="Generate call graph for SSL/TLS functions in a binary using IDA Pro"
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the binary file to analyze"
    )
    parser.add_argument(
        "--output",
        default="call_graph.json",
        help="Output JSON file path (default: call_graph.json)"
    )
    parser.add_argument(
        "--library",
        type=str,
        default="openssl",
        choices=list(LIBRARY_PATTERNS.keys()),
        help="SSL/TLS library to analyze (default: openssl)"
    )
    parser.add_argument(
        "--enable-ida-msg",
        action="store_true",
        help="Enable IDA console messages"
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"Maximum hops from SSL functions to keep when trimming (default: {DEFAULT_MAX_HOPS})"
    )
    parser.add_argument(
        "--trim-threshold",
        type=int,
        default=TRIM_THRESHOLD_NODES,
        help=f"Auto-trim if graph exceeds this many nodes (default: {TRIM_THRESHOLD_NODES})"
    )
    parser.add_argument(
        "--disable-trim",
        action="store_true",
        help="Disable automatic call graph trimming"
    )

    args = parser.parse_args()

    try:
        # Initialize IDA backend
        logger.info(f"Opening binary: {args.binary}")
        backend = IDABackend(args.binary, enable_ida_msg=args.enable_ida_msg)

        # Filter library-specific functions
        logger.info(f"Filtering {args.library} functions...")
        patterns = get_function_patterns(args.library)
        if not patterns:
            logger.warning(f"No function patterns defined for library '{args.library}'. Analyzing all functions.")
            filtered_functions = backend.get_func_list_in_name()
        else:
            pattern = re.compile("|".join(patterns))
            filtered_functions = [f for f in backend.get_func_list_in_name() if pattern.search(f)]

        logger.info(f'Found {len(filtered_functions)} {args.library} functions in total.')
        logger.info(f'Functions: {filtered_functions}')

        # Generate call graph
        logger.info("Generating call graph...")
        call_graph = backend.generate_call_graph(filtered_functions=filtered_functions)

        # Auto-trim if enabled and threshold exceeded
        trim_stats = None
        if not args.disable_trim and len(call_graph.nodes) > args.trim_threshold:
            logger.info(f"Call graph has {len(call_graph.nodes)} nodes (threshold: {args.trim_threshold}). Trimming...")
            call_graph, trim_stats = trim_call_graph(
                call_graph,
                filtered_functions,
                max_hops=args.max_hops,
                centrality_percentile=CENTRALITY_PERCENTILE
            )
        elif args.disable_trim:
            logger.info("Call graph trimming disabled by user.")
        else:
            logger.info(f"Call graph has {len(call_graph.nodes)} nodes (threshold: {args.trim_threshold}). No trimming needed.")

        # Export to JSON
        logger.info(f"Exporting to {args.output}...")
        export_to_json(call_graph, args.binary, args.output, trim_stats=trim_stats)

        # Print summary
        print("\n" + "="*50)
        print("Call Graph Generation Complete")
        print("="*50)
        print(f"Binary: {args.binary}")
        print(f"Library: {args.library}")
        print(f"Output: {args.output}")
        if trim_stats:
            print(f"Nodes (functions): {len(call_graph.nodes)} (trimmed from {trim_stats['original_nodes']})")
            print(f"Edges (calls): {len(call_graph.edges)} (trimmed from {trim_stats['original_edges']})")
            print(f"Trimming: {trim_stats['nodes_removed']} nodes, {trim_stats['edges_removed']} edges removed")
            print(f"Max hops: {trim_stats['max_hops_used']}")
        else:
            print(f"Nodes (functions): {len(call_graph.nodes)}")
            print(f"Edges (calls): {len(call_graph.edges)}")
        print("="*50)

        # Draw the call graph
        draw_call_graph(call_graph, output_file="call_graph.pdf", highlight_nodes=filtered_functions)

    except Exception as e:
        logger.error(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
