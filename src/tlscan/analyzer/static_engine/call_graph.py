"""API-centric call graph pre-analysis for IDA Pro static analysis.

Builds a call graph starting from known SSL/TLS API functions (leaf nodes)
and walking upward via ``get_callers`` using BFS. The resulting graph gives
the SSL agent a structural map of the binary before analysis begins,
reducing token waste on function discovery.

No LLM is involved — this is a deterministic, pre-workflow step.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rich.console import Console

from tlscan.config import (
    CALL_GRAPH_MAX_DEPTH,
    CALL_GRAPH_MAX_NODES_PER_LEVEL,
    CALL_GRAPH_MAX_TEXT_LENGTH,
)
from tlscan.analyzer.static_engine.signatures import (
    discover_tool,
    load_signatures,
    parse_address_from_result,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool name candidates (runtime discovery order)
# ---------------------------------------------------------------------------

_FUNC_LOOKUP_CANDIDATES = [
    "get_function_by_name",
    "get_function_info",
]

_CALLERS_CANDIDATES = [
    "get_callers",
    "get_xrefs_to",
]

_ENTRY_POINT_CANDIDATES = [
    "is_entry_point",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class NodeKind(str, Enum):
    API = "api"
    INTERNAL = "internal"
    ENTRY = "entry"


@dataclass
class CallGraphNode:
    name: str
    address: Optional[int] = None
    kind: NodeKind = NodeKind.INTERNAL


@dataclass
class CallGraphEdge:
    caller: str
    callee: str
    call_site_address: Optional[int] = None


@dataclass
class CallGraph:
    library: str
    nodes: dict[str, CallGraphNode]
    edges: list[CallGraphEdge]
    api_functions_found: list[str]
    api_functions_missing: list[str]
    max_depth: int


@dataclass
class CallGraphResult:
    library: str
    graph: CallGraph
    # Metrics
    api_total: int = 0
    api_found: int = 0
    internal_nodes: int = 0
    entry_points: int = 0
    edges_count: int = 0
    depth_reached: int = 0
    # Error tracking
    skipped: bool = False
    skip_reason: str = ""
    tool_errors: int = 0
    # Pre-rendered text for agent
    formatted_text: str = ""


# ---------------------------------------------------------------------------
# Caller result parsing
# ---------------------------------------------------------------------------


def _parse_callers(result) -> list[dict]:
    """Extract caller entries from a get_callers / get_xrefs_to result.

    Returns a list of dicts with at least a ``name`` key, and optionally
    ``address`` / ``call_site_address``.
    """
    # Normalise string to Python object
    if isinstance(result, str):
        text = result.strip()
        lower = text.lower()
        if any(kw in lower for kw in (
            "not found", "error", "no callers", "no xrefs",
            "invalid", "none", "null", "[]",
        )):
            return []
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            return []

    # Already a list of dicts
    if isinstance(result, list):
        out = []
        for item in result:
            if isinstance(item, dict) and "name" in item:
                out.append(item)
            elif isinstance(item, str):
                out.append({"name": item})
        return out

    # Single dict wrapping a list
    if isinstance(result, dict):
        for key in ("callers", "xrefs", "results", "functions"):
            if key in result and isinstance(result[key], list):
                return _parse_callers(result[key])

    return []


# ---------------------------------------------------------------------------
# Core async function
# ---------------------------------------------------------------------------


async def build_call_graph(
    tools: list,
    library_name: str,
    max_depth: int = CALL_GRAPH_MAX_DEPTH,
    max_per_level: int = CALL_GRAPH_MAX_NODES_PER_LEVEL,
) -> CallGraphResult:
    """Build an upward call graph from known API functions.

    Starting from SSL/TLS API functions defined in signature YAML files,
    walks callers upward via BFS up to *max_depth* levels.

    Args:
        tools: Live IDA MCP tool list.
        library_name: Library name matching ``--rules`` (e.g. ``openssl``).
        max_depth: Maximum BFS depth.
        max_per_level: Cap on nodes expanded per BFS level.

    Returns:
        ``CallGraphResult`` with graph data and formatted text.
    """
    empty_graph = CallGraph(
        library=library_name,
        nodes={},
        edges=[],
        api_functions_found=[],
        api_functions_missing=[],
        max_depth=max_depth,
    )
    result = CallGraphResult(library=library_name, graph=empty_graph)

    # 1. Load API function names from signature YAML
    sig_file = load_signatures(library_name)
    if sig_file is None:
        result.skipped = True
        result.skip_reason = f"No signature file for '{library_name}'"
        return result

    if not sig_file.functions:
        result.skipped = True
        result.skip_reason = (
            f"Signature file for '{library_name}' has no functions"
        )
        return result

    api_names = [fn.name for fn in sig_file.functions]
    result.api_total = len(api_names)

    # 2. Discover required tools
    lookup_tool = discover_tool(tools, _FUNC_LOOKUP_CANDIDATES)
    callers_tool = discover_tool(tools, _CALLERS_CANDIDATES)

    if lookup_tool is None:
        result.skipped = True
        result.skip_reason = (
            "Function lookup tool not available "
            f"(tried: {', '.join(_FUNC_LOOKUP_CANDIDATES)})"
        )
        return result

    if callers_tool is None:
        result.skipped = True
        result.skip_reason = (
            "Callers tool not available "
            f"(tried: {', '.join(_CALLERS_CANDIDATES)})"
        )
        return result

    entry_tool = discover_tool(tools, _ENTRY_POINT_CANDIDATES)

    # 3. Resolve API functions in binary
    nodes: dict[str, CallGraphNode] = {}
    found_apis: list[str] = []
    missing_apis: list[str] = []

    for name in api_names:
        try:
            lookup_result = await lookup_tool.ainvoke({"name": name})
            addr = parse_address_from_result(lookup_result)
        except Exception as exc:
            logger.debug("Lookup failed for %s: %s", name, exc)
            result.tool_errors += 1
            missing_apis.append(name)
            continue

        if addr is None:
            missing_apis.append(name)
            continue

        found_apis.append(name)
        nodes[name] = CallGraphNode(
            name=name, address=addr, kind=NodeKind.API,
        )

    result.api_found = len(found_apis)
    empty_graph.api_functions_found = found_apis
    empty_graph.api_functions_missing = missing_apis

    if not found_apis:
        result.skipped = True
        result.skip_reason = "No API functions found in binary"
        return result

    # 4. BFS upward from API functions
    edges: list[CallGraphEdge] = []
    frontier: set[str] = set(found_apis)
    visited: set[str] = set(found_apis)
    depth = 0

    while frontier and depth < max_depth:
        next_frontier: set[str] = set()
        expanded = 0

        for func_name in sorted(frontier):
            if expanded >= max_per_level:
                break

            # Determine argument for callers tool
            node = nodes.get(func_name)
            invoke_args: dict
            if node and node.address is not None:
                invoke_args = {"function_address": hex(node.address)}
            else:
                invoke_args = {"function_name": func_name}

            try:
                callers_result = await callers_tool.ainvoke(invoke_args)
                callers = _parse_callers(callers_result)
            except Exception as exc:
                logger.debug(
                    "get_callers failed for %s: %s", func_name, exc,
                )
                result.tool_errors += 1
                continue

            expanded += 1

            for caller_info in callers:
                caller_name = caller_info["name"]
                caller_addr = None
                if "address" in caller_info:
                    try:
                        caller_addr = (
                            int(caller_info["address"], 0)
                            if isinstance(caller_info["address"], str)
                            else int(caller_info["address"])
                        )
                    except (ValueError, TypeError):
                        pass

                call_site = None
                for key in ("call_site", "call_site_address", "from"):
                    if key in caller_info:
                        try:
                            call_site = (
                                int(caller_info[key], 0)
                                if isinstance(caller_info[key], str)
                                else int(caller_info[key])
                            )
                        except (ValueError, TypeError):
                            pass
                        break

                edges.append(CallGraphEdge(
                    caller=caller_name,
                    callee=func_name,
                    call_site_address=call_site,
                ))

                if caller_name not in visited:
                    visited.add(caller_name)
                    if caller_name not in nodes:
                        nodes[caller_name] = CallGraphNode(
                            name=caller_name,
                            address=caller_addr,
                            kind=NodeKind.INTERNAL,
                        )
                    next_frontier.add(caller_name)

        frontier = next_frontier
        depth += 1

    result.depth_reached = depth

    # 5. Entry point detection (optional)
    if entry_tool is not None:
        for name, node in nodes.items():
            if node.kind == NodeKind.API:
                continue
            try:
                if node.address is not None:
                    ep_result = await entry_tool.ainvoke(
                        {"function_address": hex(node.address)}
                    )
                else:
                    ep_result = await entry_tool.ainvoke(
                        {"function_name": name}
                    )
                if _is_entry_point(ep_result):
                    node.kind = NodeKind.ENTRY
            except Exception as exc:
                logger.debug(
                    "is_entry_point failed for %s: %s", name, exc,
                )
                result.tool_errors += 1

    # 6. Populate result
    empty_graph.nodes = nodes
    empty_graph.edges = edges
    result.graph = empty_graph
    result.internal_nodes = sum(
        1 for n in nodes.values() if n.kind == NodeKind.INTERNAL
    )
    result.entry_points = sum(
        1 for n in nodes.values() if n.kind == NodeKind.ENTRY
    )
    result.edges_count = len(edges)

    # 7. Format text for agent consumption
    result.formatted_text = _format_call_graph_text(result)

    return result


# ---------------------------------------------------------------------------
# Entry point check helper
# ---------------------------------------------------------------------------


def _is_entry_point(result) -> bool:
    """Return True if a tool result indicates the function is an entry point."""
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        lower = result.strip().lower()
        return lower in ("true", "yes", "1")
    if isinstance(result, dict):
        for key in ("is_entry_point", "entry_point", "is_export", "exported"):
            val = result.get(key)
            if val is not None:
                if isinstance(val, bool):
                    return val
                if isinstance(val, str):
                    return val.strip().lower() in ("true", "yes", "1")
                if isinstance(val, int):
                    return val != 0
    return False


# ---------------------------------------------------------------------------
# Text formatting for agent
# ---------------------------------------------------------------------------


def _format_call_graph_text(result: CallGraphResult) -> str:
    """Render the call graph as plain text for inclusion in agent messages."""
    graph = result.graph
    found = len(graph.api_functions_found)
    total = result.api_total
    lines: list[str] = []

    lines.append(
        f"== API Call Graph ({graph.library}, "
        f"{found}/{total} functions found) =="
    )
    lines.append("")

    # API functions present
    if graph.api_functions_found:
        lines.append("API functions in binary:")
        lines.append(f"  {', '.join(graph.api_functions_found)}")
        lines.append("")

    # Build callee -> callers mapping from edges
    callee_to_callers: dict[str, list[str]] = {}
    for edge in graph.edges:
        callee_to_callers.setdefault(edge.callee, []).append(edge.caller)

    # Render call relationships
    if callee_to_callers:
        lines.append("Call relationships (callee <- callers):")
        for callee in sorted(callee_to_callers):
            callers = sorted(set(callee_to_callers[callee]))
            tagged = []
            for c in callers:
                node = graph.nodes.get(c)
                if node and node.kind == NodeKind.ENTRY:
                    tagged.append(f"{c} [entry]")
                else:
                    tagged.append(c)
            lines.append(f"  {callee} <- {', '.join(tagged)}")
        lines.append("")

    # Missing API functions
    if graph.api_functions_missing:
        lines.append(
            f"Not found: {', '.join(graph.api_functions_missing)}"
        )

    text = "\n".join(lines).strip()

    # Truncate if too long
    if len(text) > CALL_GRAPH_MAX_TEXT_LENGTH:
        text = text[: CALL_GRAPH_MAX_TEXT_LENGTH - 20] + "\n... (truncated)"

    return text


# ---------------------------------------------------------------------------
# Console display
# ---------------------------------------------------------------------------


def display_call_graph_result(
    console: Console, result: CallGraphResult,
) -> None:
    """Render the call graph result as a tree-style summary to *console*.

    Follows the same visual style as ``display_repair_result()``.
    """
    if result.skipped:
        console.print(
            f"[yellow]  └─ Skipped: {result.skip_reason}[/yellow]"
        )
        return

    status = (
        "[green]✓[/green]"
        if result.tool_errors == 0
        else "[yellow]⚠[/yellow]"
    )
    console.print(f"{status} Call graph built")

    console.print(
        f"[dim]  ├─ API functions:   "
        f"{result.api_found}/{result.api_total} found[/dim]"
    )
    console.print(
        f"[dim]  ├─ Internal nodes:  "
        f"{result.internal_nodes}[/dim]"
    )
    console.print(
        f"[dim]  ├─ Entry points:    "
        f"{result.entry_points}[/dim]"
    )
    console.print(
        f"[dim]  ├─ Call edges:      "
        f"{result.edges_count}[/dim]"
    )
    console.print(
        f"[dim]  ├─ BFS depth:       "
        f"{result.depth_reached}/{result.graph.max_depth}[/dim]"
    )

    error_marker = "└" if result.tool_errors == 0 else "├"
    error_color = "yellow" if result.tool_errors > 0 else "dim"
    console.print(
        f"[{error_color}]  {error_marker}─ Tool errors:     "
        f"{result.tool_errors}[/{error_color}]"
    )

    if result.graph.api_functions_missing:
        missing = ", ".join(result.graph.api_functions_missing)
        if len(missing) > 100:
            missing = missing[:97] + "..."
        console.print(
            f"[dim]  └─ Not found: {missing}[/dim]"
        )
