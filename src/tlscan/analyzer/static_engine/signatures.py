"""Function signature repair for IDA Pro static analysis.

This module applies pre-defined C function type declarations to IDA Pro
databases before SSL/TLS analysis begins. This improves decompilation
quality for well-known library functions whose signatures IDA has not
automatically inferred (e.g. stripped PLT stubs).

No LLM is involved — this is a deterministic, pre-workflow step.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool name candidates (runtime discovery order)
# ---------------------------------------------------------------------------

_TYPE_SETTER_CANDIDATES = [
    "set_function_prototype",  # confirmed IDA Pro MCP tool
    "set_type",
    "set_local_type",
]

_FUNC_LOOKUP_CANDIDATES = [
    "get_function_by_name",
    "get_function_info",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FunctionSignature:
    name: str
    type: str
    comment: Optional[str] = None


@dataclass
class SignatureFile:
    library: str
    functions: list[FunctionSignature] = field(default_factory=list)


@dataclass
class RepairResult:
    library: str
    total: int = 0       # signatures loaded from YAML
    found: int = 0       # functions found in IDA database
    applied: int = 0     # prototypes successfully applied
    not_found: int = 0   # function not present in binary
    failed: int = 0      # tool call exceptions
    skipped: bool = False
    skip_reason: str = ""
    # Diagnostic fields (populated when failures occur)
    lookup_tool_name: str = ""
    setter_tool_name: str = ""
    failure_details: list[str] = field(default_factory=list)
    # Raw lookup results for the first few functions (address debug)
    lookup_samples: list[tuple[str, object]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def load_signatures(
    library_name: str,
    signatures_dir: Optional[Path] = None,
) -> Optional[SignatureFile]:
    """Load function signatures for *library_name* from YAML.

    Args:
        library_name: Name matching the ``--rules`` argument (e.g. ``openssl``).
        signatures_dir: Override the bundled signatures directory.

    Returns:
        ``SignatureFile`` on success, ``None`` if missing or parse error.
    """
    if signatures_dir is None:
        from tlscan.config import SIGNATURES_DIR
        signatures_dir = SIGNATURES_DIR

    yaml_path = Path(signatures_dir) / f"{library_name}.yaml"

    if not yaml_path.exists():
        return None

    try:
        with yaml_path.open() as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.debug("YAML parse error for %s: %s", yaml_path, exc)
        return None

    if not isinstance(raw, dict):
        return None

    functions = [
        FunctionSignature(
            name=fn["name"],
            type=fn["type"],
            comment=fn.get("comment"),
        )
        for fn in raw.get("functions", [])
        if isinstance(fn, dict) and "name" in fn and "type" in fn
    ]

    return SignatureFile(library=raw.get("library", library_name), functions=functions)


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


def _discover_tool(tools: list, candidates: list[str]):
    """Return the first tool from *tools* whose name matches a candidate.

    Args:
        tools: Live tool list returned by the MCP client.
        candidates: Ordered list of preferred tool names.

    Returns:
        Matching tool object, or ``None`` if none found.
    """
    tool_map = {t.name: t for t in tools}
    for name in candidates:
        if name in tool_map:
            return tool_map[name]
    return None


# ---------------------------------------------------------------------------
# Address parser
# ---------------------------------------------------------------------------


def _parse_address_from_result(result) -> Optional[int]:
    """Extract a numeric address from an MCP tool call result.

    Handles both ``str`` (raw / JSON-encoded) and ``dict`` responses.
    Returns ``None`` when the function was not found or the address cannot
    be parsed.
    """
    # Normalise to dict
    if isinstance(result, str):
        text = result.strip()
        # Quick heuristic: "not found" / error responses
        lower = text.lower()
        if any(kw in lower for kw in ("not found", "error", "invalid", "none", "null")):
            return None
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            # Try parsing a bare hex/int string
            try:
                return int(text, 0)
            except ValueError:
                return None

    if not isinstance(result, dict):
        return None

    for field_name in ("address", "ea", "start_ea", "offset"):
        val = result.get(field_name)
        if val is None:
            continue
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            try:
                return int(val, 0)
            except ValueError:
                continue

    return None


# ---------------------------------------------------------------------------
# Core async function
# ---------------------------------------------------------------------------


async def apply_function_signatures(
    tools: list,
    library_name: str,
    signatures_dir: Optional[Path] = None,
) -> RepairResult:
    """Apply pre-defined function signatures to an IDA Pro database.

    This is a *deterministic* step (no LLM). For each function in the
    signature YAML file:
    1. Look up the function address in IDA by name.
    2. If found, apply the C prototype string.

    All errors are non-fatal — the analysis always proceeds.

    Args:
        tools: Live IDA MCP tool list from ``StaticAnalysisEngine.get_tools()``.
        library_name: Library name matching the ``--rules`` argument.
        signatures_dir: Override the bundled signatures directory.

    Returns:
        ``RepairResult`` summary.
    """
    result = RepairResult(library=library_name)

    # 1. Load YAML
    sig_file = load_signatures(library_name, signatures_dir)
    if sig_file is None:
        result.skipped = True
        result.skip_reason = f"No signature file for '{library_name}'"
        return result

    if not sig_file.functions:
        result.skipped = True
        result.skip_reason = f"Signature file for '{library_name}' is empty"
        return result

    result.total = len(sig_file.functions)

    # 2. Discover tools
    lookup_tool = _discover_tool(tools, _FUNC_LOOKUP_CANDIDATES)
    setter_tool = _discover_tool(tools, _TYPE_SETTER_CANDIDATES)

    if lookup_tool is None:
        result.skipped = True
        result.skip_reason = (
            f"Lookup tool not available "
            f"(tried: {', '.join(_FUNC_LOOKUP_CANDIDATES)})"
        )
        return result

    if setter_tool is None:
        result.skipped = True
        result.skip_reason = (
            f"Prototype setter tool not available "
            f"(tried: {', '.join(_TYPE_SETTER_CANDIDATES)})"
        )
        return result

    result.lookup_tool_name = lookup_tool.name
    result.setter_tool_name = setter_tool.name

    # 3. Apply signatures
    _MAX_SAMPLES = 3   # how many raw lookup results to keep for debug
    _MAX_FAILURES = 5  # how many failure lines to store

    for sig in sig_file.functions:
        # Look up address
        try:
            lookup_result = await lookup_tool.ainvoke({"name": sig.name})
            addr = _parse_address_from_result(lookup_result)
            # Keep a few raw lookup results for address-parse debugging
            if len(result.lookup_samples) < _MAX_SAMPLES:
                result.lookup_samples.append((sig.name, lookup_result))
        except Exception as exc:
            detail = f"lookup({sig.name}): {exc}"
            logger.debug(detail)
            result.failed += 1
            if len(result.failure_details) < _MAX_FAILURES:
                result.failure_details.append(detail)
            continue

        if addr is None:
            result.not_found += 1
            continue

        result.found += 1

        # Apply prototype
        try:
            await setter_tool.ainvoke(
                {"function_address": hex(addr), "prototype": sig.type}
            )
            result.applied += 1
        except Exception as exc:
            detail = (
                f"{setter_tool.name}({sig.name} @ 0x{addr:x}): {exc}"
            )
            logger.debug(detail)
            result.failed += 1
            if len(result.failure_details) < _MAX_FAILURES:
                result.failure_details.append(detail)

    return result


# ---------------------------------------------------------------------------
# Console display
# ---------------------------------------------------------------------------


def display_repair_result(console: Console, result: RepairResult) -> None:
    """Render the repair result as a tree-style summary to *console*.

    Args:
        console: Rich ``Console`` instance.
        result: Result returned by ``apply_function_signatures()``.
    """
    if result.skipped:
        console.print(
            f"[yellow]  └─ Skipped: {result.skip_reason}[/yellow]"
        )
        return

    status = "[green]✓[/green]" if result.failed == 0 else "[yellow]⚠[/yellow]"
    console.print(f"{status} Signature repair complete")

    # Show which tools were used
    if result.lookup_tool_name or result.setter_tool_name:
        console.print(
            f"[dim]  ├─ Tools: "
            f"{result.lookup_tool_name} / {result.setter_tool_name}[/dim]"
        )

    last = "└" if result.failed == 0 else "├"
    console.print(
        f"[dim]  ├─ Signatures loaded:         {result.total}[/dim]"
    )
    console.print(
        f"[dim]  ├─ Functions found in binary:  {result.found}[/dim]"
    )
    console.print(
        f"[dim]  ├─ Signatures applied:         {result.applied}[/dim]"
    )
    console.print(
        f"[dim]  ├─ Not found in binary:        {result.not_found}[/dim]"
    )
    fail_color = "yellow" if result.failed > 0 else "dim"
    console.print(
        f"[{fail_color}]  {last}─ Failures:                   "
        f"{result.failed}[/{fail_color}]"
    )

    # Show failure details when something went wrong
    if result.failure_details:
        console.print("[yellow]  │  Failure details:[/yellow]")
        for i, detail in enumerate(result.failure_details):
            prefix = "└" if i == len(result.failure_details) - 1 else "├"
            # Truncate very long error messages
            msg = detail if len(detail) <= 120 else detail[:117] + "..."
            console.print(f"[yellow]  │  {prefix}─ {msg}[/yellow]")

    # Show raw lookup samples when address parsing may have failed
    if result.not_found > 0 and result.lookup_samples:
        console.print(
            "[dim]  │  Sample lookup results (for address-parse debug):[/dim]"
        )
        for i, (fname, raw) in enumerate(result.lookup_samples):
            prefix = "└" if i == len(result.lookup_samples) - 1 else "├"
            preview = repr(raw)
            if len(preview) > 100:
                preview = preview[:97] + "..."
            console.print(
                f"[dim]  │  {prefix}─ {fname}: {preview}[/dim]"
            )
