"""Utilities for logging agent state changes to console during analysis workflow."""

import difflib
import json
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from conn_analyzer.graph.state import AnalysisState

# Initialize console for state change output
console = Console()


def _serialize_and_truncate(obj: Any, max_str_len: int = 100) -> Any:
    """Recursively serialize Pydantic models, exclude None values, and truncate long strings.

    Args:
        obj: Object to serialize
        max_str_len: Maximum length for string values

    Returns:
        Serialized object with null fields excluded and long strings truncated
    """
    if hasattr(obj, 'model_dump'):
        # Pydantic v2 model - exclude None values
        return _serialize_and_truncate(obj.model_dump(exclude_none=True), max_str_len)
    elif hasattr(obj, 'dict'):
        # Pydantic v1 model - exclude None values
        return _serialize_and_truncate(obj.dict(exclude_none=True), max_str_len)
    elif isinstance(obj, dict):
        # Filter out None values from dicts
        return {
            k: _serialize_and_truncate(v, max_str_len)
            for k, v in obj.items()
            if v is not None
        }
    elif isinstance(obj, (list, tuple)):
        return [_serialize_and_truncate(item, max_str_len) for item in obj]
    elif isinstance(obj, set):
        return [_serialize_and_truncate(item, max_str_len) for item in obj]
    elif isinstance(obj, str):
        # Truncate long strings - keep head and tail
        if len(obj) > max_str_len:
            # Calculate how much to keep from head and tail
            keep_chars = max_str_len - 3  # Reserve 3 for "..."
            head_len = keep_chars // 2
            tail_len = keep_chars - head_len
            return obj[:head_len] + "..." + obj[-tail_len:]
        return obj
    else:
        return obj


def log_agent_state(
    agent_name: str,
    state: AnalysisState,
    changes: Dict[str, Any],
) -> None:
    """Log state changes to console after an agent completes.

    Displays the complete changes dictionary with syntax highlighting.
    Truncates long strings to 100 characters.

    Args:
        agent_name: Name of the agent that executed
        state: Current analysis state (after agent execution) - unused but kept for API compatibility
        changes: Dict of state updates (node's return value)
    """
    # Internal fields to skip
    INTERNAL_FIELDS = {"current_phase", "security_rules"}

    # Filter out internal fields
    filtered_changes = {k: v for k, v in changes.items() if k not in INTERNAL_FIELDS}

    # Skip if no changes to display
    if not filtered_changes:
        console.print(f"[dim]  ℹ {agent_name}: (no state changes)[/dim]")
        return

    # Serialize and truncate
    serialized = _serialize_and_truncate(filtered_changes, max_str_len=100)

    # Format as JSON with indentation
    json_str = json.dumps(serialized, indent=2, default=str)

    # Create syntax-highlighted display
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)

    console.print()
    console.print(Panel(
        syntax,
        title=f"[bold cyan]🔄 {agent_name} - State Changes[/bold cyan]",
        border_style="cyan",
        padding=(0, 1)
    ))


def capture_state_snapshot(
    config_tasks: List,
    dataflow_tasks: List,
    traces: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Capture current state for diff comparison.

    Creates a deep copy of the relevant state fields for before/after comparison.

    Args:
        config_tasks: Current pending_config_fetch_tasks list
        dataflow_tasks: Current pending_dataflow_tasks list
        traces: Optional traces dict from unified trace graph

    Returns:
        Snapshot dict with serialized state (null fields excluded)
    """
    snapshot = {
        "pending_config_fetch_tasks": [
            _serialize_and_truncate(t) for t in config_tasks
        ],
        "pending_dataflow_tasks": [
            _serialize_and_truncate(t) for t in dataflow_tasks
        ],
    }
    if traces:
        snapshot["traces"] = {
            k: _serialize_and_truncate(v) for k, v in traces.items()
        }
    return snapshot


def log_agent_state_diff(
    agent_name: str,
    state_before: Dict[str, Any],
    state_after: Dict[str, Any],
) -> None:
    """Log state changes as unified diff after an agent completes.

    Computes and displays a unified diff between the before and after states,
    showing exactly what was added, removed, or modified.

    Args:
        agent_name: Name of the agent that executed
        state_before: State snapshot before agent execution
        state_after: State snapshot after agent execution
    """
    # Internal fields to filter from display
    INTERNAL_FIELDS = {"current_phase", "security_rules"}

    # Filter internal fields from both states
    before_filtered = {k: v for k, v in state_before.items() if k not in INTERNAL_FIELDS}
    after_filtered = {k: v for k, v in state_after.items() if k not in INTERNAL_FIELDS}

    # Serialize to JSON for diff comparison (already serialized by capture_state_snapshot)
    before_json = json.dumps(before_filtered, indent=2, sort_keys=True, default=str)
    after_json = json.dumps(after_filtered, indent=2, sort_keys=True, default=str)

    # Skip if no changes
    if before_json == after_json:
        console.print(f"[dim]  ℹ {agent_name}: (no state changes)[/dim]")
        return

    # Compute unified diff
    diff_lines = list(difflib.unified_diff(
        before_json.splitlines(),
        after_json.splitlines(),
        fromfile="before",
        tofile="after",
        lineterm=""
    ))

    # Format with Rich markup colors
    colored_lines = []
    for line in diff_lines:
        if line.startswith('+++') or line.startswith('---'):
            # Header lines - dim
            colored_lines.append(f"[dim]{line}[/dim]")
        elif line.startswith('+'):
            # Added lines - green
            colored_lines.append(f"[green]{line}[/green]")
        elif line.startswith('-'):
            # Removed lines - red
            colored_lines.append(f"[red]{line}[/red]")
        elif line.startswith('@@'):
            # Hunk headers - cyan
            colored_lines.append(f"[cyan]{line}[/cyan]")
        else:
            # Context lines - dim
            colored_lines.append(f"[dim]{line}[/dim]")

    diff_text = "\n".join(colored_lines)

    console.print()
    console.print(Panel(
        diff_text,
        title=f"[bold cyan]🔄 {agent_name} - State Changes[/bold cyan]",
        border_style="cyan",
        padding=(0, 1)
    ))


def display_recovered_state(
    state: Dict[str, Any],
    metadata: Dict[str, Any],
    output_console: Console = None
) -> None:
    """Display recovered checkpoint state before resuming analysis.

    Uses generic JSON serialization for future compatibility - no field-specific
    parsing so new/removed state fields are handled automatically.

    Args:
        state: Recovered AnalysisState from checkpoint
        metadata: Thread metadata (thread_id, binary_path, rules, model, etc.)
        output_console: Rich console for output (defaults to module console)
    """
    if output_console is None:
        output_console = console

    # Fields to exclude from display (internal/large)
    EXCLUDE_FIELDS = {"security_rules"}  # Large content, not useful for display

    # Filter and serialize state
    filtered_state = {k: v for k, v in state.items() if k not in EXCLUDE_FIELDS}
    serialized_state = _serialize_and_truncate(filtered_state, max_str_len=200)

    # Format as JSON
    state_json = json.dumps(serialized_state, indent=2, default=str)

    # Create syntax-highlighted display
    state_syntax = Syntax(state_json, "json", theme="monokai", line_numbers=False)

    # Display metadata header
    output_console.print()
    output_console.print(Panel.fit(
        "[bold cyan]📋 Recovered Checkpoint State[/bold cyan]",
        border_style="cyan"
    ))
    output_console.print()

    # Display thread metadata
    output_console.print(f"[cyan]Thread:[/cyan] {metadata.get('thread_id', 'N/A')}")
    output_console.print(f"[cyan]Binary:[/cyan] {metadata.get('binary_path', 'N/A')}")
    output_console.print(f"[cyan]Rules:[/cyan] {metadata.get('rules', 'N/A')}")
    output_console.print(f"[cyan]Model:[/cyan] {metadata.get('model', 'N/A')}")
    if metadata.get('firmware_path'):
        output_console.print(f"[cyan]Firmware:[/cyan] {metadata.get('firmware_path')}")
    output_console.print(f"[cyan]Created:[/cyan] {metadata.get('created_at', 'N/A')}")
    output_console.print()

    # Display full state as JSON
    output_console.print(Panel(
        state_syntax,
        title="[bold cyan]Analysis State[/bold cyan]",
        border_style="dim",
        padding=(0, 1)
    ))
    output_console.print()
