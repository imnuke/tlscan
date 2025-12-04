"""Utilities for logging agent state changes to console during analysis workflow."""

import json
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from conn_analyzer.graph.state import AnalysisState

# Initialize console for state change output
console = Console()


def _serialize_and_truncate(obj: Any, max_str_len: int = 100) -> Any:
    """Recursively serialize Pydantic models and truncate long strings.

    Args:
        obj: Object to serialize
        max_str_len: Maximum length for string values

    Returns:
        Serialized object with truncated strings
    """
    if hasattr(obj, 'model_dump'):
        # Pydantic v2 model
        return _serialize_and_truncate(obj.model_dump(), max_str_len)
    elif hasattr(obj, 'dict'):
        # Pydantic v1 model
        return _serialize_and_truncate(obj.dict(), max_str_len)
    elif isinstance(obj, dict):
        return {k: _serialize_and_truncate(v, max_str_len) for k, v in obj.items()}
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
    INTERNAL_FIELDS = {"current_phase", "depth", "security_rules"}

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
