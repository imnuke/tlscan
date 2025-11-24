"""Utilities for logging agent state during analysis workflow."""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from conn_analyzer.config import TEMP_FILES_DIR
from conn_analyzer.graph.state import AnalysisState

AGENT_STATE_LOGS_DIR = TEMP_FILES_DIR / "agent_state_logs"
"""Directory for agent state log files."""

# Global variable to track current log file path
_current_log_file: Path | None = None
_log_entries: List[Dict[str, Any]] = []


def init_state_log(binary_path: str) -> Path:
    """Initialize state logging for a new analysis run.

    Cleans up old state logs and creates a new log file for this run.

    Args:
        binary_path: Path to the binary being analyzed (used in filename)

    Returns:
        Path to the new log file
    """
    global _current_log_file, _log_entries

    # Clean up old logs
    if AGENT_STATE_LOGS_DIR.exists():
        shutil.rmtree(AGENT_STATE_LOGS_DIR)

    # Create logs directory
    AGENT_STATE_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate log filename
    binary_name = Path(binary_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"state_log_{binary_name}_{timestamp}.json"
    _current_log_file = AGENT_STATE_LOGS_DIR / log_filename

    # Reset log entries
    _log_entries = []

    return _current_log_file


def _serialize_for_json(obj: Any) -> Any:
    """Recursively serialize Pydantic models and complex types to JSON-compatible format.

    Handles:
    - Pydantic v2 models (model_dump)
    - Pydantic v1 models (dict)
    - Nested dicts, lists, tuples, sets
    - Other types pass through

    Args:
        obj: Object to serialize

    Returns:
        JSON-serializable representation
    """
    if hasattr(obj, 'model_dump'):
        # Pydantic v2 model
        return obj.model_dump()
    elif hasattr(obj, 'dict'):
        # Pydantic v1 model
        return obj.dict()
    elif isinstance(obj, dict):
        return {k: _serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_serialize_for_json(item) for item in obj]
    elif isinstance(obj, set):
        return [_serialize_for_json(item) for item in obj]
    else:
        return obj


def log_initial_state(state: AnalysisState) -> None:
    """Log the initial analysis state at workflow start.

    Should be called once after creating initial state, before any agents execute.

    Args:
        state: Initial analysis state
    """
    global _current_log_file, _log_entries

    if _current_log_file is None:
        # Logging not initialized, skip silently
        return

    # Serialize initial state (skip large fields)
    state_dict = dict(state)
    state_dict.pop("security_rules", None)  # Too large to log

    # Create initial state entry
    entry = {
        "event": "initial",
        "phase": state.get("current_phase"),
        "depth": state.get("depth"),
        "state": state_dict,
    }

    # Append to log entries
    _log_entries.append(entry)

    # Write to file
    with open(_current_log_file, "w") as f:
        json.dump(_log_entries, f, indent=2, default=str)


def log_agent_state(
    agent_name: str,
    state: AnalysisState,
    changes: Dict[str, Any],
) -> None:
    """Log state changes after an agent completes.

    Logs only the changes made by the agent, keeping logs compact and readable.

    Args:
        agent_name: Name of the agent that executed
        state: Current analysis state (after agent execution)
        changes: Dict of state updates (node's return value)
    """
    global _current_log_file, _log_entries

    if _current_log_file is None:
        # Logging not initialized, skip silently
        return

    # Create log entry
    entry = {
        "event": "agent_complete",
        "agent_name": agent_name,
        "phase": state.get("current_phase"),
        "depth": state.get("depth"),
        "changes": _serialize_for_json(changes),
    }

    # Append to log entries
    _log_entries.append(entry)

    # Write to file (overwrite with full array each time)
    with open(_current_log_file, "w") as f:
        json.dump(_log_entries, f, indent=2, default=str)
