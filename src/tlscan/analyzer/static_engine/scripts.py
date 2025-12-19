"""Tools for analyzing script files (shell, PHP, Python, etc.).

This module provides tools for script analysis as an alternative to IDA tools
for binary analysis. The same agents (SSL, dataflow) can use these tools
to analyze scripts instead of binaries.
"""

import re
from pathlib import Path
from typing import Optional, List
from langchain_core.tools import tool

# Global script path - will be set before analysis
SCRIPT_PATH: Optional[str] = None
SCRIPT_CONTENT: Optional[str] = None
SCRIPT_LINES: Optional[List[str]] = None


def set_script_path(path: str):
    """Set the script file to analyze.

    Args:
        path: Absolute path to the script file
    """
    global SCRIPT_PATH, SCRIPT_CONTENT, SCRIPT_LINES
    SCRIPT_PATH = path

    # Pre-load content
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            SCRIPT_CONTENT = f.read()
            SCRIPT_LINES = SCRIPT_CONTENT.splitlines()
    except Exception as e:
        SCRIPT_CONTENT = f"Error reading file: {e}"
        SCRIPT_LINES = []


def get_script_tools() -> List:
    """Get all script analysis tools.

    Returns:
        List of LangChain tools for script analysis
    """
    return [
        get_script_content,
        get_lines,
        search_pattern,
        find_command_usage,
    ]


@tool
def get_script_content() -> str:
    """Get the full script content with line numbers.

    Use this to read the entire script for analysis. Each line is prefixed
    with its line number for easy reference.

    Returns:
        Script content with line numbers (format: "linenum: content")
    """
    if SCRIPT_LINES is None:
        return "Error: Script not loaded. Call set_script_path() first."

    if not SCRIPT_LINES:
        return "Error: Script is empty or could not be read."

    # Format with line numbers
    numbered_lines = []
    for i, line in enumerate(SCRIPT_LINES, 1):
        numbered_lines.append(f"{i:4d}: {line}")

    return f"Script: {SCRIPT_PATH}\n{'=' * 60}\n" + "\n".join(numbered_lines)


@tool
def get_lines(start: int, end: int) -> str:
    """Get specific line range from script.

    Use this to examine a specific portion of the script.

    Args:
        start: Starting line number (1-indexed, inclusive)
        end: Ending line number (1-indexed, inclusive)

    Returns:
        Lines in the specified range with line numbers
    """
    if SCRIPT_LINES is None:
        return "Error: Script not loaded. Call set_script_path() first."

    if start < 1:
        start = 1
    if end > len(SCRIPT_LINES):
        end = len(SCRIPT_LINES)

    if start > end:
        return f"Error: Invalid range. start ({start}) > end ({end})"

    # Extract lines (convert to 0-indexed)
    selected = SCRIPT_LINES[start-1:end]
    numbered_lines = []
    for i, line in enumerate(selected, start):
        numbered_lines.append(f"{i:4d}: {line}")

    return f"Lines {start}-{end} of {SCRIPT_PATH}:\n{'=' * 60}\n" + "\n".join(numbered_lines)


@tool
def search_pattern(pattern: str) -> str:
    """Search for regex pattern in script.

    Use this to find specific patterns, function calls, or variable usages.

    Args:
        pattern: Regular expression pattern to search for

    Returns:
        Matching lines with line numbers (format: "linenum: content")

    Examples:
        search_pattern("wget") - Find all wget invocations
        search_pattern("--no-check-certificate") - Find insecure wget options
        search_pattern("\\$\\{?\\w+") - Find variable references
    """
    if SCRIPT_LINES is None:
        return "Error: Script not loaded. Call set_script_path() first."

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: Invalid regex pattern: {e}"

    matches = []
    for i, line in enumerate(SCRIPT_LINES, 1):
        if regex.search(line):
            matches.append(f"{i:4d}: {line}")

    if not matches:
        return f"No matches found for pattern: {pattern}"

    return f"Found {len(matches)} matches for '{pattern}':\n" + "\n".join(matches)


@tool
def find_command_usage(command: str) -> str:
    """Find where a command is used with its arguments.

    Use this to find how specific commands (wget, curl, etc.) are invoked.
    Returns the full command line including all arguments.

    Args:
        command: Command name to search for (e.g., "wget", "curl", "openssl")

    Returns:
        Lines containing the command with context

    Examples:
        find_command_usage("wget") - Find wget command invocations
        find_command_usage("curl") - Find curl command invocations
    """
    if SCRIPT_LINES is None:
        return "Error: Script not loaded. Call set_script_path() first."

    # Pattern to match command at word boundary (not as part of another word)
    # Matches: wget, /usr/bin/wget, `wget`, $(wget), etc.
    pattern = rf'(?:^|[`$(\s/])({re.escape(command)})\s'

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        # Fallback to simple search
        regex = re.compile(re.escape(command), re.IGNORECASE)

    matches = []
    for i, line in enumerate(SCRIPT_LINES, 1):
        if regex.search(line) or command.lower() in line.lower():
            # Include some context - check for line continuation
            full_command = line

            # Check if line ends with backslash (continuation)
            line_idx = i - 1
            while full_command.rstrip().endswith('\\') and line_idx + 1 < len(SCRIPT_LINES):
                line_idx += 1
                full_command += '\n' + SCRIPT_LINES[line_idx]

            matches.append(f"Line {i}:\n{full_command}")

    if not matches:
        return f"No usage found for command: {command}"

    return f"Found {len(matches)} usages of '{command}':\n{'=' * 40}\n" + "\n\n".join(matches)
