#!/usr/bin/env python3
"""
Debug and test utility for firmware_tools.

Simple script to test firmware analysis tools. Edit the configuration section
and uncomment/modify the test calls in main() to test different tools.

Usage:
    1. Edit FIRMWARE_PATH below to point to your firmware directory
    2. Uncomment/modify test calls in main() function
    3. Run: uv run python -m conn_analyzer.debug.test_firmware_tools
"""

import sys
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

from conn_analyzer.static_analysis import firmware_tools

console = Console()


# ============================================================================
# CONFIGURATION - EDIT THIS SECTION
# ============================================================================

# Set your firmware path here
FIRMWARE_PATH = "/home/peng/MyWorkspace/firmwares/mydataset/Asustor/AS3204T_4.3.3_RKD2"  # TODO: Change this to your firmware directory


# ============================================================================
# TOOL TESTER CLASS
# ============================================================================

class FirmwareToolsTester:
    """Test harness for firmware_tools module."""

    def __init__(self, firmware_path: str):
        """Initialize tester with firmware root path."""
        self.firmware_path = Path(firmware_path).resolve()
        if not self.firmware_path.exists():
            console.print(f"[red]Error: Firmware path does not exist: {firmware_path}[/red]")
            sys.exit(1)
        if not self.firmware_path.is_dir():
            console.print(f"[red]Error: Firmware path is not a directory: {firmware_path}[/red]")
            sys.exit(1)

        # Initialize firmware_tools
        firmware_tools.set_firmware_root(str(self.firmware_path))
        console.print(f"[green]✓[/green] Firmware root set to: {self.firmware_path}\n")

    def run_tool(self, tool_func, **kwargs) -> tuple[str, float]:
        """Run a tool and measure execution time."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            progress.add_task(f"Running tool...", total=None)
            start_time = time.time()
            # LangChain tools are StructuredTool objects, invoke them with .invoke()
            result = tool_func.invoke(kwargs)
            elapsed = time.time() - start_time
        
        console.print(f"[green]✓[/green] Tool completed in {elapsed:.3f} seconds.\n")
        console.print(result)


def main():
    """Main entry point. Edit the test calls below to test different tools."""

    # Display header
    console.print(Panel.fit(
        "[bold cyan]Firmware Tools Debugger[/bold cyan]\n"
        f"Firmware Path: {FIRMWARE_PATH}",
        border_style="cyan"
    ))
    console.print()

    # Initialize tester
    try:
        tester = FirmwareToolsTester(FIRMWARE_PATH)
    except Exception as e:
        console.print(f"[red]Failed to initialize tester: {e}[/red]")
        sys.exit(1)

    # ============================================================================
    # EDIT TEST CALLS HERE
    # ============================================================================
    tester.run_tool(
        firmware_tools.search_files_by_content,
        pattern="upscli_connect",
        file_pattern="*"
    ) 


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
