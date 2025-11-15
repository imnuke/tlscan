"""
IDA Pro headless server management.

Provides functionality to start and manage headless IDA Pro server processes.
"""

import subprocess
import time
import requests
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from conn_analyzer.config import (
    IDA_SERVER_HOST,
    IDA_SERVER_STARTUP_TIMEOUT,
    IDA_SERVER_READINESS_CHECK_INTERVAL,
    IDA_SERVER_LOGS_DIR,
)
from conn_analyzer.utils.formatting import format_duration

# Initialize console for output
console = Console()


def start_headless_ida_server(
    binary_path: str,
    host: str = IDA_SERVER_HOST,
    port: int = 8800  # Default port, will be allocated by PortManager in practice
) -> subprocess.Popen:
    """
    Start headless IDA server process.

    Args:
        binary_path: Path to binary to analyze
        host: Server host (default: localhost)
        port: Server port (default: from config)

    Returns:
        Server process handle

    Raises:
        RuntimeError: If server fails to start
        TimeoutError: If server doesn't respond within timeout
    """
    ida_pro_mcp_dir = '/home/peng/Projects/others/ida-pro-mcp'

    start_time = time.perf_counter()
    console.print(f"[cyan]⚙[/cyan]  Starting headless IDA server for [bold]{binary_path}[/bold]...")

    # Create logs directory if it doesn't exist
    IDA_SERVER_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate log filename based on binary name, port, and timestamp
    binary_name = Path(binary_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"ida_server_{binary_name}_{port}_{timestamp}.log"
    log_path = IDA_SERVER_LOGS_DIR / log_filename

    cmd = [
        "uv", "run",
        "--directory", ida_pro_mcp_dir,
        "idalib-mcp",
        "--host", host,
        "--port", str(port),
        binary_path
    ]

    try:
        # Open log file for writing (both stdout and stderr)
        log_file = open(log_path, 'w', buffering=1)  # Line buffered

        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout
            text=True
        )

        # Store log file path and handle on the process object for later access
        process._log_file = log_file
        process._log_path = log_path

        # Wait for server to be ready (poll SSE endpoint)
        url = f"http://{host}:{port}/sse"
        console.print(f"[cyan]⏳[/cyan]  Waiting for server at {url}...")

        for i in range(IDA_SERVER_STARTUP_TIMEOUT):
            # Check if process crashed
            if process.poll() is not None:
                # Process exited, read log file
                log_file.close()
                console.print(f"[bold red]✗[/bold red] Headless IDA server process exited with code {process.returncode}")
                console.print(f"[cyan]📄[/cyan] Log file: {log_path}")
                console.print()

                # Read and display log contents
                try:
                    with open(log_path, 'r') as f:
                        log_contents = f.read()
                    if log_contents.strip():
                        console.print("[bold yellow]Server Log Output:[/bold yellow]")
                        console.print(Panel(log_contents, border_style="yellow", title="Log"))
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not read log file: {e}")

                raise RuntimeError(f"Headless IDA server failed to start (exit code {process.returncode})")

            time.sleep(IDA_SERVER_READINESS_CHECK_INTERVAL)
            try:
                response = requests.head(url, timeout=1)
                if response.status_code in [200, 405, 400]:  # Server responding
                    elapsed = time.perf_counter() - start_time
                    console.print(f"[green]✓[/green] Headless IDA server ready ({format_duration(elapsed)})")
                    console.print(f"[cyan]📄[/cyan] Server logs: {log_path}")
                    return process
            except requests.RequestException:
                pass

        # Timeout - check if process is still running
        if process.poll() is not None:
            # Process died during wait
            log_file.close()
            console.print(f"[bold red]✗[/bold red] Server process died during startup (exit code {process.returncode})")
            console.print(f"[cyan]📄[/cyan] Log file: {log_path}")
            console.print()

            # Read and display log contents
            try:
                with open(log_path, 'r') as f:
                    log_contents = f.read()
                if log_contents.strip():
                    console.print("[bold yellow]Server Log Output:[/bold yellow]")
                    console.print(Panel(log_contents, border_style="yellow", title="Log"))
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not read log file: {e}")

            raise RuntimeError(f"Server process failed during startup (exit code {process.returncode})")
        else:
            # Still running but not responding
            log_file.close()
            process.terminate()
            console.print(f"[bold red]✗[/bold red] Server did not respond within {IDA_SERVER_STARTUP_TIMEOUT} seconds (process still running)")
            console.print(f"[cyan]📄[/cyan] Log file: {log_path}")
            console.print(f"[yellow]⚠[/yellow]  Check if port {port} is already in use or server is slow to start")
            raise TimeoutError(f"Headless IDA server did not start within {IDA_SERVER_STARTUP_TIMEOUT} seconds")

    except Exception as e:
        # Ensure log file is closed on any exception
        if 'log_file' in locals() and not log_file.closed:
            log_file.close()
        console.print(f"[bold red]✗[/bold red] Failed to start headless IDA server: {e}")
        raise
