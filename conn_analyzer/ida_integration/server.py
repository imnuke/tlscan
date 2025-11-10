"""
IDA Pro headless server management.

Provides functionality to start and manage headless IDA Pro server processes.
"""

import subprocess
import time
import requests
from rich.console import Console
from rich.panel import Panel

from conn_analyzer.config import (
    IDA_SERVER_HOST,
    IDA_SERVER_STARTUP_TIMEOUT,
    IDA_SERVER_READINESS_CHECK_INTERVAL,
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

    cmd = [
        "uv", "run",
        "--directory", ida_pro_mcp_dir,
        "idalib-mcp",
        "--host", host,
        "--port", str(port),
        binary_path
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait for server to be ready (poll SSE endpoint)
        url = f"http://{host}:{port}/sse"
        console.print(f"[cyan]⏳[/cyan]  Waiting for server at {url}...")

        for i in range(IDA_SERVER_STARTUP_TIMEOUT):
            # Check if process crashed
            if process.poll() is not None:
                # Process exited, capture output
                stdout, stderr = process.communicate()
                console.print(f"[bold red]✗[/bold red] Headless IDA server process exited with code {process.returncode}")
                console.print()
                if stderr:
                    console.print("[bold red]Server Error Output:[/bold red]")
                    console.print(Panel(stderr, border_style="red", title="stderr"))
                if stdout:
                    console.print("[bold yellow]Server Output:[/bold yellow]")
                    console.print(Panel(stdout, border_style="yellow", title="stdout"))
                raise RuntimeError(f"Headless IDA server failed to start (exit code {process.returncode})")

            time.sleep(IDA_SERVER_READINESS_CHECK_INTERVAL)
            try:
                response = requests.head(url, timeout=1)
                if response.status_code in [200, 405, 400]:  # Server responding
                    elapsed = time.perf_counter() - start_time
                    console.print(f"[green]✓[/green] Headless IDA server ready ({format_duration(elapsed)})")
                    return process
            except requests.RequestException:
                pass

        # Timeout - check if process is still running
        if process.poll() is not None:
            # Process died during wait
            stdout, stderr = process.communicate()
            console.print(f"[bold red]✗[/bold red] Server process died during startup (exit code {process.returncode})")
            if stderr:
                console.print("[bold red]Error Output:[/bold red]")
                console.print(Panel(stderr, border_style="red"))
            if stdout:
                console.print("[bold yellow]Output:[/bold yellow]")
                console.print(Panel(stdout, border_style="yellow"))
            raise RuntimeError(f"Server process failed during startup (exit code {process.returncode})")
        else:
            # Still running but not responding
            process.terminate()
            console.print(f"[bold red]✗[/bold red] Server did not respond within {IDA_SERVER_STARTUP_TIMEOUT} seconds (process still running)")
            console.print(f"[yellow]⚠[/yellow]  Check if port {port} is already in use or server is slow to start")
            raise TimeoutError(f"Headless IDA server did not start within {IDA_SERVER_STARTUP_TIMEOUT} seconds")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to start headless IDA server: {e}")
        raise
