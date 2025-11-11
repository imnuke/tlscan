"""Binary registry manager for multi-binary analysis.

This module provides the BinaryRegistry class that manages multiple binaries,
each with its own MCP server, MCP client, and specialized agents.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Dict, Optional

from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console

from conn_analyzer.ida_integration.server import start_headless_ida_server
from conn_analyzer.ida_integration.port_manager import PortManager
from conn_analyzer.config import IDA_SERVER_HOST

# Initialize console for output
console = Console()


@dataclass
class BinaryEntry:
    """Entry for a registered binary in the registry.

    Attributes:
        binary_path: Absolute path to the binary file
        port: Allocated MCP server port
        server_process: Server subprocess handle
        mcp_client: MCP client instance for this binary
        agents: Dictionary of agents for this binary {"dataflow": agent, "ssl": agent}
    """
    binary_path: str
    port: int
    server_process: any  # subprocess.Popen
    mcp_client: MultiServerMCPClient
    agents: Dict[str, any]  # {"dataflow": agent, "ssl": agent}


class BinaryRegistry:
    """Registry for managing multiple binaries with their own MCP servers and agents.

    This class provides thread-safe registration and management of multiple binaries.
    Each binary gets:
    - Its own allocated port (via PortManager)
    - Its own headless IDA MCP server
    - Its own MCP client
    - Its own set of agents (dataflow + SSL)

    The registry ensures proper resource cleanup and prevents duplicate registrations.
    """

    def __init__(
        self,
        firmware_path: Optional[str],
        llm: any,
        port_manager: PortManager
    ):
        """Initialize the binary registry.

        Args:
            firmware_path: Path to firmware root (for resolving relative binary paths)
            llm: Language model instance to use for creating agents
            port_manager: PortManager instance for port allocation
        """
        self._registry: Dict[str, BinaryEntry] = {}
        self._lock = Lock()  # Thread-safe operations
        self._firmware_path = firmware_path
        self._llm = llm
        self._port_manager = port_manager

    def _normalize_path(self, binary_path: str) -> str:
        """Normalize binary path to absolute path.

        Handles firmware-relative paths by resolving against firmware root.

        Args:
            binary_path: Binary path (can be relative or absolute)

        Returns:
            Normalized absolute path
        """
        if os.path.isabs(binary_path):
            return os.path.abspath(binary_path)
        elif self._firmware_path:
            return os.path.abspath(os.path.join(self._firmware_path, binary_path))
        else:
            return os.path.abspath(binary_path)

    async def register_binary(self, binary_path: str) -> BinaryEntry:
        """Register a binary and initialize its MCP server and agents.

        This method:
        1. Normalizes the binary path
        2. Checks if already registered (returns existing if so)
        3. Allocates a port via PortManager
        4. Starts a headless IDA MCP server on that port
        5. Initializes MCP client
        6. Gets IDA tools from the MCP server
        7. Creates dataflow and SSL agents with those tools
        8. Stores the entry in the registry
        9. Returns the BinaryEntry

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            BinaryEntry for the registered binary

        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If port allocation fails or server start fails
        """
        with self._lock:
            # Normalize path
            normalized_path = self._normalize_path(binary_path)

            # Check if binary file exists
            if not os.path.exists(normalized_path):
                raise FileNotFoundError(
                    f"Binary file not found: {normalized_path}\n"
                    f"Original path: {binary_path}"
                )

            # Check if already registered
            if normalized_path in self._registry:
                console.print(f"[dim]📦 Binary already registered: {binary_path} (reusing)[/dim]")
                return self._registry[normalized_path]

            console.print(f"[cyan]📦 Registering binary: {binary_path}[/cyan]")

            try:
                # Allocate port
                port = self._port_manager.allocate_port(binary_path=normalized_path)
                console.print(f"[dim]  ├─ Allocated port: {port}[/dim]")

                # Hack: Pre-initialize IDA database to avoid PySide6 errors
                # When IDA opens a binary for the first time, it needs to do analysis
                # which may trigger GUI-related code paths. By opening and closing
                # the database first, the headless server can then open an existing database.
                console.print(f"[dim]  ├─ Pre-initializing IDA database...[/dim]")
                try:
                    import idapro
                    idapro.enable_console_messages(False)
                    idapro.open_database(normalized_path, run_auto_analysis=True)
                    idapro.close_database()
                    console.print(f"[dim]  ├─ Database pre-initialized[/dim]")
                except Exception as e:
                    # Database might already exist or initialization might fail
                    # Continue anyway as the headless server might still work
                    console.print(f"[yellow]  ├─ Pre-init note: {e}[/yellow]")

                # Start headless IDA server
                server_process = start_headless_ida_server(normalized_path, port=port)
                console.print(f"[dim]  ├─ Started MCP server on port {port}[/dim]")

                # Initialize MCP client
                server_config = {
                    "idapro": {
                        "transport": "sse",
                        "url": f"http://{IDA_SERVER_HOST}:{port}/sse"
                    }
                }

                client = MultiServerMCPClient(server_config)
                tools = await client.get_tools()
                console.print(f"[dim]  ├─ Loaded {len(tools)} IDA tools from MCP server[/dim]")

                # Create agents for this binary
                # Import here to avoid circular dependency
                from conn_analyzer.agents.factory import create_agents_for_binary

                agents = await create_agents_for_binary(
                    tools=tools,
                    binary_path=normalized_path,
                    llm=self._llm
                )
                console.print(f"[dim]  └─ Created agents: {', '.join(agents.keys())}[/dim]")

                # Create entry
                entry = BinaryEntry(
                    binary_path=normalized_path,
                    port=port,
                    server_process=server_process,
                    mcp_client=client,
                    agents=agents
                )

                # Store in registry
                self._registry[normalized_path] = entry

                console.print(f"[green]✓ Binary registered successfully: {binary_path}[/green]")
                return entry

            except Exception as e:
                # Cleanup on failure
                console.print(f"[red]✗ Failed to register binary: {e}[/red]")

                # Release port if allocated
                if 'port' in locals():
                    self._port_manager.release_port(port)

                # Terminate server if started
                if 'server_process' in locals() and server_process:
                    try:
                        server_process.terminate()
                        server_process.wait(timeout=5)
                    except:
                        pass

                raise RuntimeError(f"Failed to register binary {binary_path}: {e}") from e

    def get_binary_entry(self, binary_path: str) -> Optional[BinaryEntry]:
        """Get the registry entry for a binary.

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            BinaryEntry if registered, None otherwise
        """
        with self._lock:
            normalized_path = self._normalize_path(binary_path)
            return self._registry.get(normalized_path)

    def cleanup_binary(self, binary_path: str) -> bool:
        """Cleanup resources for a registered binary.

        This method:
        1. Terminates the MCP server
        2. Releases the allocated port
        3. Removes the entry from the registry

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            True if cleanup successful, False if binary not registered
        """
        with self._lock:
            normalized_path = self._normalize_path(binary_path)

            entry = self._registry.get(normalized_path)
            if entry is None:
                console.print(f"[yellow]⚠ Binary not registered: {binary_path}[/yellow]")
                return False

            console.print(f"[cyan]🧹 Cleaning up binary: {binary_path}[/cyan]")

            try:
                # Terminate server process
                if entry.server_process:
                    try:
                        console.print(f"[dim]  ├─ Terminating MCP server on port {entry.port}[/dim]")
                        entry.server_process.terminate()
                        entry.server_process.wait(timeout=5)
                    except Exception as e:
                        console.print(f"[yellow]  ├─ Warning: Failed to terminate server: {e}[/yellow]")

                # Release port
                try:
                    console.print(f"[dim]  ├─ Releasing port {entry.port}[/dim]")
                    self._port_manager.release_port(entry.port)
                except Exception as e:
                    console.print(f"[yellow]  ├─ Warning: Failed to release port: {e}[/yellow]")

                # Remove from registry
                del self._registry[normalized_path]
                console.print(f"[green]  └─ Cleanup complete[/green]")

                return True

            except Exception as e:
                console.print(f"[red]✗ Error during cleanup: {e}[/red]")
                return False

    def cleanup_all(self):
        """Cleanup all registered binaries.

        This method is typically called during shutdown to ensure
        all resources are properly released.
        """
        with self._lock:
            if not self._registry:
                return

            console.print(f"[cyan]🧹 Cleaning up {len(self._registry)} registered binaries...[/cyan]")

            # Get list of paths to avoid modifying dict during iteration
            paths = list(self._registry.keys())

            for path in paths:
                entry = self._registry[path]

                # Terminate server
                if entry.server_process:
                    try:
                        entry.server_process.terminate()
                        entry.server_process.wait(timeout=5)
                    except:
                        pass

                # Release port
                try:
                    self._port_manager.release_port(entry.port)
                except:
                    pass

            # Clear registry
            self._registry.clear()
            console.print("[green]✓ All binaries cleaned up[/green]")

    def get_registered_binaries(self) -> list[str]:
        """Get list of all registered binary paths.

        Returns:
            List of normalized binary paths
        """
        with self._lock:
            return list(self._registry.keys())
