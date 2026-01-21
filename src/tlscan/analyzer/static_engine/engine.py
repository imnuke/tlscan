"""Static Analysis Engine for managing IDA Pro MCP servers.

This module provides the StaticAnalysisEngine class that manages MCP servers
for multiple binaries. Each binary gets its own MCP server instance and tools.

The engine is responsible for:
- Starting and stopping IDA Pro MCP servers
- Managing port allocation
- Providing IDA tools for each binary

It does NOT create agents - that's the responsibility of AgentFactory.
"""

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, List

from langchain_mcp_adapters.client import MultiServerMCPClient
from rich.console import Console

from tlscan.analyzer.static_engine.ida.server import start_headless_ida_server
from tlscan.analyzer.static_engine.ida.ports import PortManager
from tlscan.config import IDA_SERVER_HOST, TEMP_IDB_DIR

# Initialize console for output
console = Console()


@dataclass
class MCPSession:
    """Represents an active MCP server session for a binary.

    Attributes:
        binary_path: Absolute path to the binary file
        idb_dir: Path to IDB session directory (None if no directory created)
        port: Allocated MCP server port
        server_process: Server subprocess handle
        mcp_client: MCP client instance for this binary
        tools: List of IDA tools from the MCP server
    """
    binary_path: str
    idb_dir: Optional[str]
    port: int
    server_process: any  # subprocess.Popen
    mcp_client: MultiServerMCPClient
    tools: List[any]  # List of LangChain tools


class StaticAnalysisEngine:
    """Engine for managing IDA Pro MCP servers across multiple binaries.

    This class provides thread-safe management of MCP server sessions.
    Each binary gets its own:
    - Allocated port (via PortManager)
    - Headless IDA MCP server
    - MCP client
    - IDA tools

    The engine ensures proper resource cleanup and prevents duplicate sessions.
    It does NOT create agents - use AgentFactory for that.
    """

    def __init__(
        self,
        firmware_path: Optional[str],
        port_manager: PortManager,
    ):
        """Initialize the static analysis engine.

        Args:
            firmware_path: Path to firmware root (for resolving relative binary paths)
            port_manager: PortManager instance for port allocation
        """
        self._sessions: Dict[str, MCPSession] = {}
        self._lock = Lock()  # Thread-safe operations
        self._firmware_path = firmware_path
        self._port_manager = port_manager

    def _normalize_path(self, binary_path: str) -> str:
        """Normalize binary path to absolute path.

        Handles firmware-relative paths by resolving against firmware root.
        Detects paths that look absolute but are actually firmware-relative
        (e.g., /usr/bin/app is really firmware_root/usr/bin/app).

        Args:
            binary_path: Binary path (can be relative or absolute)

        Returns:
            Normalized absolute path
        """
        # Strip leading slash if path doesn't exist as absolute but we have firmware_path
        # This handles LLM returning "/usr/bin/app" when it means "usr/bin/app"
        if self._firmware_path and binary_path.startswith('/'):
            # Check if it exists as a true absolute path
            if not os.path.exists(binary_path):
                # Likely a firmware-relative path with leading slash
                binary_path = binary_path.lstrip('/')

        if os.path.isabs(binary_path):
            return os.path.abspath(binary_path)
        elif self._firmware_path:
            return os.path.abspath(os.path.join(self._firmware_path, binary_path))
        else:
            return os.path.abspath(binary_path)

    def _create_idb_session_dir(self) -> str:
        """Create session directory for IDB files.

        Directory structure: /tmp/tlscan/idb/{session_id}/

        Returns:
            Absolute path to IDB session directory
        """
        session_id = str(uuid.uuid4())[:8]
        idb_dir = TEMP_IDB_DIR / session_id
        idb_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[dim]  ├─ Created IDB directory: {idb_dir}[/dim]")
        return str(idb_dir)

    def _cleanup_idb_dir(self, idb_dir: str):
        """Remove IDB session directory.

        Args:
            idb_dir: Path to IDB session directory
        """
        if not idb_dir:
            return

        try:
            idb_path = Path(idb_dir)
            if idb_path.exists():
                shutil.rmtree(idb_path)
                console.print(f"[dim]  ├─ Removed IDB directory: {idb_path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]  ├─ Warning: Failed to remove IDB directory: {e}[/yellow]")

    def _is_session_alive(self, session: MCPSession) -> bool:
        """Check if an MCP session is still alive.

        Args:
            session: MCPSession to check

        Returns:
            True if session is alive, False otherwise
        """
        if session.server_process is None:
            return False

        # Check if process is still running (poll() returns None if running)
        return session.server_process.poll() is None

    def _cleanup_session(self, session: MCPSession):
        """Clean up a dead session's resources including IDB directory.

        Args:
            session: MCPSession to clean up
        """
        # Terminate server process if still exists
        if session.server_process:
            try:
                session.server_process.terminate()
                session.server_process.wait(timeout=2)
            except:
                pass

        # Release port
        if session.port:
            self._port_manager.release_port(session.port)

        # Clean up IDB directory
        if session.idb_dir:
            self._cleanup_idb_dir(session.idb_dir)

    async def get_tools(self, binary_path: str) -> List[any]:
        """Get IDA tools for a binary, starting MCP server if needed.

        This is the main entry point for obtaining static analysis tools.

        Cache behavior:
        - Searches for existing session by original binary path
        - Reuses session if found and alive (intra-run caching)
        - Creates new IDB session directory if not cached
        - Cache keyed by IDB directory to support concurrent runs

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            List of IDA tools from the MCP server

        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If server start fails
        """
        with self._lock:
            # Normalize path
            normalized_path = self._normalize_path(binary_path)

            # Check if session already exists for this binary (search by original path)
            existing_session = None
            for session in self._sessions.values():
                if session.binary_path == normalized_path:
                    existing_session = session
                    break

            # If session exists and alive, reuse it
            if existing_session and self._is_session_alive(existing_session):
                console.print(f"[dim]📦 Reusing existing MCP session: {binary_path}[/dim]")
                return existing_session.tools

            # If session exists but dead, clean it up
            if existing_session:
                console.print(f"[yellow]⚠ MCP session died, restarting: {binary_path}[/yellow]")
                self._cleanup_session(existing_session)
                del self._sessions[existing_session.idb_dir]

            # Start new session (creates IDB session directory)
            console.print(f"[cyan]📦 Starting MCP session for: {binary_path}[/cyan]")
            session = await self._start_session(normalized_path)

            # Store in cache using IDB directory as key (enables concurrent sessions)
            self._sessions[session.idb_dir] = session

            console.print(f"[green]✓ MCP session ready: {len(session.tools)} tools available[/green]")
            return session.tools

    async def _start_session(self, normalized_path: str) -> MCPSession:
        """Start a new MCP server session for a binary.

        This method:
        1. Validates binary exists
        2. Creates IDB session directory
        3. Allocates port
        4. Starts headless IDA MCP server with --idb-dir
        5. Initializes MCP client
        6. Gets IDA tools

        Args:
            normalized_path: Normalized absolute path to binary

        Returns:
            MCPSession for the binary

        Raises:
            FileNotFoundError: If binary doesn't exist
            RuntimeError: If any step fails
        """
        # Check if binary file exists
        if not os.path.exists(normalized_path):
            raise FileNotFoundError(f"Binary file not found: {normalized_path}")

        idb_dir = None

        try:
            # Create IDB session directory
            idb_dir = self._create_idb_session_dir()

            # Allocate port (use original path for lock file identification)
            port = self._port_manager.allocate_port(binary_path=normalized_path)
            console.print(f"[dim]  ├─ Allocated port: {port}[/dim]")

            # Start headless IDA server with original binary and IDB directory
            server_process = start_headless_ida_server(
                normalized_path, idb_dir=idb_dir, port=port
            )
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
            console.print(f"[dim]  └─ Loaded {len(tools)} IDA tools from MCP server[/dim]")

            # Create session
            return MCPSession(
                binary_path=normalized_path,
                idb_dir=idb_dir,
                port=port,
                server_process=server_process,
                mcp_client=client,
                tools=tools
            )

        except Exception as e:
            # Cleanup on failure
            console.print(f"[red]✗ Failed to start MCP session: {e}[/red]")

            # Clean up IDB directory if created
            if idb_dir:
                self._cleanup_idb_dir(idb_dir)

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

            raise RuntimeError(f"Failed to start MCP session for {normalized_path}: {e}") from e

    def get_session(self, binary_path: str) -> Optional[MCPSession]:
        """Get the MCP session for a binary.

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            MCPSession if exists, None otherwise
        """
        with self._lock:
            normalized_path = self._normalize_path(binary_path)
            return self._sessions.get(normalized_path)

    def cleanup(self, binary_path: str) -> bool:
        """Cleanup MCP session for a binary including IDB directory.

        This method:
        1. Terminates the MCP server
        2. Releases the allocated port
        3. Removes IDB session directory
        4. Removes the session

        Args:
            binary_path: Path to binary (can be relative or absolute)

        Returns:
            True if cleanup successful, False if session not found
        """
        with self._lock:
            normalized_path = self._normalize_path(binary_path)

            # Find session by original binary path (cache is keyed by IDB directory)
            session = None
            session_key = None
            for key, sess in self._sessions.items():
                if sess.binary_path == normalized_path:
                    session = sess
                    session_key = key
                    break

            if session is None:
                console.print(f"[yellow]⚠ No MCP session for: {binary_path}[/yellow]")
                return False

            console.print(f"[cyan]🧹 Cleaning up MCP session: {binary_path}[/cyan]")

            try:
                # Terminate server process
                if session.server_process:
                    try:
                        console.print(f"[dim]  ├─ Terminating MCP server on port {session.port}[/dim]")
                        session.server_process.terminate()
                        session.server_process.wait(timeout=5)
                    except Exception as e:
                        console.print(f"[yellow]  ├─ Warning: Failed to terminate server: {e}[/yellow]")

                # Release port
                try:
                    console.print(f"[dim]  ├─ Releasing port {session.port}[/dim]")
                    self._port_manager.release_port(session.port)
                except Exception as e:
                    console.print(f"[yellow]  ├─ Warning: Failed to release port: {e}[/yellow]")

                # Clean up IDB directory
                if session.idb_dir:
                    self._cleanup_idb_dir(session.idb_dir)

                # Remove from sessions
                del self._sessions[session_key]
                console.print(f"[green]  └─ Cleanup complete[/green]")

                return True

            except Exception as e:
                console.print(f"[red]✗ Error during cleanup: {e}[/red]")
                return False

    def cleanup_all(self):
        """Cleanup all MCP sessions including IDB directories.

        This method is typically called during shutdown to ensure
        all resources are properly released.
        """
        with self._lock:
            if not self._sessions:
                return

            console.print(f"[cyan]🧹 Cleaning up {len(self._sessions)} MCP sessions...[/cyan]")

            # Get list of keys to avoid modifying dict during iteration
            keys = list(self._sessions.keys())

            for key in keys:
                session = self._sessions[key]

                # Terminate server
                if session.server_process:
                    try:
                        # First try graceful termination (SIGTERM)
                        session.server_process.terminate()
                        session.server_process.wait(timeout=5)
                        console.print(f"[dim]  ✓ Server for {Path(session.binary_path).name} terminated gracefully[/dim]")
                    except subprocess.TimeoutExpired:
                        # Process didn't respond to SIGTERM, force kill (SIGKILL)
                        console.print(f"[yellow]  ⚠ Server for {Path(session.binary_path).name} unresponsive, forcing termination...[/yellow]")
                        try:
                            session.server_process.kill()
                            session.server_process.wait(timeout=2)
                            console.print(f"[dim]  ✓ Server forcefully terminated[/dim]")
                        except Exception as e:
                            console.print(f"[red]  ✗ Failed to kill server: {e}[/red]")
                    except Exception as e:
                        console.print(f"[yellow]  ⚠ Warning during server termination: {e}[/yellow]")

                # Release port
                try:
                    self._port_manager.release_port(session.port)
                except Exception as e:
                    console.print(f"[yellow]  ⚠ Warning: Failed to release port {session.port}: {e}[/yellow]")

                # Clean up IDB directory
                if session.idb_dir:
                    self._cleanup_idb_dir(session.idb_dir)

            # Clear sessions
            self._sessions.clear()
            console.print("[green]✓ All MCP sessions cleaned up[/green]")

    def get_active_binaries(self) -> List[str]:
        """Get list of all binaries with active MCP sessions.

        Returns:
            List of normalized binary paths
        """
        with self._lock:
            return list(self._sessions.keys())

    def get_script_tools(self, script_path: str) -> List[any]:
        """Get tools for script analysis (instead of IDA tools).

        This method is used for non-binary files (shell scripts, PHP, etc.)
        that don't need IDA Pro for analysis.

        Args:
            script_path: Path to the script file

        Returns:
            List of script analysis tools
        """
        from tlscan.analyzer.static_engine import scripts

        # Normalize path
        normalized_path = self._normalize_path(script_path)

        # Set the script path and get tools
        scripts.set_script_path(normalized_path)
        return scripts.get_script_tools()
