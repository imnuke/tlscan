"""Port allocation manager for multi-instance IDA MCP server coordination.

This module provides thread-safe, multi-process port allocation using file-based locks.
Multiple tlscan instances can safely allocate ports without conflicts.
"""

import json
import os
import time
from pathlib import Path
from threading import Lock
from typing import Optional

from tlscan.config import (
    PORT_LOCK_DIR,
    PORT_LOCK_TIMEOUT,
    PORT_RANGE_END,
    PORT_RANGE_START,
)


class PortManager:
    """Manages port allocation across multiple tlscan instances.

    Uses file-based locks in temp_files/port_locks/ to coordinate port allocation
    across multiple processes. Each allocated port gets a lock file containing
    PID, timestamp, and binary path information.
    """

    def __init__(self):
        """Initialize the port manager and ensure lock directory exists."""
        self._lock = Lock()  # Thread-safe operations within this process
        self._ensure_lock_dir()

    def _ensure_lock_dir(self):
        """Create the port lock directory if it doesn't exist."""
        PORT_LOCK_DIR.mkdir(parents=True, exist_ok=True)

    def _get_lock_file_path(self, port: int) -> Path:
        """Get the path to the lock file for a given port."""
        return PORT_LOCK_DIR / f"{port}.lock"

    def _is_process_alive(self, pid: int) -> bool:
        """Check if a process with the given PID is still running."""
        if pid <= 0:
            return False

        try:
            # Send signal 0 to check if process exists (doesn't actually send a signal)
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _is_lock_stale(self, lock_file: Path) -> bool:
        """Check if a lock file is stale (process dead or timeout exceeded).

        Args:
            lock_file: Path to the lock file to check

        Returns:
            True if the lock is stale and can be cleaned up, False otherwise
        """
        try:
            with open(lock_file, 'r') as f:
                lock_data = json.load(f)

            pid = lock_data.get('pid', 0)
            timestamp = lock_data.get('timestamp', 0)

            # Check if process is dead
            if not self._is_process_alive(pid):
                return True

            # Check if lock has timed out
            if time.time() - timestamp > PORT_LOCK_TIMEOUT:
                return True

            return False
        except (json.JSONDecodeError, IOError):
            # If we can't read the lock file, consider it stale
            return True

    def is_port_available(self, port: int) -> bool:
        """Check if a port is available (no lock file or stale lock).

        Args:
            port: Port number to check

        Returns:
            True if the port is available, False otherwise
        """
        lock_file = self._get_lock_file_path(port)

        if not lock_file.exists():
            return True

        # Check if the lock is stale
        return self._is_lock_stale(lock_file)

    def allocate_port(self, binary_path: Optional[str] = None) -> int:
        """Allocate an available port from the configured range.

        Creates a lock file with PID, timestamp, and binary path information.
        Uses atomic file operations to prevent race conditions across processes.

        Args:
            binary_path: Optional binary path for debugging (stored in lock file)

        Returns:
            Allocated port number

        Raises:
            RuntimeError: If no ports are available in the configured range
        """
        with self._lock:  # Thread-safe within this process
            for port in range(PORT_RANGE_START, PORT_RANGE_END + 1):
                if self.is_port_available(port):
                    lock_file = self._get_lock_file_path(port)

                    # Try to create the lock file atomically
                    try:
                        # Use os.open with O_CREAT | O_EXCL for atomic creation
                        # This ensures only one process can create the file
                        fd = os.open(
                            lock_file,
                            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                            0o644
                        )

                        # Write lock data
                        lock_data = {
                            'pid': os.getpid(),
                            'timestamp': time.time(),
                            'binary_path': binary_path or 'unknown',
                        }

                        os.write(fd, json.dumps(lock_data, indent=2).encode())
                        os.close(fd)

                        return port
                    except FileExistsError:
                        # Another process created the lock file, try next port
                        continue
                    except OSError as e:
                        # Other error, log and try next port
                        print(f"Warning: Failed to create lock file for port {port}: {e}")
                        continue

            # No ports available
            raise RuntimeError(
                f"Port exhaustion: All ports in range {PORT_RANGE_START}-{PORT_RANGE_END} are in use. "
                "Try increasing the port range or cleaning up stale locks with cleanup_stale_locks()."
            )

    def release_port(self, port: int) -> bool:
        """Release a port by removing its lock file.

        Args:
            port: Port number to release

        Returns:
            True if port was successfully released, False if lock file didn't exist
        """
        with self._lock:
            lock_file = self._get_lock_file_path(port)

            if not lock_file.exists():
                return False

            try:
                lock_file.unlink()
                return True
            except OSError as e:
                print(f"Warning: Failed to release port {port}: {e}")
                return False

    def cleanup_stale_locks(self) -> int:
        """Clean up stale lock files (dead processes or timed out).

        This should be called periodically or at startup to clean up locks
        from crashed processes or long-running analyses.

        Returns:
            Number of stale locks cleaned up
        """
        with self._lock:
            cleaned_count = 0

            if not PORT_LOCK_DIR.exists():
                return 0

            for lock_file in PORT_LOCK_DIR.glob("*.lock"):
                if self._is_lock_stale(lock_file):
                    try:
                        lock_file.unlink()
                        cleaned_count += 1
                        print(f"Cleaned up stale lock: {lock_file.name}")
                    except OSError as e:
                        print(f"Warning: Failed to clean up stale lock {lock_file.name}: {e}")

            return cleaned_count

    def get_allocated_ports(self) -> list[int]:
        """Get a list of currently allocated ports.

        Returns:
            List of port numbers that are currently locked
        """
        with self._lock:
            if not PORT_LOCK_DIR.exists():
                return []

            ports = []
            for lock_file in PORT_LOCK_DIR.glob("*.lock"):
                try:
                    port = int(lock_file.stem)
                    if not self._is_lock_stale(lock_file):
                        ports.append(port)
                except ValueError:
                    # Not a valid port number
                    continue

            return sorted(ports)
