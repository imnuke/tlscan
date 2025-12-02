"""Checkpoint management for LangGraph workflow state persistence.

This module provides CheckpointManager which uses LangGraph's AsyncSqliteSaver
to persist workflow state after each node execution.
"""

import asyncio
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver


class CheckpointManager:
    """Manages workflow checkpoints and metadata.

    Uses LangGraph's built-in AsyncSqliteSaver for automatic state persistence.
    Provides thread management, metadata tracking, and checkpoint listing.
    """

    def __init__(
        self,
        checkpoint_dir: Path = None,
        persist: bool = True
    ):
        """Initialize checkpoint manager.

        Args:
            checkpoint_dir: Directory for checkpoint storage
            persist: Whether to persist checkpoints (default: True)
        """
        self.checkpoint_dir = checkpoint_dir or Path(".state_snapshots")
        self.persist = persist

        # Create directories
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir = self.checkpoint_dir / "metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        # Initialize AsyncSqliteSaver
        if persist:
            db_path = self.checkpoint_dir / "checkpoints.db"

            # Create AsyncSqliteSaver with aiosqlite connection
            # Note: We create the connection synchronously in __init__
            # The connection will be used in async context during workflow execution
            self._db_path = str(db_path)
            self._conn = None  # Store connection for cleanup
            self._checkpointer = None  # Will be initialized in async context
            self._initialized = False
        else:
            self._conn = None
            self._checkpointer = None
            self._db_path = None
            self._initialized = True

    def create_thread_id(self, binary_path: str) -> str:
        """Generate unique thread ID for a workflow run.

        Format: {binary_name}_{timestamp}_{uuid8}
        Example: libssl_20241202_143052_a3b4c5d6

        Args:
            binary_path: Path to binary being analyzed

        Returns:
            Unique thread ID string
        """
        binary_name = Path(binary_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]

        return f"{binary_name}_{timestamp}_{unique_id}"

    def save_metadata(
        self,
        thread_id: str,
        binary_path: str,
        rules: str,
        model: str,
        firmware_path: Optional[str] = None,
        **extra
    ):
        """Save thread metadata to JSON file.

        Args:
            thread_id: Thread identifier
            binary_path: Path to binary
            rules: Security rules used
            model: LLM model used
            firmware_path: Optional firmware root path
            **extra: Additional metadata fields
        """
        metadata = {
            "thread_id": thread_id,
            "binary_path": binary_path,
            "rules": rules,
            "model": model,
            "firmware_path": firmware_path,
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            **extra
        }

        metadata_file = self.metadata_dir / f"{thread_id}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

    def get_thread_metadata(self, thread_id: str) -> Optional[Dict]:
        """Load metadata for a specific thread.

        Args:
            thread_id: Thread identifier

        Returns:
            Metadata dict or None if not found
        """
        metadata_file = self.metadata_dir / f"{thread_id}.json"
        if not metadata_file.exists():
            return None

        with open(metadata_file, 'r') as f:
            return json.load(f)

    def list_threads(self) -> List[Dict]:
        """List all checkpoint threads with metadata.

        Returns:
            List of thread metadata dicts, sorted by timestamp (newest first)
        """
        threads = []

        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    threads.append(metadata)
            except (json.JSONDecodeError, OSError):
                continue

        # Sort by creation time (newest first)
        threads.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return threads

    def list_checkpoints(self, thread_id: str) -> List[Dict]:
        """List all checkpoints for a specific thread using direct SQLite query.

        This is a synchronous method that doesn't require async initialization,
        making it suitable for CLI commands.

        Args:
            thread_id: Thread identifier

        Returns:
            List of checkpoint info dicts with:
            - checkpoint_id: Checkpoint identifier
            - parent_id: Parent checkpoint ID
            - timestamp: When checkpoint was created (if available)
        """
        if not self._db_path:
            return []

        checkpoints = []
        try:
            # Use synchronous SQLite connection for read-only listing
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()

            # Query checkpoints table for this thread
            cursor.execute("""
                SELECT checkpoint_id, parent_checkpoint_id
                FROM checkpoints
                WHERE thread_id = ?
                ORDER BY checkpoint_id
            """, (thread_id,))

            for row in cursor.fetchall():
                checkpoint_id, parent_id = row
                checkpoints.append({
                    "checkpoint_id": checkpoint_id,
                    "parent_id": parent_id if parent_id else None,
                    "timestamp": "N/A"  # Timestamp would require parsing checkpoint blob
                })

            conn.close()
        except Exception as e:
            # Database error or table doesn't exist
            pass

        return checkpoints

    async def initialize(self):
        """Initialize the async checkpointer with aiosqlite connection.

        This must be called in an async context before using get_checkpointer().
        Call this from main.py after creating CheckpointManager.
        """
        if not self._initialized and self._db_path:
            # Create and STORE the aiosqlite connection
            self._conn = await aiosqlite.connect(self._db_path)

            # Create AsyncSqliteSaver with connection
            self._checkpointer = AsyncSqliteSaver(conn=self._conn)

            # Setup database tables
            await self._checkpointer.setup()

            self._initialized = True

    async def close(self):
        """Close the aiosqlite connection and cleanup resources.

        Call this in the finally block to ensure proper cleanup and allow
        the process to exit cleanly (especially on Ctrl-C).
        """
        if self._conn:
            await self._conn.close()
            self._conn = None
            self._checkpointer = None
            self._initialized = False

    def get_checkpointer(self) -> Optional[AsyncSqliteSaver]:
        """Get the AsyncSqliteSaver instance for workflow compilation.

        Note: You must call initialize() first in an async context.

        Returns:
            AsyncSqliteSaver instance or None if not persisting

        Raises:
            RuntimeError: If checkpointer not initialized
        """
        if not self._initialized and self._db_path:
            raise RuntimeError(
                "CheckpointManager not initialized. "
                "Call 'await checkpoint_manager.initialize()' before using get_checkpointer()"
            )

        return self._checkpointer
