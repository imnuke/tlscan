"""
Command-line interface for conn_analyzer.

Provides argument parsing and entry point.
"""

import sys
import argparse
import asyncio
from pathlib import Path
from rich.console import Console

# Add project root to path for importing project modules
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from conn_analyzer.main import main

console = Console()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze SSL/TLS security using multi-agent system with IDA Pro"
    )
    parser.add_argument(
        "binary_path",
        type=str,
        help="Path to binary file to analyze (absolute or relative). "
             "Relative paths are resolved against --firmware-path if provided, "
             "otherwise against current working directory."
    )
    parser.add_argument(
        "-c", "--conn-type",
        type=str,
        default="headless_ida",
        choices=["plugin", "headless_ida"],
        help="IDA connection type: 'plugin' (IDA GUI with MCP plugin) or "
             "'headless_ida' (automatic headless server) (default: headless_ida)"
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default=None,
        help="LLM model to use. "
             "Examples: openai:gpt-4o, anthropic:claude-sonnet-4-5, deepseek:deepseek-chat"
    )
    parser.add_argument(
        "-f", "--firmware-path",
        type=str,
        default=None,
        help="Path to firmware filesystem root (enables firmware analysis agent)"
    )
    parser.add_argument(
        "-r", "--rules",
        type=str,
        default="openssl",
        choices=["openssl", "curl", "libcurl", "gnutls", "mbedtls", "php_curl", "wget"],
        help="SSL/TLS library rules to use (default: openssl)"
    )
    parser.add_argument(
        "--save-checkpoints",
        action="store_true",
        help="Enable automatic state checkpointing after each workflow node"
    )
    parser.add_argument(
        "--resume",
        type=str,
        metavar="THREAD_ID",
        help="Resume workflow from saved checkpoint thread ID"
    )
    parser.add_argument(
        "--from-checkpoint",
        type=str,
        metavar="CHECKPOINT_ID",
        help="Resume from specific checkpoint ID (requires --resume)"
    )
    parser.add_argument(
        "--list-threads",
        action="store_true",
        help="List all available checkpoint threads and exit"
    )
    parser.add_argument(
        "--list-checkpoints",
        type=str,
        metavar="THREAD_ID",
        help="List all checkpoints in a specific thread and exit"
    )
    return parser.parse_args()


def run():
    """Main entry point for CLI."""
    args = parse_args()

    # Handle --list-threads
    if args.list_threads:
        from conn_analyzer.persistence import CheckpointManager
        from rich.table import Table

        checkpoint_manager = CheckpointManager()
        threads = checkpoint_manager.list_threads()

        if not threads:
            console.print("[yellow]No checkpoint threads found[/yellow]")
            sys.exit(0)

        # Create table
        table = Table(title="Checkpoint Threads", show_header=True, header_style="bold cyan")
        table.add_column("Thread ID", style="cyan")
        table.add_column("Binary", style="green")
        table.add_column("Rules", style="yellow")
        table.add_column("Model", style="magenta")
        table.add_column("Created At", style="dim")

        for thread in threads:
            binary_name = Path(thread['binary_path']).name
            created_at = thread.get('created_at', 'N/A')
            # Format timestamp
            if created_at != 'N/A':
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(created_at)
                    created_at = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass

            table.add_row(
                thread['thread_id'],
                binary_name,
                thread.get('rules', 'N/A'),
                thread.get('model', 'N/A'),
                created_at
            )

        console.print(table)
        sys.exit(0)

    # Handle --list-checkpoints
    if args.list_checkpoints:
        from conn_analyzer.persistence import CheckpointManager
        from rich.table import Table

        checkpoint_manager = CheckpointManager()
        checkpoints = checkpoint_manager.list_checkpoints(args.list_checkpoints)

        if not checkpoints:
            console.print(f"[yellow]No checkpoints found for thread: {args.list_checkpoints}[/yellow]")
            sys.exit(0)

        # Create table
        table = Table(title=f"Checkpoints for {args.list_checkpoints}", show_header=True, header_style="bold cyan")
        table.add_column("Checkpoint ID", style="cyan")
        table.add_column("Parent ID", style="dim")
        table.add_column("Timestamp", style="green")

        for cp in checkpoints:
            checkpoint_id = cp.get('checkpoint_id', 'N/A')
            parent_id = cp.get('parent_id', 'None')
            timestamp = cp.get('timestamp', 'N/A')

            # Show full IDs (UUIDs)
            table.add_row(
                checkpoint_id if checkpoint_id != 'N/A' else 'N/A',
                parent_id if parent_id and parent_id != 'None' else 'None',
                str(timestamp)
            )

        console.print(table)
        sys.exit(0)

    # Validate --from-checkpoint requires --resume
    if args.from_checkpoint and not args.resume:
        console.print("[red]Error: --from-checkpoint requires --resume[/red]")
        sys.exit(1)

    try:
        asyncio.run(main(
            file_path=args.binary_path,
            model=args.model,
            conn_type=args.conn_type,
            firmware_path=args.firmware_path,
            rules=args.rules,
            save_checkpoints=args.save_checkpoints,
            thread_id=args.resume,
            checkpoint_id=args.from_checkpoint
        ))
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]🛑 Analysis interrupted by user (Ctrl-C)[/yellow]")
        console.print("[dim]Cleanup already completed[/dim]")
        sys.exit(0)
    except Exception as e:
        console.print()
        console.print(f"[red]✗ Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    run()
