"""
Command-line interface for conn_analyzer.

Provides argument parsing and entry point.
"""

import sys
import argparse
import asyncio
from pathlib import Path

# Add project root to path for importing project modules
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from conn_analyzer.config import DEFAULT_MAX_HOPS, TRIM_THRESHOLD_NODES
from conn_analyzer.main import main


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
        default="deepseek-chat",
        help="LLM model to use (default: deepseek-chat). "
             "Examples: openai:gpt-4o, anthropic:claude-sonnet-4-5, deepseek-chat"
    )
    parser.add_argument(
        "-g", "--call-graph",
        type=str,
        default=None,
        help="Path to call graph JSON file (default: auto-generated in temp_files/)"
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
        "-p", "--port",
        type=int,
        default=8800,
        help="IDA headless server port (default: 8800, supports multiple instances)"
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"Maximum hops from SSL functions when trimming call graph "
             f"(default: {DEFAULT_MAX_HOPS})"
    )
    parser.add_argument(
        "--trim-threshold",
        type=int,
        default=TRIM_THRESHOLD_NODES,
        help=f"Auto-trim call graph if it exceeds this many nodes "
             f"(default: {TRIM_THRESHOLD_NODES})"
    )
    parser.add_argument(
        "--disable-trim",
        action="store_true",
        help="Disable automatic call graph trimming"
    )
    return parser.parse_args()


def run():
    """Main entry point for CLI."""
    args = parse_args()

    asyncio.run(main(
        file_path=args.binary_path,
        model=args.model,
        conn_type=args.conn_type,
        call_graph_path=args.call_graph,
        firmware_path=args.firmware_path,
        rules=args.rules,
        port=args.port,
        max_hops=args.max_hops,
        trim_threshold=args.trim_threshold,
        disable_trim=args.disable_trim
    ))


if __name__ == "__main__":
    run()
