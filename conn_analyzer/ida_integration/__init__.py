"""
IDA Pro integration modules.

Provides server management and call graph generation functionality.
"""

from conn_analyzer.ida_integration.server import start_headless_ida_server
from conn_analyzer.ida_integration.call_graph import generate_call_graph_for_binary

__all__ = [
    "start_headless_ida_server",
    "generate_call_graph_for_binary",
]
