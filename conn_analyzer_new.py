#!/usr/bin/env python3
"""
Compatibility wrapper for conn_analyzer.

This is a thin wrapper that imports and runs the new modular version.
The original conn_analyzer.py is kept for reference.
"""

from conn_analyzer.cli import run

if __name__ == "__main__":
    run()
