#!/usr/bin/env python3
"""
Generate library-specific SSL/TLS security rules using Claude Code.

Usage:
    uv run rule_generator.py --library <name> --doc-file <path>
    uv run rule_generator.py --library <name> --doc-file <path> --prompt-only

For help:
    uv run rule_generator.py --help
"""

from rule_generator.main import main

if __name__ == "__main__":
    main()
