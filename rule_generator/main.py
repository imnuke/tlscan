#!/usr/bin/env python3
"""CLI entry point for the rule generator."""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from .prompt_builder import build_prompt


def main():
    """Main entry point for rule generator CLI."""
    parser = argparse.ArgumentParser(
        description="Generate library-specific SSL/TLS security rules using Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate rules from a documentation file
  uv run -m rule_generator --library wolfssl --doc-file wolfssl_docs.txt

  # Just print the prompt (don't run Claude)
  uv run -m rule_generator --library wolfssl --doc-file docs.txt --prompt-only

  # Save prompt to file for manual use
  uv run -m rule_generator --library wolfssl --doc-file docs.txt --prompt-only > prompt.txt
        """,
    )

    parser.add_argument(
        "--library",
        "-l",
        required=True,
        help="Name of the SSL/TLS library (e.g., wolfssl, boringssl, nss)",
    )

    parser.add_argument(
        "--doc-file",
        "-f",
        type=Path,
        required=True,
        help="Path to documentation file to analyze",
    )

    parser.add_argument(
        "--rules-dir",
        type=Path,
        help="Path to security_rules directory (default: auto-detect)",
    )

    parser.add_argument(
        "--prompt-only",
        "-p",
        action="store_true",
        help="Only print the prompt, don't run Claude Code",
    )

    args = parser.parse_args()

    # Validate input
    if not args.doc_file.exists():
        print(f"Error: Documentation file not found: {args.doc_file}", file=sys.stderr)
        sys.exit(1)

    # Load documentation
    documentation = args.doc_file.read_text()
    print(f"Loaded documentation from {args.doc_file}", file=sys.stderr)

    # Build prompt
    prompt = build_prompt(args.library, documentation, args.rules_dir)

    if args.prompt_only:
        # Just print the prompt
        print(prompt)
        return

    # Run Claude Code with the prompt
    print(f"Generating rules for {args.library} using Claude Code...", file=sys.stderr)

    # Write prompt to temp file to handle large prompts
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(prompt)
        temp_path = f.name

    try:
        # Run claude with --print flag for non-interactive output
        result = subprocess.run(
            ["claude", "--print", "-p", prompt],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"Claude Code error: {result.stderr}", file=sys.stderr)
            sys.exit(1)

        # Output the result
        print(result.stdout)

    finally:
        # Clean up temp file
        Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
