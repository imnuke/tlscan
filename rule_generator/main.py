#!/usr/bin/env python3
"""CLI entry point for the rule generator."""

import argparse
import os
import shutil
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
  # Generate rules from a documentation file (shows real-time progress)
  uv run -m rule_generator --library wolfssl --doc-file wolfssl_docs.txt

  # Generate rules from a documentation URL (Claude fetches it)
  uv run -m rule_generator --library wolfssl --doc-url https://www.wolfssl.com/docs/

  # Save output to file
  uv run -m rule_generator --library wolfssl --doc-file docs.txt -o security_rules/rule_wolfssl.md

  # Quiet mode - suppress progress output
  uv run -m rule_generator --library wolfssl --doc-file docs.txt --quiet -o rule_wolfssl.md

  # Just print the prompt (don't run Claude)
  uv run -m rule_generator --library wolfssl --doc-file docs.txt --prompt-only
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
        help="Path to documentation file to analyze",
    )

    parser.add_argument(
        "--doc-url",
        "-u",
        help="URL to documentation (Claude will fetch it directly)",
    )

    parser.add_argument(
        "--rules-dir",
        type=Path,
        help="Path to security_rules directory (default: auto-detect)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path for generated rules (default: print to stdout)",
    )

    parser.add_argument(
        "--prompt-only",
        "-p",
        action="store_true",
        help="Only print the prompt, don't run Claude Code",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress Claude's progress output, show only final result",
    )

    args = parser.parse_args()

    # Validate input - need either doc-file or doc-url
    if not args.doc_file and not args.doc_url:
        print("Error: Must specify either --doc-file or --doc-url", file=sys.stderr)
        sys.exit(1)

    if args.doc_file and args.doc_url:
        print("Error: Cannot specify both --doc-file and --doc-url", file=sys.stderr)
        sys.exit(1)

    # Load documentation or use URL
    if args.doc_file:
        if not args.doc_file.exists():
            print(f"Error: Documentation file not found: {args.doc_file}", file=sys.stderr)
            sys.exit(1)
        documentation = args.doc_file.read_text()
        print(f"Loaded documentation from {args.doc_file}", file=sys.stderr)
        doc_url = None
    else:
        documentation = None
        doc_url = args.doc_url
        print(f"Will fetch documentation from {doc_url}", file=sys.stderr)

    # Build prompt
    prompt = build_prompt(args.library, documentation, args.rules_dir, doc_url=doc_url)

    if args.prompt_only:
        # Just print the prompt
        print(prompt)
        return

    # Run Claude Code with the prompt
    print(f"Generating rules for {args.library} using Claude Code...", file=sys.stderr)

    # Build command - add --verbose for real-time progress unless --quiet
    # Use --permission-mode acceptEdits to bypass plan mode and execute directly
    cmd = ["claude", "--print", "--permission-mode", "acceptEdits"]
    if not args.quiet:
        cmd.append("--verbose")
    cmd.extend(["-p", prompt])

    # Run Claude in isolated environment to avoid loading CLAUDE.md memory files
    # - CLAUDE_CONFIG_DIR set to temp dir: avoids user memory (~/.claude/CLAUDE.md)
    # - cwd set to temp dir: avoids project memory (./.claude/CLAUDE.md)
    # - Copy credentials to preserve authentication
    with tempfile.TemporaryDirectory() as config_dir:
        with tempfile.TemporaryDirectory() as work_dir:
            # Copy credentials from user's config (preserves login)
            user_config = Path.home() / ".claude"
            credentials_file = user_config / ".credentials.json"
            if credentials_file.exists():
                shutil.copy(credentials_file, Path(config_dir) / ".credentials.json")

            env = os.environ.copy()
            env["CLAUDE_CONFIG_DIR"] = config_dir

            # Stream output in real-time using Popen
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=work_dir,
            )

            # Stream stdout line by line
            output_lines = []
            for line in process.stdout:
                if not args.quiet:
                    print(line, end="", file=sys.stderr)  # Show progress to stderr
                output_lines.append(line)

            # Wait for process to complete and get stderr
            _, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Claude Code error: {stderr}", file=sys.stderr)
        sys.exit(1)

    # Output the final result
    final_output = "".join(output_lines)

    if args.output:
        args.output.write_text(final_output)
        print(f"Rules written to {args.output}", file=sys.stderr)
    else:
        print(final_output)


if __name__ == "__main__":
    main()
