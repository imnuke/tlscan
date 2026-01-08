#!/usr/bin/env python3
"""Plain LLM demo for TLS security detection.

This demo shows baseline LLM performance on TLS security analysis
WITHOUT any security rules - just pseudocode + simple prompt.

Purpose: Academic comparison against the multi-agent system with rules.
"""

import argparse
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tlscan.config.loader import LLMConfig, ConfigurationError

SIMPLE_PROMPT = """Analyze the following decompiled C code for TLS/SSL security issues.
Identify any vulnerabilities or insecure configurations.

```c
{pseudocode}
```
"""


def create_llm(model_spec: str, config: LLMConfig):
    """Create an LLM instance based on model specification.

    Args:
        model_spec: Model specification in format "provider:model_name"
        config: LLM configuration with API keys

    Returns:
        LangChain LLM instance
    """
    if ":" not in model_spec:
        raise ValueError(
            f"Invalid model format: {model_spec}. Expected 'provider:model_name'"
        )

    provider, model_name = model_spec.split(":", 1)
    provider_config = config.get_provider_config(provider)

    if provider == "deepseek":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name,
            api_key=provider_config["api_key"],
            base_url=provider_config.get("api_base", "https://api.deepseek.com"),
        )
    elif provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_name,
            api_key=provider_config["api_key"],
        )
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model_name,
            api_key=provider_config["api_key"],
        )
    else:
        raise ValueError(f"Unknown provider: {provider}")


def main():
    parser = argparse.ArgumentParser(
        description="Plain LLM demo for TLS security detection (no rules)"
    )
    parser.add_argument(
        "pseudocode_file",
        type=Path,
        help="File containing pseudocode to analyze",
    )
    parser.add_argument(
        "-m",
        "--model",
        required=True,
        help="LLM model in format 'provider:model_name' (e.g., deepseek:deepseek-chat)",
    )

    args = parser.parse_args()

    # Load pseudocode
    if not args.pseudocode_file.exists():
        print(f"Error: File not found: {args.pseudocode_file}", file=sys.stderr)
        sys.exit(1)
    pseudocode = args.pseudocode_file.read_text()

    # Load LLM config
    try:
        config = LLMConfig()
    except ConfigurationError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Create LLM
    try:
        llm = create_llm(args.model, config)
    except (ValueError, ConfigurationError) as e:
        print(f"Error creating LLM: {e}", file=sys.stderr)
        sys.exit(1)

    # Build prompt and invoke
    prompt = SIMPLE_PROMPT.format(pseudocode=pseudocode)

    print(f"Model: {args.model}")
    print(f"File: {args.pseudocode_file}")
    print("=" * 60)
    print("Analyzing pseudocode for TLS security issues...")
    print("=" * 60)
    print()

    response = llm.invoke(prompt)
    print(response.content)


if __name__ == "__main__":
    main()
