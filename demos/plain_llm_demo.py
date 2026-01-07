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

# Hard-coded sample pseudocode from libupsclient.so.c
# This is a real-world OpenSSL TLS client with:
# - Conditional certificate verification
# - Missing hostname verification vulnerability
SAMPLE_PSEUDOCODE = '''
__int64 __fastcall upscli_sslinit(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  if ( !upscli_initialized )
  {
    if ( nut_debug_level > 2 )
      s_upsdebugx(
        3,
        (unsigned int)"upscli not initialized, force initialisation without SSL configuration",
        a3,
        a4,
        a5,
        a6);
    upscli_init(0, 0, 0, 0);
  }
  strcpy(s, "STARTTLS\\n");
  v6 = strlen(s);
  if ( upscli_sendline(a1, s, v6) )
    return 0xFFFFFFFFLL;
  if ( upscli_readline(a1, s, 512) )
    return 0xFFFFFFFFLL;
  if ( strncmp(s, "OK STARTTLS", 0xBu) )
    return 0;
  if ( ssl_ctx )
  {
    v12 = SSL_new(ssl_ctx);
    *(_QWORD *)(a1 + 656) = v12;
    if ( *(_QWORD *)(a1 + 656) )
    {
      if ( (unsigned int)SSL_set_fd(*(_QWORD *)(a1 + 656), *(unsigned int *)(a1 + 12)) == 1 )
      {
        if ( a2 )
          SSL_set_verify(*(_QWORD *)(a1 + 656), 1, 0);
        else
          SSL_set_verify(*(_QWORD *)(a1 + 656), 0, 0);
        v20 = SSL_connect(*(_QWORD *)(a1 + 656));
        v30 = v20;
        if ( v20 )
        {
          if ( v20 == 1 )
          {
            if ( nut_debug_level > 2 )
            {
              version = SSL_get_version(*(_QWORD *)(a1 + 656));
              s_upsdebugx(3, (unsigned int)"SSL connected (%s)", version, v26, v27, v28);
            }
            return 1;
          }
          else
          {
            upslog_with_errno(1, (unsigned int)"Unknown return value from SSL_connect %d", v30, v22, v23, v24);
            ssl_error(*(_QWORD *)(a1 + 656), v30);
            return 0xFFFFFFFFLL;
          }
        }
        else
        {
          upslog_with_errno(1, (unsigned int)"SSL_connect do not accept handshake.", v21, v22, v23, v24);
          ssl_error(*(_QWORD *)(a1 + 656), v30);
          return 0xFFFFFFFFLL;
        }
      }
      else
      {
        if ( nut_debug_level > 2 )
          s_upsdebugx(3, (unsigned int)"Can not bind file descriptor to SSL socket", v16, v17, v18, v19);
        return 0xFFFFFFFFLL;
      }
    }
    else
    {
      if ( nut_debug_level > 2 )
        s_upsdebugx(3, (unsigned int)"Can not create SSL socket", v12, v13, v14, v15);
      return 0;
    }
  }
  else
  {
    if ( nut_debug_level > 2 )
      s_upsdebugx(3, (unsigned int)"SSL context is not available", v8, v9, v10, v11);
    return 0;
  }
}
'''.strip()

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
        "-m",
        "--model",
        required=True,
        help="LLM model in format 'provider:model_name' (e.g., deepseek:deepseek-chat)",
    )
    parser.add_argument(
        "--pseudocode-file",
        type=Path,
        help="Optional file containing pseudocode (overrides built-in sample)",
    )

    args = parser.parse_args()

    # Load pseudocode
    if args.pseudocode_file:
        if not args.pseudocode_file.exists():
            print(f"Error: File not found: {args.pseudocode_file}", file=sys.stderr)
            sys.exit(1)
        pseudocode = args.pseudocode_file.read_text()
    else:
        pseudocode = SAMPLE_PSEUDOCODE

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
    print("=" * 60)
    print("Analyzing pseudocode for TLS security issues...")
    print("=" * 60)
    print()

    response = llm.invoke(prompt)
    print(response.content)


if __name__ == "__main__":
    main()
