"""TeamClaude-backed ChatAnthropic wrapper.

This module provides a ChatAnthropic subclass used ONLY for piloting the
framework against an Anthropic subscription proxied through the local
`teamclaude` router (a multi-account Claude proxy). It is not intended for
the reproducible experiments reported in the paper: for those, use a real
`anthropic` API key via the standard `anthropic` provider.

Why a subclass is needed
-------------------------
The subscription OAuth path enforced by the upstream requires that every
request carry, as the FIRST system block, the Claude Code CLI identity
string. TLScan's agents each supply their own task-specific system prompt
(ssl / dataflow / firmware), so we inject the identity block at the payload
layer, ahead of whatever system prompt the agent provided. This keeps all
three agent prompt files untouched.

The required `anthropic-beta: oauth-2025-04-20` header is supplied via
`default_headers` at construction time (see main.parse_model_string).
"""

from __future__ import annotations

from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import LanguageModelInput

# The exact identity string the subscription OAuth path expects as the first
# system block. Empirically required: a request without it hangs/rejects.
CLAUDE_CODE_IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude."


def _prepend_identity(system: Any) -> list[dict[str, Any]]:
    """Return a system value with the Claude Code identity as the first block.

    Anthropic accepts `system` as either a string or a list of text blocks.
    We always normalize to a list so the identity block can be placed first,
    ahead of the agent-provided prompt, without mutating the original.
    """
    identity_block = {"type": "text", "text": CLAUDE_CODE_IDENTITY}

    if system is None:
        return [identity_block]
    if isinstance(system, str):
        return [identity_block, {"type": "text", "text": system}]
    if isinstance(system, list):
        # Avoid double-injection if identity is already the first block.
        if system and isinstance(system[0], dict) and system[0].get("text") == CLAUDE_CODE_IDENTITY:
            return system
        return [identity_block, *system]
    # Unknown shape: fall back to stringifying, still identity-first.
    return [identity_block, {"type": "text", "text": str(system)}]


class TeamClaudeChatAnthropic(ChatAnthropic):
    """ChatAnthropic that forces the Claude Code identity as the first system block."""

    def _get_request_payload(
        self,
        input_: LanguageModelInput,
        *,
        stop: list[str] | None = None,
        **kwargs: dict,
    ) -> dict:
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        payload["system"] = _prepend_identity(payload.get("system"))
        return payload
