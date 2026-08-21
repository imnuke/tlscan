"""
Agent execution infrastructure.

Provides streaming execution and logging for agents.
"""

import time
import json
from typing import TypedDict, Tuple, Any
from rich.console import Console
from rich.panel import Panel

from tlscan.analyzer.utils.formatting import format_duration, count_tokens, format_token_count
from tlscan.analyzer.utils.formatting import create_markdown
from tlscan.analyzer.agents.core.context import cleanup_old_tool_results, prune_message_history
import tlscan.analyzer.agents.core.middleware as middleware_module

# Initialize console
console = Console()


# ============================================================================
# Metrics Types
# ============================================================================

class AgentOutputParseError(ValueError):
    """Raised when an agent's final message cannot be parsed into its model.

    Carries the metrics of the invocation that failed: the LLM call really
    happened and really cost tokens, so a caller that recovers from the failure
    must still be able to bill it. Subclasses ValueError so existing handlers
    keep working.
    """

    def __init__(self, message: str, metrics: "AgentMetrics"):
        super().__init__(message)
        self.metrics = metrics


class AgentMetrics(TypedDict):
    """Metrics from a single agent invocation."""

    thinking_tokens: int
    """Tokens in AI thinking/content messages (local estimate, not billed)."""

    tool_result_tokens: int
    """Tokens in tool result messages (local estimate, not billed)."""

    tool_call_count: int
    """Number of tool calls made."""

    elapsed_seconds: float
    """Total execution time in seconds."""

    real_input_tokens: int
    """Real prompt tokens billed by the provider (from AIMessage.usage_metadata)."""

    real_output_tokens: int
    """Real completion tokens billed by the provider."""

    real_total_tokens: int
    """Real total tokens billed by the provider (input + output)."""

    cache_hit_tokens: int
    """Prompt tokens served from the provider's context cache (billed cheaper)."""


def create_empty_metrics() -> AgentMetrics:
    """Create an empty AgentMetrics dict with all fields initialized to zero."""
    return AgentMetrics(
        thinking_tokens=0,
        tool_result_tokens=0,
        tool_call_count=0,
        elapsed_seconds=0.0,
        real_input_tokens=0,
        real_output_tokens=0,
        real_total_tokens=0,
        cache_hit_tokens=0,
    )


def add_metrics(base: AgentMetrics, addition: AgentMetrics) -> AgentMetrics:
    """Add two AgentMetrics together."""
    return AgentMetrics(
        thinking_tokens=base["thinking_tokens"] + addition["thinking_tokens"],
        tool_result_tokens=base["tool_result_tokens"] + addition["tool_result_tokens"],
        tool_call_count=base["tool_call_count"] + addition["tool_call_count"],
        elapsed_seconds=base["elapsed_seconds"] + addition["elapsed_seconds"],
        real_input_tokens=base["real_input_tokens"] + addition["real_input_tokens"],
        real_output_tokens=base["real_output_tokens"] + addition["real_output_tokens"],
        real_total_tokens=base["real_total_tokens"] + addition["real_total_tokens"],
        cache_hit_tokens=base["cache_hit_tokens"] + addition["cache_hit_tokens"],
    )


def _normalize_enum_values(data):
    """Normalize enum values to lowercase for case-insensitive parsing."""
    if isinstance(data, dict):
        normalized = {}
        for key, value in data.items():
            if key in ("status", "step_type", "resolving_status", "source_kind") and isinstance(value, str):
                # Normalize enum values to lowercase
                normalized[key] = value.lower()
            else:
                # Recursively normalize nested dicts and lists
                normalized[key] = _normalize_enum_values(value)
        return normalized
    elif isinstance(data, list):
        return [_normalize_enum_values(item) for item in data]
    else:
        return data


def _strip_json_comments(json_string: str) -> str:
    """Remove JS-style comments from JSON and normalize Python-style literals.

    Handles:
    - // line comments
    - /* block comments */
    - Python-style None/True/False → null/true/false (outside quoted strings)
    """
    result = []
    in_string = False
    i = 0
    n = len(json_string)

    while i < n:
        char = json_string[i]

        if in_string:
            result.append(char)
            if char == '\\' and i + 1 < n:
                i += 1
                result.append(json_string[i])
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
                result.append(char)
            elif char == '/' and i + 1 < n and json_string[i + 1] == '/':
                # Skip // line comment
                while i < n and json_string[i] != '\n':
                    i += 1
                continue
            elif char == '/' and i + 1 < n and json_string[i + 1] == '*':
                # Skip /* block comment */
                i += 2
                while i < n - 1 and not (json_string[i] == '*' and json_string[i + 1] == '/'):
                    i += 1
                i += 2  # skip closing */
                continue
            elif char in ('N', 'T', 'F') and not in_string:
                # Detect Python-style None/True/False literals
                rest = json_string[i:]
                if rest.startswith('None'):
                    result.append('null')
                    i += 4
                    continue
                elif rest.startswith('True'):
                    result.append('true')
                    i += 4
                    continue
                elif rest.startswith('False'):
                    result.append('false')
                    i += 5
                    continue
                else:
                    result.append(char)
            else:
                result.append(char)

        i += 1

    return ''.join(result)


def _content_to_text(content: Any) -> str:
    """Normalize a LangChain message ``content`` to plain text.

    DeepSeek/OpenAI return ``content`` as a ``str``, whereas Anthropic returns
    a list of content blocks (e.g. ``text`` / ``tool_use``). The streaming
    logger and the JSON output parser below both assume a string, so collapse
    the list form to the concatenation of its text-bearing blocks. ``tool_use``
    blocks are intentionally dropped here because tool calls are surfaced
    separately via ``last_message.tool_calls``.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "".join(parts)
    return str(content)


async def stream_and_log_agent(agent, messages: list, agent_name: str, agent_emoji: str = "🤖", config: dict = None, output_model=None) -> Tuple[Any, AgentMetrics]:
    """
    Stream an agent's execution and log all intermediate steps.

    Args:
        agent: The agent to execute
        messages: List of messages to send to the agent
        agent_name: Display name of the agent (e.g., "Dataflow Agent")
        agent_emoji: Emoji to use for this agent (e.g., "🔍")
        config: Optional config dict for the agent
        output_model: Optional Pydantic model class to parse the output into

    Returns:
        Tuple of (output, metrics) where:
        - output: The final AI message content (string) or parsed Pydantic model if output_model is provided
        - metrics: AgentMetrics with token counts, tool calls, and timing
    """
    # Print agent header
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]{agent_emoji} {agent_name} Executing[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    start_time = time.perf_counter()

    # Initialize metrics tracking
    metrics = create_empty_metrics()

    # Prune message history if it's getting long to save context
    # if len(messages) > 10:
    #     original_count = len(messages)
    #     messages = prune_message_history(messages, max_recent=5)
    #     console.print(f"[dim]  ℹ  Message history pruned: {original_count} → {len(messages)} messages (context management)[/dim]")
    #     console.print()

    final_content = ""
    last_json_candidate = ""  # last AI message content starting with '{' (may be in tool-call branch)
    config = config or {"recursion_limit": 300}

    # Track how many messages we've already processed to avoid duplicates
    processed_message_count = 0

    async for chunk in agent.astream(
        {"messages": messages},
        stream_mode="values",
        config=config
    ):
        # Check if connection failed - terminate immediately
        if middleware_module.connection_failed:
            break

        # Get only NEW messages we haven't processed yet
        if "messages" in chunk and chunk["messages"]:
            new_messages = chunk["messages"][processed_message_count:]

            # Process each new message
            for last_message in new_messages:
                # Capture REAL billed token usage before dispatching to the
                # print branches. LangChain attaches usage_metadata to every
                # AIMessage (present in both streaming and non-streaming), so
                # each model turn is counted exactly once here (messages are
                # de-duplicated via processed_message_count). Non-AI messages
                # (tool/human) carry no usage_metadata and are skipped. Unlike
                # count_tokens() below, which only estimates the size of the
                # thinking/tool-result TEXT, this is the actual prompt+completion
                # the provider billed, including the full re-sent context.
                usage = getattr(last_message, "usage_metadata", None)
                if usage:
                    metrics["real_input_tokens"] += usage.get("input_tokens", 0)
                    metrics["real_output_tokens"] += usage.get("output_tokens", 0)
                    metrics["real_total_tokens"] += usage.get("total_tokens", 0)
                    details = usage.get("input_token_details") or {}
                    metrics["cache_hit_tokens"] += details.get("cache_read", 0)

                # Normalize content once: Anthropic returns a list of blocks,
                # others return a plain string. Downstream display and JSON
                # parsing both assume a string.
                msg_text = _content_to_text(getattr(last_message, "content", None))
                # Check if it's an AI message with tool calls
                if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                    # Print AI message content if present
                    if hasattr(last_message, "content") and msg_text and msg_text.strip():
                        thinking_tokens = count_tokens(msg_text)
                        metrics["thinking_tokens"] += thinking_tokens  # Track thinking tokens
                        console.print(f"[bold blue]💭 {agent_name} THINKING - {format_token_count(thinking_tokens)} tokens:[/bold blue]")
                        md = create_markdown(msg_text)
                        console.print(md)
                        console.print()
                        # Track JSON candidates even in tool-call messages (DeepSeek sometimes puts
                        # the final JSON here before making one more tool call, then emits prose as
                        # the true final message — which overwrites final_content with non-JSON text)
                        if msg_text.strip().startswith("{"):
                            last_json_candidate = msg_text

                    # Print tool calls with counter
                    total_calls = len(last_message.tool_calls)
                    metrics["tool_call_count"] += total_calls  # Track tool call count
                    console.print(f"[bold magenta]🔧 {agent_name} TOOL CALLS ({total_calls}):[/bold magenta]")
                    for i, tool_call in enumerate(last_message.tool_calls, start=1):
                        console.print(f"  • [cyan]Tool Call {i}/{total_calls}: {tool_call['name']}[/cyan]")
                        # Escape square brackets in JSON output to prevent Rich markup parsing errors
                        args_json = json.dumps(tool_call['args'], indent=6).replace("[", r"\[").replace("]", r"\]")
                        console.print(f"    [dim]Args: {args_json}[/dim]")

                    # Print invalid tool calls if any
                    if hasattr(last_message, "invalid_tool_calls") and last_message.invalid_tool_calls:
                        for invalid_call in last_message.invalid_tool_calls:
                            call_name = invalid_call.get('name', 'unknown')
                            console.print(f"  • [yellow]⚠️  Tool Call [INVALID]: {call_name}[/yellow]")
                            if 'error' in invalid_call:
                                error_msg = str(invalid_call['error']).replace("[", r"\[").replace("]", r"\]")
                                console.print(f"    [dim]Error: {error_msg}[/dim]")
                            if 'args' in invalid_call:
                                args_json = json.dumps(invalid_call['args'], indent=6).replace("[", r"\[").replace("]", r"\]")
                                console.print(f"    [dim]Args: {args_json}[/dim]")

                    console.print()

                # Check if it's a tool message (result)
                elif hasattr(last_message, "type") and last_message.type == "tool":
                    # Count tokens in tool result (even for errors)
                    tool_tokens = count_tokens(msg_text)
                    metrics["tool_result_tokens"] += tool_tokens  # Track tool result tokens

                    # Check if it's an error result
                    if hasattr(last_message, "status") and last_message.status == "error":
                        console.print(f"[bold yellow]⚠️  {agent_name} TOOL ERROR ({last_message.name}):[/bold yellow]")
                        # Escape square brackets in error messages to prevent Rich markup parsing errors
                        escaped_error = msg_text.replace("[", r"\[").replace("]", r"\]")
                        console.print(f"  [yellow]{escaped_error}[/yellow]")
                    else:
                        console.print(f"[bold green]📊 {agent_name} TOOL RESULT ([cyan]{last_message.name}[/cyan]) - {format_token_count(tool_tokens)} tokens:[/bold green]")
                        content_preview = msg_text[:500] if len(msg_text) > 500 else msg_text
                        # Escape square brackets to prevent Rich markup parsing errors
                        escaped_preview = content_preview.replace("[", r"\[").replace("]", r"\]")
                        console.print(f"  [dim]{escaped_preview}{'...' if len(msg_text) > 500 else ''}[/dim]")
                    console.print()

                # Check if it's an AI message with content (thinking)
                elif hasattr(last_message, "type") and last_message.type == "ai":
                    if hasattr(last_message, "content") and msg_text and msg_text.strip():
                        thinking_tokens = count_tokens(msg_text)
                        metrics["thinking_tokens"] += thinking_tokens  # Track thinking tokens
                        console.print(f"[bold blue]💭 {agent_name} THINKING - {format_token_count(thinking_tokens)} tokens:[/bold blue]")
                        md = create_markdown(msg_text)
                        console.print(md)
                        console.print()
                        final_content = msg_text
                        if msg_text.strip().startswith("{"):
                            last_json_candidate = msg_text

                # Check if it's a human message
                elif hasattr(last_message, "type") and last_message.type == "human":
                    if hasattr(last_message, "content") and msg_text and msg_text.strip():
                        user_tokens = count_tokens(msg_text)
                        console.print(f"[bold green]🧑 User Message - {format_token_count(user_tokens)} tokens:[/bold green]")
                        md = create_markdown(msg_text)
                        console.print(md)
                        console.print()

                else:
                    # Output unhandled message types for debugging (pretty printed as JSON)
                    console.print(f"[dim]  ℹ  Unhandled message type in {agent_name}:[/dim]")
                    try:
                        # Convert message to dict for JSON serialization
                        if hasattr(last_message, "dict"):
                            message_dict = last_message.dict()
                        elif hasattr(last_message, "model_dump"):
                            message_dict = last_message.model_dump()
                        else:
                            # Fallback: try to convert to dict directly
                            message_dict = dict(last_message) if hasattr(last_message, "__dict__") else {"message": str(last_message)}

                        # Pretty print as JSON with proper escaping
                        pretty_json = json.dumps(message_dict, indent=2, default=str)
                        escaped_json = pretty_json.replace("[", r"\[").replace("]", r"\]")
                        console.print(f"  [dim]{escaped_json}[/dim]")
                    except Exception as e:
                        # Fallback to string representation if JSON serialization fails
                        console.print(f"  [dim]{str(last_message).replace('[', r'\[').replace(']', r'\]')}[/dim]")
                        console.print(f"  [dim](JSON serialization failed: {e})[/dim]")
                    console.print()

            # Update the count of processed messages after processing all new messages
            processed_message_count = len(chunk["messages"])

    elapsed = time.perf_counter() - start_time
    metrics["elapsed_seconds"] = elapsed  # Track elapsed time
    console.print(Panel.fit(
        f"[bold green]✓ {agent_name} Complete ({format_duration(elapsed)})[/bold green]\n"
        f"[dim]🔢 Real tokens: in={metrics['real_input_tokens']:,} "
        f"out={metrics['real_output_tokens']:,} "
        f"total={metrics['real_total_tokens']:,} "
        f"(cache_hit={metrics['cache_hit_tokens']:,})[/dim]",
        border_style="green"
    ))
    console.print()

    # Parse output into Pydantic model if requested
    if output_model:
        import re

        # output_model(**data) structurally requires a mapping, so a candidate
        # that is not a dict is noise no matter where it was found.
        required_fields = {
            name
            for name, field in getattr(output_model, "model_fields", {}).items()
            if field.is_required()
        }

        def _best_object(candidates):
            objects = [c for c in candidates if isinstance(c, dict)]
            if not objects:
                return None
            # Prefer the last candidate that actually satisfies the model: the
            # intermediate drafts an agent emits (a bare rule object, a
            # conditions fragment) are dicts too.
            if required_fields:
                complete = [o for o in objects if required_fields <= o.keys()]
                if complete:
                    return complete[-1]
            return objects[-1]

        def _scan_embedded_json(text: str):
            # Agents routinely narrate before answering, may emit several
            # intermediate JSON drafts, and often keep talking AFTER the final
            # answer. A greedy first-brace-to-last-brace regex splices prose
            # between drafts and fails, while a first-match regex picks a draft.
            # Forward-scan every '{'/'[' with a strict decoder and collect every
            # value that decodes cleanly; prose braces raise and are skipped.
            # Arrays are collected but dropped by _best_object, because trailing
            # prose about decompiled code ("sa_data[0]") parses as a JSON array
            # and would otherwise win as the last value.
            dec = json.JSONDecoder()
            cleaned = _strip_json_comments(text)
            candidates = []
            idx, n = 0, len(cleaned)
            while idx < n:
                if cleaned[idx] in "{[":
                    try:
                        obj, end = dec.raw_decode(cleaned, idx)
                        candidates.append(obj)
                        idx = end
                        continue
                    except Exception:
                        pass
                idx += 1
            return _best_object(candidates)

        def _try_parse_json(text: str):
            stripped = text.strip()
            # Each of the shaped attempts below can pick the wrong span when the
            # message holds more than one JSON value, so a miss here falls
            # through to the forward scan rather than aborting the parse.
            if stripped.startswith("{"):
                try:
                    parsed = json.loads(_strip_json_comments(text))
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass
            # Tried before the fence regex: when a message carries several
            # fenced blocks, re.search returns the FIRST, which is a draft.
            embedded = _scan_embedded_json(text)
            if embedded is not None:
                return embedded
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(_strip_json_comments(json_match.group(1)))
                except Exception:
                    pass
            bare_match = re.search(r'\{[\s\S]*\}', text)
            if bare_match:
                return json.loads(_strip_json_comments(bare_match.group(0)))
            return json.loads(_strip_json_comments(text))

        try:
            data = _try_parse_json(final_content)
        except Exception as first_err:
            # final_content was prose (e.g. DeepSeek emitted JSON in a tool-call
            # thinking block then continued with a prose summary message).
            # Fall back to the last AI-message content that started with '{'.
            if last_json_candidate and last_json_candidate != final_content:
                try:
                    data = _try_parse_json(last_json_candidate)
                except Exception as second_err:
                    console.print(f"[yellow]⚠️ Failed to parse output into {output_model.__name__}: {first_err}[/yellow]")
                    console.print(f"[dim]Raw output: {final_content[:500]}...[/dim]")
                    raise AgentOutputParseError(
                        f"Failed to parse agent output into {output_model.__name__}: {first_err}",
                        metrics,
                    )
            else:
                console.print(f"[yellow]⚠️ Failed to parse output into {output_model.__name__}: {first_err}[/yellow]")
                console.print(f"[dim]Raw output: {final_content[:500]}...[/dim]")
                raise ValueError(f"Failed to parse agent output into {output_model.__name__}: {first_err}")

        # Normalize status values to lowercase for enum compatibility
        data = _normalize_enum_values(data)

        return (output_model(**data), metrics)

    return (final_content, metrics)
