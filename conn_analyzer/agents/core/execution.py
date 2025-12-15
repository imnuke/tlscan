"""
Agent execution infrastructure.

Provides streaming execution and logging for agents.
"""

import time
import json
from typing import TypedDict, Tuple, Any
from rich.console import Console
from rich.panel import Panel

from conn_analyzer.utils.formatting import format_duration, count_tokens, format_token_count
from conn_analyzer.utils.formatting import create_markdown
from conn_analyzer.agents.core.context_management import cleanup_old_tool_results, prune_message_history
import conn_analyzer.agents.core.middleware as middleware_module

# Initialize console
console = Console()


# ============================================================================
# Metrics Types
# ============================================================================

class AgentMetrics(TypedDict):
    """Metrics from a single agent invocation."""

    thinking_tokens: int
    """Tokens in AI thinking/content messages."""

    tool_result_tokens: int
    """Tokens in tool result messages."""

    tool_call_count: int
    """Number of tool calls made."""

    elapsed_seconds: float
    """Total execution time in seconds."""


def create_empty_metrics() -> AgentMetrics:
    """Create an empty AgentMetrics dict with all fields initialized to zero."""
    return AgentMetrics(
        thinking_tokens=0,
        tool_result_tokens=0,
        tool_call_count=0,
        elapsed_seconds=0.0,
    )


def add_metrics(base: AgentMetrics, addition: AgentMetrics) -> AgentMetrics:
    """Add two AgentMetrics together."""
    return AgentMetrics(
        thinking_tokens=base["thinking_tokens"] + addition["thinking_tokens"],
        tool_result_tokens=base["tool_result_tokens"] + addition["tool_result_tokens"],
        tool_call_count=base["tool_call_count"] + addition["tool_call_count"],
        elapsed_seconds=base["elapsed_seconds"] + addition["elapsed_seconds"],
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
    config = config or {"recursion_limit": 100}

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
                # Check if it's an AI message with tool calls
                if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                    # Print AI message content if present
                    if hasattr(last_message, "content") and last_message.content and last_message.content.strip():
                        thinking_tokens = count_tokens(last_message.content)
                        metrics["thinking_tokens"] += thinking_tokens  # Track thinking tokens
                        console.print(f"[bold blue]💭 {agent_name} THINKING - {format_token_count(thinking_tokens)} tokens:[/bold blue]")
                        md = create_markdown(last_message.content)
                        console.print(md)
                        console.print()

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
                    tool_tokens = count_tokens(last_message.content)
                    metrics["tool_result_tokens"] += tool_tokens  # Track tool result tokens

                    # Check if it's an error result
                    if hasattr(last_message, "status") and last_message.status == "error":
                        console.print(f"[bold yellow]⚠️  {agent_name} TOOL ERROR ({last_message.name}):[/bold yellow]")
                        # Escape square brackets in error messages to prevent Rich markup parsing errors
                        escaped_error = last_message.content.replace("[", r"\[").replace("]", r"\]")
                        console.print(f"  [yellow]{escaped_error}[/yellow]")
                    else:
                        console.print(f"[bold green]📊 {agent_name} TOOL RESULT ([cyan]{last_message.name}[/cyan]) - {format_token_count(tool_tokens)} tokens:[/bold green]")
                        content_preview = last_message.content[:500] if len(last_message.content) > 500 else last_message.content
                        # Escape square brackets to prevent Rich markup parsing errors
                        escaped_preview = content_preview.replace("[", r"\[").replace("]", r"\]")
                        console.print(f"  [dim]{escaped_preview}{'...' if len(last_message.content) > 500 else ''}[/dim]")
                    console.print()

                # Check if it's an AI message with content (thinking)
                elif hasattr(last_message, "type") and last_message.type == "ai":
                    if hasattr(last_message, "content") and last_message.content and last_message.content.strip():
                        thinking_tokens = count_tokens(last_message.content)
                        metrics["thinking_tokens"] += thinking_tokens  # Track thinking tokens
                        console.print(f"[bold blue]💭 {agent_name} THINKING - {format_token_count(thinking_tokens)} tokens:[/bold blue]")
                        md = create_markdown(last_message.content)
                        console.print(md)
                        console.print()
                        final_content = last_message.content

                # Check if it's a human message
                elif hasattr(last_message, "type") and last_message.type == "human":
                    if hasattr(last_message, "content") and last_message.content and last_message.content.strip():
                        user_tokens = count_tokens(last_message.content)
                        console.print(f"[bold green]🧑 User Message - {format_token_count(user_tokens)} tokens:[/bold green]")
                        md = create_markdown(last_message.content)
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
        f"[bold green]✓ {agent_name} Complete ({format_duration(elapsed)})[/bold green]",
        border_style="green"
    ))
    console.print()

    # Parse output into Pydantic model if requested
    if output_model:
        try:
            # Try to parse as JSON first
            if final_content.strip().startswith("{") or final_content.strip().startswith("["):
                data = json.loads(final_content)
            else:
                # Try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', final_content, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(1))
                else:
                    # If no JSON found, try to parse the whole content as JSON
                    data = json.loads(final_content)

            # Normalize status values to lowercase for enum compatibility
            data = _normalize_enum_values(data)

            return (output_model(**data), metrics)
        except Exception as e:
            console.print(f"[yellow]⚠️ Failed to parse output into {output_model.__name__}: {e}[/yellow]")
            console.print(f"[dim]Raw output: {final_content[:500]}...[/dim]")
            raise ValueError(f"Failed to parse agent output into {output_model.__name__}: {e}")

    return (final_content, metrics)
