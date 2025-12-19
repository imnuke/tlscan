"""
Agent context management.

Provides message history management and pruning.
"""

from langchain_core.messages import ToolMessage


def prune_message_history(messages: list, max_recent: int = 5) -> list:
    """
    Keep recent messages and summarize older ones to save context.

    Strategy:
    - Keep: Initial user query + last N messages
    - For older messages: Keep AI synthesis, remove detailed tool results
    - Replace tool result content with summary to save tokens

    Args:
        messages: List of message objects
        max_recent: Number of recent messages to keep completely (default: 5)

    Returns:
        Pruned message list
    """
    if len(messages) <= max_recent + 1:
        # Not enough messages to prune
        return messages

    # Always keep first message (original user query)
    pruned = [messages[0]]

    # Process middle messages (between first and last N)
    middle_messages = messages[1:-max_recent]

    for msg in middle_messages:
        if hasattr(msg, "type"):
            if msg.type == "ai":
                # Keep AI synthesis messages, but create a copy without tool_calls details
                pruned.append(msg)
            elif msg.type == "tool":
                # Replace tool result content with summary
                from langchain_core.messages import ToolMessage
                summary_content = f"[Tool result cleared for context management - Tool: {msg.name}]"
                pruned.append(ToolMessage(
                    content=summary_content,
                    tool_call_id=msg.tool_call_id if hasattr(msg, "tool_call_id") else "",
                    name=msg.name if hasattr(msg, "name") else ""
                ))
            elif msg.type == "human":
                # Keep human messages
                pruned.append(msg)

    # Keep last N messages completely intact (current working context)
    pruned.extend(messages[-max_recent:])

    return pruned

def cleanup_old_tool_results(messages: list, keep_last_n: int = 3) -> list:
    """
    Clear tool result content from older messages, keeping only recent ones.

    This is called after an agent synthesizes findings to reduce context usage.

    Args:
        messages: List of message objects
        keep_last_n: Number of most recent tool results to keep intact

    Returns:
        Cleaned message list
    """
    from langchain_core.messages import ToolMessage

    # Find all tool message indices
    tool_indices = []
    for i, msg in enumerate(messages):
        if hasattr(msg, "type") and msg.type == "tool":
            tool_indices.append(i)

    if len(tool_indices) <= keep_last_n:
        # Not enough tool results to clean
        return messages

    # Indices of tool results to clear (all except last N)
    clear_indices = set(tool_indices[:-keep_last_n])

    # Create new list with cleared tool results
    cleaned = []
    for i, msg in enumerate(messages):
        if i in clear_indices:
            # Replace this tool result with summary
            summary_content = f"[Tool result cleared - Tool: {msg.name if hasattr(msg, 'name') else 'unknown'}]"
            cleaned.append(ToolMessage(
                content=summary_content,
                tool_call_id=msg.tool_call_id if hasattr(msg, "tool_call_id") else "",
                name=msg.name if hasattr(msg, "name") else ""
            ))
        else:
            cleaned.append(msg)

    return cleaned

