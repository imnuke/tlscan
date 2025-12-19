"""
Universal tool middleware for enforcing token limits on tool results.

This middleware wraps LangChain tools to prevent excessive result sizes from
overwhelming the LLM context window. It provides a safety net by truncating
results and giving helpful guidance to the LLM on how to refine searches.
"""

from functools import wraps
from typing import List
from langchain_core.tools import BaseTool


def estimate_tokens(text: str) -> int:
    """
    Estimate token count using simple heuristic.

    Args:
        text: Text to estimate tokens for

    Returns:
        Estimated token count (characters / 4)
    """
    return len(text) // 4


def truncate_if_needed(result: str, max_tokens: int = 10000) -> str:
    """
    Truncate result if it exceeds token budget.

    This function checks if a tool result exceeds the token budget and
    truncates it if necessary, adding a helpful warning message that
    guides the LLM to refine their search.

    Args:
        result: Tool result string to check/truncate
        max_tokens: Maximum allowed tokens (default: 10000)

    Returns:
        Original result if under budget, or truncated result with warning
    """
    estimated = estimate_tokens(result)

    if estimated <= max_tokens:
        return result

    # Truncate to token budget
    max_chars = max_tokens * 4
    truncated = result[:max_chars]

    # Count how many results were found (heuristic based on newlines)
    match_count = result.count('\n')
    shown_count = truncated.count('\n')

    warning = f"""
⚠️ RESULT TRUNCATED: Showing ~{shown_count}/{match_count} results (exceeded {max_tokens} token limit).

To see complete results, refine your search:
- Use more specific patterns (e.g., "ssl_verify_mode" not "verify")
- Add file_pattern parameter (e.g., file_pattern="*.conf")
- Search in specific directories or file types
- Use exact matches with word boundaries or anchors
"""

    return truncated + "\n" + warning


def wrap_tool_with_token_limit(tool: BaseTool, max_tokens: int = 10000) -> BaseTool:
    """
    Wrap a LangChain tool to enforce token limits on results.

    This middleware intercepts tool results and truncates them if needed,
    providing helpful guidance to the LLM on how to refine searches.

    Args:
        tool: LangChain tool to wrap
        max_tokens: Maximum tokens per result (default: 10000)

    Returns:
        Wrapped tool with token limit enforcement
    """
    original_func = tool.func

    @wraps(original_func)
    def wrapper(*args, **kwargs):
        result = original_func(*args, **kwargs)
        return truncate_if_needed(result, max_tokens)

    tool.func = wrapper
    return tool


def wrap_all_tools(tools: List[BaseTool], max_tokens: int = 10000) -> List[BaseTool]:
    """
    Apply token limit wrapper to all tools in a list.

    This is the main entry point for applying middleware to firmware tools.

    Args:
        tools: List of LangChain tools
        max_tokens: Maximum tokens per result (default: 10000)

    Returns:
        List of wrapped tools with token limit enforcement

    Example:
        >>> wrapped_tools = wrap_all_tools(firmware_tools, max_tokens=10000)
        >>> agent = create_react_agent(llm, tools=wrapped_tools, ...)
    """
    return [wrap_tool_with_token_limit(tool, max_tokens) for tool in tools]
