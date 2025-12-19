"""
Formatting utilities for tlscan analyzer.

Provides functions for formatting tokens, durations, and markdown.
"""

from rich.markdown import Markdown, Heading
from rich.panel import Panel
from rich import box

from tlscan.config import TOKEN_WARNING_THRESHOLD


def count_tokens(text: str, model: str = "gpt-4") -> int:
    """
    Count tokens in text using tiktoken.

    Args:
        text: Text to count tokens for
        model: Model name for tokenizer (default: gpt-4)

    Returns:
        Token count
    """
    try:
        import tiktoken
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception:
        # Fallback: rough estimate (1 token ≈ 4 chars)
        return len(text) // 4


def format_token_count(count: int, threshold: int = TOKEN_WARNING_THRESHOLD) -> str:
    """
    Format token count with highlighting if it exceeds threshold.

    Args:
        count: Token count to format
        threshold: Warning threshold (default: TOKEN_WARNING_THRESHOLD)

    Returns:
        Formatted string with color coding for high counts
    """
    if count > threshold:
        return f"[bold yellow]⚠️ {count:,}[/bold yellow]"
    else:
        return f"{count:,}"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string like "2m 34s" or "15.3s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"


# Custom Heading class with left alignment instead of center
class LeftAlignedHeading(Heading):
    """Custom heading that renders left-aligned instead of centered."""

    def __rich_console__(self, console, options):
        text = self.text
        text.justify = "left"  # Changed from "center" to "left"
        if self.tag == "h1":
            # Draw a border around h1s
            yield Panel(
                text,
                box=box.HEAVY,
                style="markdown.h1.border",
            )
        else:
            # Styled text for h2 and beyond
            if self.tag == "h2":
                from rich.text import Text
                yield Text("")
            yield text


def create_markdown(content: str) -> Markdown:
    """Create a Markdown instance with left-aligned headings."""
    md = Markdown(content)
    # Override the heading element to use our custom left-aligned version
    md.elements["heading_open"] = LeftAlignedHeading
    return md
