"""Base definitions for library detection.

Provides the core abstractions for defining how libraries are detected.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Set, List, Callable, Dict, Optional, Tuple
import re


class IndicatorStrength(Enum):
    """Strength level for detection indicators."""

    STRONG = auto()  # Definitive proof of client usage
    MEDIUM = auto()  # Strong suggestion of client usage
    WEAK = auto()  # May indicate client usage


class MatchType(Enum):
    """How to match indicators against extracted data."""

    EXACT = auto()  # Exact match (for symbols)
    SUBSTRING = auto()  # Substring match (for strings)


@dataclass
class IndicatorSet:
    """A set of indicators with associated strength and matching behavior."""

    name: str
    """Category name (e.g., 'strong', 'client_methods', 'weak')."""

    strength: IndicatorStrength
    """How strongly this indicator set suggests library usage."""

    indicators: Set[str]
    """The actual indicator strings to match."""

    match_type: MatchType = MatchType.EXACT
    """How to match indicators (exact for symbols, substring for strings)."""


@dataclass
class ScoringRule:
    """A rule for determining detection confidence.

    Scoring rules are evaluated in order - first matching rule wins.
    """

    confidence: str
    """Confidence level if this rule matches: 'high', 'medium', 'low'."""

    condition: Callable[[Dict[str, List[str]]], bool]
    """Function that takes hits dict and returns True if rule matches."""

    rationale_template: str
    """Template string for the rationale message. Can use {hits} placeholder."""

    def format_rationale(self, hits: Dict[str, List[str]]) -> str:
        """Format the rationale message with actual hit data."""
        # For simple templates, just return as-is
        if "{" not in self.rationale_template:
            return self.rationale_template

        # Try to format with hits data
        try:
            # Support {category} style placeholders
            formatted = self.rationale_template
            for category, items in hits.items():
                placeholder = "{" + category + "}"
                if placeholder in formatted:
                    formatted = formatted.replace(placeholder, ", ".join(sorted(items)))
            return formatted
        except Exception:
            return self.rationale_template


@dataclass
class VersionPattern:
    """Pattern for extracting version information from strings."""

    pattern: re.Pattern
    """Compiled regex pattern with a capturing group for version."""

    name: str
    """Display name for this pattern (e.g., 'OpenSSL version string')."""


@dataclass
class LibraryDefinition:
    """Complete definition for detecting a library.

    This dataclass encapsulates everything needed to detect a specific
    library: what to look for, how to score matches, and how to report.
    """

    id: str
    """Unique identifier (e.g., 'openssl', 'libcurl')."""

    name: str
    """Human-readable display name (e.g., 'OpenSSL', 'libcurl')."""

    description: str
    """Brief description of what this library detection covers."""

    detection_method: str
    """Primary detection method: 'symbols', 'strings', or 'both'."""

    applicable_file_types: List[str]
    """File types this library can be detected in (e.g., ['elf_binary'])."""

    indicator_sets: List[IndicatorSet]
    """Categorized indicators for detection."""

    scoring_rules: List[ScoringRule]
    """Ordered scoring rules (first match wins)."""

    version_patterns: List[VersionPattern] = field(default_factory=list)
    """Regex patterns for version string extraction."""

    # Optional: backend symbols for curl-like libraries
    backend_symbols: Optional[Dict[str, Set[str]]] = None
    """Backend-specific symbols keyed by backend name (for curl/libcurl)."""
