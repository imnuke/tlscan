"""curl/wget CLI tool library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for curl/wget CLI detection (string-based)
CURL_WGET_INDICATORS = [
    IndicatorSet(
        name="tools",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl",
            "wget",
            "/usr/bin/curl",
            "/usr/bin/wget",
            "/bin/curl",
            "/bin/wget",
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="urls",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "http://",
            "https://",
            "ftp://",
            "ftps://",
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="curl_insecure",
        strength=IndicatorStrength.STRONG,  # Security risk indicator
        indicators={
            "-k",
            "--insecure",
            "--no-check-certificate",
            "CURLOPT_SSL_VERIFYPEER",
            "CURLOPT_SSL_VERIFYHOST",
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="wget_insecure",
        strength=IndicatorStrength.STRONG,  # Security risk indicator
        indicators={
            "--no-check-certificate",
            "--no-verify-peer",
            "--no-host-check",
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="curl_options",
        strength=IndicatorStrength.WEAK,
        indicators={
            "-X",
            "--request",
            "-d",
            "--data",
            "-H",
            "--header",
            "-o",
            "--output",
            "-O",
            "--remote-name",
            "-u",
            "--user",
        },
        match_type=MatchType.EXACT,  # Exact match for options
    ),
    IndicatorSet(
        name="wget_options",
        strength=IndicatorStrength.WEAK,
        indicators={
            "-O",
            "--output-document",
            "-P",
            "--directory-prefix",
            "-q",
            "--quiet",
            "-c",
            "--continue",
            "--user",
            "--password",
        },
        match_type=MatchType.EXACT,  # Exact match for options
    ),
]


def _has_tool(h: dict) -> bool:
    """Check if any tool indicator was found."""
    return len(h.get("tools", [])) > 0


def _has_url(h: dict) -> bool:
    """Check if any URL scheme was found."""
    return len(h.get("urls", [])) > 0


def _has_insecure(h: dict) -> bool:
    """Check if any insecure flag was found."""
    return len(h.get("curl_insecure", [])) > 0 or len(h.get("wget_insecure", [])) > 0


def _has_options(h: dict) -> bool:
    """Check if enough options were found (minimum 2)."""
    return len(h.get("curl_options", [])) + len(h.get("wget_options", [])) >= 2


def _get_tool_name(h: dict) -> str:
    """Determine which tool was detected."""
    tools = h.get("tools", [])
    if any("curl" in t for t in tools):
        return "curl"
    elif any("wget" in t for t in tools):
        return "wget"
    return "unknown"


# Scoring rules (evaluated in order - first match wins)
CURL_WGET_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: _has_tool(h) and _has_url(h) and _has_insecure(h),
        rationale_template="SECURITY RISK: Tool with URL and insecure flags",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: _has_tool(h) and _has_url(h) and _has_options(h),
        rationale_template="Active tool usage with URLs and options detected",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: _has_tool(h) and _has_url(h),
        rationale_template="Command-line HTTP client usage",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: _has_tool(h),
        rationale_template="Tool command strings found: {tools}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: _has_url(h),
        rationale_template="URL schemes found but no tool commands",
    ),
]


CURL_WGET = LibraryDefinition(
    id="curl_wget",
    name="curl/wget",
    description="curl and wget command-line tools",
    detection_method="strings",
    applicable_file_types=["elf_binary", "php_script", "shell_script", "other_script"],
    indicator_sets=CURL_WGET_INDICATORS,
    scoring_rules=CURL_WGET_SCORING_RULES,
)
