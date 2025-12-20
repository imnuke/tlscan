"""PHP curl extension library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for PHP curl detection (hybrid: symbols + strings)
PHP_CURL_INDICATORS = [
    IndicatorSet(
        name="php_functions",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_init",
            "curl_exec",
            "curl_setopt",
            "curl_setopt_array",
            "curl_close",
            "curl_getinfo",
            "curl_error",
            "curl_errno",
            "curl_multi_init",
            "curl_multi_exec",
            "curl_multi_add_handle",
        },
        match_type=MatchType.SUBSTRING,  # String matching for PHP scripts
    ),
    IndicatorSet(
        name="php_internal",
        strength=IndicatorStrength.STRONG,
        indicators={
            "php_curl_init",
            "php_curl_exec",
            "php_curl_setopt",
            "php_curl_close",
            "zif_curl_init",
            "zif_curl_exec",
            "zif_curl_setopt",
            "zif_curl_setopt_array",
            "zif_curl_close",
            "zif_curl_getinfo",
        },
        match_type=MatchType.EXACT,  # Symbol matching for internal functions
    ),
    IndicatorSet(
        name="curlopt_constants",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "CURLOPT_URL",
            "CURLOPT_RETURNTRANSFER",
            "CURLOPT_SSL_VERIFYPEER",
            "CURLOPT_SSL_VERIFYHOST",
            "CURLOPT_CAINFO",
            "CURLOPT_CAPATH",
            "CURLOPT_SSLVERSION",
            "CURLOPT_POST",
            "CURLOPT_POSTFIELDS",
            "CURLOPT_HTTPHEADER",
            "CURLOPT_FOLLOWLOCATION",
        },
        match_type=MatchType.SUBSTRING,
    ),
    IndicatorSet(
        name="insecure_patterns",
        strength=IndicatorStrength.STRONG,  # Security risk indicator
        indicators={
            "CURLOPT_SSL_VERIFYPEER",
            "CURLOPT_SSL_VERIFYHOST",
            "verify_peer",
            "verify_host",
        },
        match_type=MatchType.SUBSTRING,
    ),
]


def _has_internal(h: dict) -> bool:
    """Check if PHP curl internal symbols were found."""
    return len(h.get("php_internal", [])) > 0


def _has_functions(h: dict) -> bool:
    """Check if enough PHP curl functions were found (minimum 2)."""
    return len(h.get("php_functions", [])) >= 2


def _has_curlopt(h: dict) -> bool:
    """Check if enough CURLOPT constants were found (minimum 2)."""
    return len(h.get("curlopt_constants", [])) >= 2


def _has_insecure(h: dict) -> bool:
    """Check if any insecure pattern was found."""
    return len(h.get("insecure_patterns", [])) > 0


# Scoring rules (evaluated in order - first match wins)
PHP_CURL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: _has_internal(h),
        rationale_template="PHP curl extension internals detected",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: _has_functions(h) and _has_curlopt(h) and _has_insecure(h),
        rationale_template="SECURITY RISK: PHP curl with insecure patterns",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: _has_functions(h) and _has_curlopt(h),
        rationale_template="PHP curl usage detected",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: _has_functions(h),
        rationale_template="PHP curl functions detected: {php_functions}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: _has_curlopt(h),
        rationale_template="CURLOPT constants found but no clear PHP curl usage",
    ),
]


PHP_CURL = LibraryDefinition(
    id="php_curl",
    name="PHP curl",
    description="PHP curl extension",
    detection_method="both",
    applicable_file_types=["php_script"],  # ONLY PHP scripts
    indicator_sets=PHP_CURL_INDICATORS,
    scoring_rules=PHP_CURL_SCORING_RULES,
)
