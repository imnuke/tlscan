"""libcurl library definition."""

from .base import (
    LibraryDefinition,
    IndicatorSet,
    IndicatorStrength,
    ScoringRule,
    MatchType,
)

# Indicator sets for libcurl client detection
LIBCURL_INDICATORS = [
    IndicatorSet(
        name="strong",
        strength=IndicatorStrength.STRONG,
        indicators={
            "curl_easy_perform",
            "curl_multi_perform",
            "curl_easy_send",
            "curl_easy_recv",
        },
    ),
    IndicatorSet(
        name="init",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_init",
            "curl_multi_init",
            "curl_global_init",
        },
    ),
    IndicatorSet(
        name="setopt",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_setopt",
            "curl_multi_setopt",
            "curl_easy_setopt_array",
        },
    ),
    IndicatorSet(
        name="info",
        strength=IndicatorStrength.MEDIUM,
        indicators={
            "curl_easy_getinfo",
            "curl_multi_info_read",
        },
    ),
    IndicatorSet(
        name="weak",
        strength=IndicatorStrength.WEAK,
        indicators={
            "curl_easy_cleanup",
            "curl_multi_cleanup",
            "curl_global_cleanup",
            "curl_slist_append",
            "curl_slist_free_all",
            "curl_easy_strerror",
            "curl_multi_strerror",
            "curl_version",
            "curl_version_info",
            "curl_easy_escape",
            "curl_easy_unescape",
            "curl_free",
        },
    ),
]


# Scoring rules (evaluated in order - first match wins)
LIBCURL_SCORING_RULES = [
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("strong", [])) > 0,
        rationale_template="Found strong client transfer function(s): {strong}",
    ),
    ScoringRule(
        confidence="high",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("setopt", [])) > 0,
        rationale_template="Client setup pattern: init + setopt",
    ),
    ScoringRule(
        confidence="medium",
        condition=lambda h: len(h.get("init", [])) > 0 and len(h.get("info", [])) > 0,
        rationale_template="Client info retrieval pattern: init + info",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("init", [])) > 0,
        rationale_template="Only initialization found: {init}",
    ),
    ScoringRule(
        confidence="low",
        condition=lambda h: len(h.get("weak", [])) >= 3,  # Default threshold
        rationale_template="Multiple weak libcurl indicators",
    ),
]


LIBCURL = LibraryDefinition(
    id="libcurl",
    name="libcurl",
    description="libcurl HTTP/HTTPS client library",
    detection_method="symbols",
    applicable_file_types=["elf_binary"],
    indicator_sets=LIBCURL_INDICATORS,
    scoring_rules=LIBCURL_SCORING_RULES,
)
