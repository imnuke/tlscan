"""Generic scoring engine for library detection.

Replaces the 6 duplicated scoring functions (score_openssl, score_libcurl, etc.)
with a single data-driven implementation that works with any LibraryDefinition.
"""

import logging
from typing import Set, Dict, List

from ..models import ConfidenceLevel, DetectionResult, DetectionMethod
from .libraries.base import LibraryDefinition, IndicatorSet, MatchType

logger = logging.getLogger(__name__)


def match_indicators(
    indicator_set: IndicatorSet,
    symbols: Set[str],
    strings: Set[str],
) -> List[str]:
    """Match indicators against extracted data based on match type.

    Args:
        indicator_set: The indicator set with match type and indicators
        symbols: Extracted symbol names from the binary
        strings: Extracted printable strings from the binary

    Returns:
        List of matched indicator strings
    """
    if indicator_set.match_type == MatchType.EXACT:
        # Exact matching - typically for symbols
        return [ind for ind in indicator_set.indicators if ind in symbols]
    else:
        # Substring matching - typically for strings
        matches = []
        for ind in indicator_set.indicators:
            for s in strings:
                if ind in s:
                    matches.append(ind)
                    break
        return matches


def score_library(
    definition: LibraryDefinition,
    symbols: Set[str],
    strings: Set[str],
) -> DetectionResult:
    """Score a library detection using its definition.

    This is the single generic scoring function that replaces all 6 of the
    duplicated score_* functions. It works entirely from the LibraryDefinition
    data structure.

    Args:
        definition: The library definition with indicators and scoring rules
        symbols: Extracted symbol names from the binary
        strings: Extracted printable strings from the binary

    Returns:
        DetectionResult with confidence level, rationale, and hits
    """
    # Collect hits for all indicator categories
    hits: Dict[str, List[str]] = {}
    for ind_set in definition.indicator_sets:
        matches = match_indicators(ind_set, symbols, strings)
        hits[ind_set.name] = matches

    # Apply scoring rules in order (first match wins)
    for rule in definition.scoring_rules:
        try:
            if rule.condition(hits):
                rationale = rule.format_rationale(hits)
                logger.debug(
                    f"Library {definition.id}: {rule.confidence} confidence - {rationale}"
                )
                return DetectionResult(
                    library_id=definition.id,
                    library_name=definition.name,
                    confidence=ConfidenceLevel(rule.confidence),
                    rationale=rationale,
                    hits=hits,
                    detection_method=DetectionMethod(definition.detection_method),
                )
        except Exception as e:
            logger.debug(f"Error evaluating rule for {definition.id}: {e}")
            continue

    # No rules matched - no detection
    return DetectionResult(
        library_id=definition.id,
        library_name=definition.name,
        confidence=ConfidenceLevel.NONE,
        rationale="No sufficient indicators",
        hits=hits,
        detection_method=DetectionMethod(definition.detection_method),
    )


def score_all_libraries(
    definitions: List[LibraryDefinition],
    symbols: Set[str],
    strings: Set[str],
) -> Dict[str, DetectionResult]:
    """Score multiple libraries and return only positive detections.

    Args:
        definitions: List of library definitions to check
        symbols: Extracted symbol names from the binary
        strings: Extracted printable strings from the binary

    Returns:
        Dict mapping library_id to DetectionResult for positive detections only
    """
    results: Dict[str, DetectionResult] = {}

    for definition in definitions:
        result = score_library(definition, symbols, strings)
        if result.confidence != ConfidenceLevel.NONE:
            results[definition.id] = result
            logger.debug(
                f"Detected {definition.name} with {result.confidence.value} confidence"
            )

    return results
