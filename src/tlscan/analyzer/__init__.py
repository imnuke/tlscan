"""
Core analyzer module for SSL/TLS security analysis.

Provides multi-agent LLM-based analysis of binary files for SSL/TLS
security configuration issues.
"""

from tlscan.analyzer.main import main as analyze
from tlscan.analyzer.workflow import (
    AnalysisState,
    AnalysisPhase,
    create_initial_state,
)

__all__ = [
    "analyze",
    "AnalysisState",
    "AnalysisPhase",
    "create_initial_state",
]
