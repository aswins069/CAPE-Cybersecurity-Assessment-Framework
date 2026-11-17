"""CAPE Pillar A — Explainability Engine.

Reconstructs, in full, why an Opportunity received the score and
severity it did: which rule conditions matched on which evidence, and
every factor in the scoring formula with its provenance.
"""
from cape.show.explain.trace_models import (
    ConditionTrace,
    FindingTrace,
    OpportunityTrace,
    ScoreComponent,
)
from cape.show.explain.tracing_evaluator import TracingEvaluator
from cape.show.explain.ai_narrator import (
    ai_narration_available,
    narrate,
    narrate_stream,
)

__all__ = [
    "ConditionTrace",
    "FindingTrace",
    "OpportunityTrace",
    "ScoreComponent",
    "TracingEvaluator",
    "ai_narration_available",
    "narrate",
    "narrate_stream",
]
