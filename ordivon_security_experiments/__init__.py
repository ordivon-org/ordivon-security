"""Minimal, deletable experiment layer for Agent-native adversarial research."""

from .models import (
    ActorIdentity,
    Decision,
    EvaluationIdentity,
    ExperimentSpec,
    FamilySummary,
    Observation,
    TrialOutcome,
    TrialResult,
    WorldIdentity,
)
from .runner import run_family, run_trial

__all__ = [
    "ActorIdentity",
    "Decision",
    "EvaluationIdentity",
    "ExperimentSpec",
    "FamilySummary",
    "Observation",
    "TrialOutcome",
    "TrialResult",
    "WorldIdentity",
    "run_family",
    "run_trial",
]
