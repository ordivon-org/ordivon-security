"""Minimal, deletable experiment layer for Agent-native adversarial research."""

from .models import (
    ActorIdentity,
    Decision,
    EvaluationIdentity,
    ExperimentSpec,
    FamilySummary,
    HiddenEvaluationRecord,
    Observation,
    TrialOutcome,
    TrialResult,
    WorldIdentity,
)
from .evidence import verify_trial_evidence
from .runner import run_family, run_trial

__all__ = [
    "ActorIdentity",
    "Decision",
    "EvaluationIdentity",
    "ExperimentSpec",
    "FamilySummary",
    "HiddenEvaluationRecord",
    "Observation",
    "TrialOutcome",
    "TrialResult",
    "WorldIdentity",
    "run_family",
    "verify_trial_evidence",
    "run_trial",
]
