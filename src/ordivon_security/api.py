"""Stable public facade for the active Security Contest core."""

from .actors import ActorBackend, SequenceActorBackend
from .contest import (
    ActionAdmission,
    ActionProposal,
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ContestResult,
    ScenarioManifest,
)
from .contest.runner import ContestRunner
from .evidence import EvidenceBundle, EvidenceRecorder, verify_evidence_bundle
from .ranges import (
    CAGE4_NATIVE_PLAN,
    CAGE4_PLANS,
    CAGE4_RANGE_ID,
    CAGE4_REVISION,
    CAGE4_SLEEP_PLAN,
    Cage4RangeBackend,
    Cage4RangeConfig,
    MicroContestRange,
    RangeBackend,
)

__all__ = [
    "ActionAdmission",
    "ActionProposal",
    "ActorActionResult",
    "ActorBackend",
    "ActorBinding",
    "ActorObservation",
    "CAGE4_NATIVE_PLAN",
    "CAGE4_PLANS",
    "CAGE4_RANGE_ID",
    "CAGE4_REVISION",
    "CAGE4_SLEEP_PLAN",
    "Cage4RangeBackend",
    "Cage4RangeConfig",
    "ContestResult",
    "ContestRunner",
    "EvidenceBundle",
    "EvidenceRecorder",
    "MicroContestRange",
    "RangeBackend",
    "ScenarioManifest",
    "SequenceActorBackend",
    "verify_evidence_bundle",
]
