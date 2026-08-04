"""Stable public facade for the active Security Contest core."""

from .actors import (
    ActorBackend,
    ActorProposalFailure,
    ActorProposalFailureCode,
    SequenceActorBackend,
)
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
from .evidence import (
    EvidenceBundle,
    EvidenceRecorder,
    OperationalEvidenceEvent,
    verify_evidence_bundle,
    verify_operational_evidence,
)
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
    "ActorProposalFailure",
    "ActorProposalFailureCode",
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
    "OperationalEvidenceEvent",
    "MicroContestRange",
    "RangeBackend",
    "ScenarioManifest",
    "SequenceActorBackend",
    "verify_evidence_bundle",
    "verify_operational_evidence",
]
