"""Frozen Campaign v0 research substrate.

This package remains executable for historical reproduction. It is not the
active Security architecture and must not absorb new World, Runtime, Host,
Harness, or evaluation responsibilities.
"""

from .bindings import ComponentBinding, ResidualCheck, ResidualReport
from .bundle import (
    BundleError,
    BundleReceipt,
    EvidenceAttachment,
    export_evidence_bundle,
    verify_evidence_bundle,
)
from .campaign import (
    ContractError,
    canonical_bytes,
    digest,
    validate_campaign,
    validate_transition,
)
from .coordinator import (
    AmbiguousOperationError,
    CampaignCoordinator,
    ComponentPort,
    CoordinatorError,
    LifecycleRun,
    ObserverUnavailableError,
    OperationResult,
)
from .ledger import (
    CampaignEvent,
    CampaignLedger,
    CampaignProjection,
    LedgerConflict,
    LedgerCorrupt,
    LedgerError,
    replay_campaign,
)

__all__ = [
    "AmbiguousOperationError",
    "BundleError",
    "BundleReceipt",
    "CampaignCoordinator",
    "CampaignEvent",
    "CampaignLedger",
    "CampaignProjection",
    "ComponentBinding",
    "ComponentPort",
    "ContractError",
    "CoordinatorError",
    "EvidenceAttachment",
    "LedgerConflict",
    "LedgerCorrupt",
    "LedgerError",
    "LifecycleRun",
    "ObserverUnavailableError",
    "OperationResult",
    "ResidualCheck",
    "ResidualReport",
    "canonical_bytes",
    "digest",
    "export_evidence_bundle",
    "replay_campaign",
    "validate_campaign",
    "validate_transition",
    "verify_evidence_bundle",
]
