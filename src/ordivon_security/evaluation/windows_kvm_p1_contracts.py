from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_digest

_REQUIRED_SNAPSHOT_DOMAINS = frozenset(
    {
        "files",
        "registry",
        "services",
        "drivers",
        "scheduled-tasks",
        "bits-jobs",
        "startup-entries",
        "installed-products",
        "users-groups",
        "certificates",
        "defender",
        "event-logs",
    }
)
_REQUIRED_EVENT_CHANNELS = frozenset(
    {
        "process-tree",
        "powershell-script-block",
        "service-control-manager",
        "task-scheduler",
        "windows-installer",
        "defender",
        "qmp-topology",
        "host-media-identity",
        "residual-closure",
    }
)


def _digest(value: str, label: str) -> str:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"Windows KVM P1 {label} digest is invalid")
    bytes.fromhex(value.removeprefix("sha256:"))
    if value.lower() != value:
        raise ValueError(f"Windows KVM P1 {label} digest must be lowercase")
    return value


@dataclass(frozen=True, slots=True)
class WindowsKvmInstallerStaticDecision:
    decision_id: str
    revision: str
    case_id: str
    outcome: str
    execution_authorized: bool
    chain_complete: bool
    identities: JsonObject
    reasons: tuple[str, ...]
    unresolved_questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.decision_id.startswith("decision:")
            or not self.case_id.startswith("case:")
            or not self.revision
        ):
            raise ValueError("Windows KVM P1 static decision identity is invalid")
        for key in (
            "archive",
            "wrapper",
            "outerMsi",
            "nestedMsi",
            "downloaderScript",
            "crackDll",
            "mainExecutable",
        ):
            value = self.identities.get(key)
            if not isinstance(value, str):
                raise ValueError(f"Windows KVM P1 static identity is missing: {key}")
            _digest(value, key)
        if self.outcome not in {
            "reject-execution-profile",
            "candidate-for-isolated-observation",
        }:
            raise ValueError("Windows KVM P1 static decision outcome is unsupported")
        if self.execution_authorized:
            raise ValueError("Static P1 evidence cannot authorize installer execution")
        if not self.reasons or any(not value for value in self.reasons):
            raise ValueError("Windows KVM P1 static decision must state reasons")
        if any(not value for value in self.unresolved_questions):
            raise ValueError("Windows KVM P1 unresolved questions must be non-empty")

    @classmethod
    def from_dict(cls, value: JsonObject) -> WindowsKvmInstallerStaticDecision:
        if (
            value.get("schemaVersion") != 1
            or value.get("kind") != "ordivon.security.windows-kvm-installer-static-decision"
        ):
            raise ValueError("Windows KVM P1 static decision schema is unsupported")
        identities = value.get("identities")
        reasons = value.get("reasons")
        unresolved = value.get("unresolvedQuestions", [])
        if not isinstance(identities, dict):
            raise ValueError("Windows KVM P1 static identities are missing")
        if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
            raise ValueError("Windows KVM P1 static reasons are invalid")
        if not isinstance(unresolved, list) or not all(
            isinstance(item, str) for item in unresolved
        ):
            raise ValueError("Windows KVM P1 unresolved questions are invalid")
        return cls(
            decision_id=str(value.get("decisionId", "")),
            revision=str(value.get("revision", "")),
            case_id=str(value.get("caseId", "")),
            outcome=str(value.get("outcome", "")),
            execution_authorized=value.get("executionAuthorized") is True,
            chain_complete=value.get("chainComplete") is True,
            identities=identities,
            reasons=tuple(cast(list[str], reasons)),
            unresolved_questions=tuple(cast(list[str], unresolved)),
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-installer-static-decision",
            "decisionId": self.decision_id,
            "revision": self.revision,
            "caseId": self.case_id,
            "outcome": self.outcome,
            "executionAuthorized": self.execution_authorized,
            "chainComplete": self.chain_complete,
            "identities": self.identities,
            "reasons": list(self.reasons),
            "unresolvedQuestions": list(self.unresolved_questions),
        }


@dataclass(frozen=True, slots=True)
class WindowsKvmInstallerObservationProfile:
    profile_id: str
    revision: str
    snapshot_domains: tuple[str, ...]
    event_channels: tuple[str, ...]
    network_mode: str
    capture_memory: str
    invariants: JsonObject

    def __post_init__(self) -> None:
        if not self.profile_id.startswith("observation-profile:") or not self.revision:
            raise ValueError("Windows KVM P1 observation profile identity is invalid")
        if self.network_mode != "deny-all":
            raise ValueError("Windows KVM P1 observation requires deny-all network")
        if self.capture_memory not in {"never", "terminal"}:
            raise ValueError("Windows KVM P1 memory capture policy is unsupported")
        if len(self.snapshot_domains) != len(set(self.snapshot_domains)) or len(
            self.event_channels
        ) != len(set(self.event_channels)):
            raise ValueError("Windows KVM P1 observation entries must be unique")
        missing_domains = _REQUIRED_SNAPSHOT_DOMAINS - set(self.snapshot_domains)
        missing_channels = _REQUIRED_EVENT_CHANNELS - set(self.event_channels)
        if missing_domains:
            raise ValueError(
                f"Windows KVM P1 snapshot domains are incomplete: {sorted(missing_domains)}"
            )
        if missing_channels:
            raise ValueError(
                f"Windows KVM P1 event channels are incomplete: {sorted(missing_channels)}"
            )
        for key in ("processTree", "qmpNoNetworkAuthority", "prePostDiff", "residualClosure"):
            if self.invariants.get(key) is not True:
                raise ValueError(f"Windows KVM P1 observation invariant is required: {key}")

    @classmethod
    def from_dict(cls, value: JsonObject) -> WindowsKvmInstallerObservationProfile:
        if (
            value.get("schemaVersion") != 1
            or value.get("kind") != "ordivon.security.windows-kvm-installer-observation-profile"
        ):
            raise ValueError("Windows KVM P1 observation profile schema is unsupported")
        domains = value.get("snapshotDomains")
        channels = value.get("eventChannels")
        invariants = value.get("invariants")
        if not isinstance(domains, list) or not all(isinstance(item, str) for item in domains):
            raise ValueError("Windows KVM P1 snapshot domains are invalid")
        if not isinstance(channels, list) or not all(isinstance(item, str) for item in channels):
            raise ValueError("Windows KVM P1 event channels are invalid")
        if not isinstance(invariants, dict):
            raise ValueError("Windows KVM P1 observation invariants are missing")
        return cls(
            profile_id=str(value.get("profileId", "")),
            revision=str(value.get("revision", "")),
            snapshot_domains=tuple(cast(list[str], domains)),
            event_channels=tuple(cast(list[str], channels)),
            network_mode=str(value.get("networkMode", "")),
            capture_memory=str(value.get("captureMemory", "")),
            invariants=invariants,
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-installer-observation-profile",
            "profileId": self.profile_id,
            "revision": self.revision,
            "snapshotDomains": list(self.snapshot_domains),
            "eventChannels": list(self.event_channels),
            "networkMode": self.network_mode,
            "captureMemory": self.capture_memory,
            "invariants": self.invariants,
        }
