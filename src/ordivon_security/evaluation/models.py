from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 300:
        raise ValueError(f"{label} exceeds 300 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _digest(value: str, label: str) -> str:
    _text(value, label, prefix="sha256")
    if len(value) != 71:
        raise ValueError(f"{label} must contain a SHA-256 hex digest")
    try:
        bytes.fromhex(value.removeprefix("sha256:"))
    except ValueError as error:
        raise ValueError(f"{label} must contain lowercase hexadecimal") from error
    if value.lower() != value:
        raise ValueError(f"{label} must contain lowercase hexadecimal")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} values must be unique")
    for value in values:
        _text(value, label)


@dataclass(frozen=True, slots=True)
class SampleIdentity:
    sample_id: str
    sha256: str
    byte_length: int
    media_type: str
    original_name: str | None = None

    def __post_init__(self) -> None:
        _text(self.sample_id, "Sample identity", prefix="sample")
        _digest(self.sha256, "Sample digest")
        if self.sample_id != f"sample:{self.sha256.removeprefix('sha256:')}":
            raise ValueError("Sample identity must be derived from the Sample digest")
        if self.byte_length < 0:
            raise ValueError("Sample byte length must be non-negative")
        _text(self.media_type, "Sample media type")
        if self.original_name is not None:
            _text(self.original_name, "Sample original name")

    @classmethod
    def create(
        cls,
        *,
        sha256: str,
        byte_length: int,
        media_type: str,
        original_name: str | None = None,
    ) -> SampleIdentity:
        return cls(
            sample_id=f"sample:{sha256.removeprefix('sha256:')}",
            sha256=sha256,
            byte_length=byte_length,
            media_type=media_type,
            original_name=original_name,
        )

    def to_dict(self) -> JsonObject:
        return {
            "sampleId": self.sample_id,
            "sha256": self.sha256,
            "byteLength": self.byte_length,
            "mediaType": self.media_type,
            "originalName": self.original_name,
        }


@dataclass(frozen=True, slots=True)
class AuthorityManifest:
    authority_id: str
    revision: str
    sample_digest: str
    operator_id: str
    authorization_basis: str
    permitted_environment_ids: tuple[str, ...]
    permitted_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    max_runtime_ms: int
    allow_network: bool
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.authority_id, "Authority identity", prefix="authority")
        _text(self.revision, "Authority revision")
        _digest(self.sample_digest, "Authority Sample digest")
        _text(self.operator_id, "Operator identity", prefix="operator")
        _text(self.authorization_basis, "Authorization basis")
        _unique(self.permitted_environment_ids, "Permitted environment identity")
        _unique(self.permitted_actions, "Permitted action")
        _unique(self.prohibited_actions, "Prohibited action")
        if not self.permitted_environment_ids:
            raise ValueError("Authority must permit at least one environment")
        if set(self.permitted_actions) & set(self.prohibited_actions):
            raise ValueError("Authority action cannot be both permitted and prohibited")
        if self.max_runtime_ms < 1:
            raise ValueError("Authority max runtime must be positive")
        validate_json(self.metadata)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-authority",
            "authorityId": self.authority_id,
            "revision": self.revision,
            "sampleDigest": self.sample_digest,
            "operatorId": self.operator_id,
            "authorizationBasis": self.authorization_basis,
            "permittedEnvironmentIds": list(self.permitted_environment_ids),
            "permittedActions": list(self.permitted_actions),
            "prohibitedActions": list(self.prohibited_actions),
            "maxRuntimeMs": self.max_runtime_ms,
            "allowNetwork": self.allow_network,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class GuardianPolicy:
    policy_id: str
    revision: str
    network_mode: str
    max_runtime_ms: int
    max_memory_mib: int
    max_processes: int
    max_artifact_bytes: int
    terminate_on: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.policy_id, "Guardian policy identity", prefix="guardian-policy")
        _text(self.revision, "Guardian policy revision")
        if self.network_mode not in {"deny-all", "simulated-only"}:
            raise ValueError("Guardian network mode is unsupported")
        if (
            min(
                self.max_runtime_ms,
                self.max_memory_mib,
                self.max_processes,
                self.max_artifact_bytes,
            )
            < 1
        ):
            raise ValueError("Guardian limits must be positive")
        _unique(self.terminate_on, "Guardian termination condition")
        if not self.terminate_on:
            raise ValueError("Guardian must declare at least one termination condition")

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.guardian-policy",
            "policyId": self.policy_id,
            "revision": self.revision,
            "networkMode": self.network_mode,
            "maxRuntimeMs": self.max_runtime_ms,
            "maxMemoryMiB": self.max_memory_mib,
            "maxProcesses": self.max_processes,
            "maxArtifactBytes": self.max_artifact_bytes,
            "terminateOn": list(self.terminate_on),
        }


@dataclass(frozen=True, slots=True)
class ObservationPlan:
    plan_id: str
    revision: str
    channels: tuple[str, ...]
    capture_memory: str
    max_event_bytes: int

    def __post_init__(self) -> None:
        _text(self.plan_id, "Observation plan identity", prefix="observation-plan")
        _text(self.revision, "Observation plan revision")
        _unique(self.channels, "Observation channel")
        if not self.channels:
            raise ValueError("Observation plan must declare at least one channel")
        if self.capture_memory not in {"never", "terminal", "always"}:
            raise ValueError("Observation memory-capture policy is unsupported")
        if self.max_event_bytes < 1:
            raise ValueError("Observation event bound must be positive")

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.observation-plan",
            "planId": self.plan_id,
            "revision": self.revision,
            "channels": list(self.channels),
            "captureMemory": self.capture_memory,
            "maxEventBytes": self.max_event_bytes,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentIdentity:
    environment_id: str
    provider_id: str
    provider_revision: str
    image_digest: str
    configuration_digest: str
    guardian_policy_digest: str
    observation_plan_digest: str

    def __post_init__(self) -> None:
        _text(self.environment_id, "Environment identity", prefix="environment")
        _text(self.provider_id, "Environment provider identity", prefix="provider")
        _text(self.provider_revision, "Environment provider revision")
        _digest(self.image_digest, "Environment image digest")
        _digest(self.configuration_digest, "Environment configuration digest")
        _digest(self.guardian_policy_digest, "Environment Guardian policy digest")
        _digest(self.observation_plan_digest, "Environment Observation plan digest")

    def to_dict(self) -> JsonObject:
        return {
            "environmentId": self.environment_id,
            "providerId": self.provider_id,
            "providerRevision": self.provider_revision,
            "imageDigest": self.image_digest,
            "configurationDigest": self.configuration_digest,
            "guardianPolicyDigest": self.guardian_policy_digest,
            "observationPlanDigest": self.observation_plan_digest,
        }


@dataclass(frozen=True, slots=True)
class EvaluationSpec:
    evaluation_id: str
    revision: str
    sample: SampleIdentity
    authority: AuthorityManifest
    environment: EnvironmentIdentity
    guardian_policy: GuardianPolicy
    observation_plan: ObservationPlan
    requested_actions: tuple[str, ...]
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.evaluation_id, "Evaluation identity", prefix="evaluation")
        _text(self.revision, "Evaluation revision")
        _unique(self.requested_actions, "Requested evaluation action")
        if not self.requested_actions:
            raise ValueError("Evaluation must request at least one action")
        if self.sample.sha256 != self.authority.sample_digest:
            raise ValueError("Authority does not cover the Evaluation Sample")
        if self.environment.environment_id not in self.authority.permitted_environment_ids:
            raise ValueError("Authority does not permit the Evaluation environment")
        if self.guardian_policy.max_runtime_ms > self.authority.max_runtime_ms:
            raise ValueError("Guardian runtime exceeds the authorized runtime")
        if self.environment.guardian_policy_digest != self.guardian_policy.digest:
            raise ValueError("Environment Guardian policy binding differs")
        if self.environment.observation_plan_digest != self.observation_plan.digest:
            raise ValueError("Environment Observation plan binding differs")
        permitted = set(self.authority.permitted_actions)
        prohibited = set(self.authority.prohibited_actions)
        if not set(self.requested_actions) <= permitted:
            raise ValueError("Evaluation requests an action outside Authority")
        if set(self.requested_actions) & prohibited:
            raise ValueError("Evaluation requests a prohibited action")
        if self.guardian_policy.network_mode != "deny-all" and not self.authority.allow_network:
            raise ValueError("Authority does not permit the Guardian network mode")
        validate_json(self.metadata)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-spec",
            "evaluationId": self.evaluation_id,
            "revision": self.revision,
            "sample": self.sample.to_dict(),
            "authority": self.authority.to_dict(),
            "environment": self.environment.to_dict(),
            "guardianPolicy": self.guardian_policy.to_dict(),
            "observationPlan": self.observation_plan.to_dict(),
            "requestedActions": list(self.requested_actions),
            "metadata": self.metadata,
        }


class EvaluationDisposition(StrEnum):
    CONFIRMED_HARMFUL_BEHAVIOR = "confirmed-harmful-behavior"
    HIGH_RISK_CAPABILITY = "high-risk-capability"
    ENGINEERING_SECURITY_DEFECT = "engineering-security-defect"
    SUSPICIOUS_INCONCLUSIVE = "suspicious-inconclusive"
    NO_ISSUE_OBSERVED = "no-issue-observed"
    INVALID_TRIAL = "invalid-trial"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    behavior_class: str
    severity: str
    confidence: float
    summary: str
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.finding_id, "Finding identity", prefix="finding")
        _text(self.behavior_class, "Finding behavior class")
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("Finding severity is unsupported")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Finding confidence must be between zero and one")
        _text(self.summary, "Finding summary")
        _unique(self.evidence_refs, "Finding evidence reference")
        if not self.evidence_refs:
            raise ValueError("Finding must reference evidence")
        _unique(self.limitations, "Finding limitation")

    def to_dict(self) -> JsonObject:
        return {
            "findingId": self.finding_id,
            "behaviorClass": self.behavior_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidenceRefs": list(self.evidence_refs),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    run_id: str
    evaluation_spec_digest: str
    execution_identity_digest: str
    terminal_reason: str
    disposition: EvaluationDisposition
    findings: tuple[Finding, ...]
    residual_closed: bool
    evidence_path: str
    evidence_digest: str
    operational_evidence_digest: str

    def __post_init__(self) -> None:
        _text(self.run_id, "Evaluation Run identity", prefix="evaluation-run")
        _digest(self.evaluation_spec_digest, "Evaluation Spec digest")
        _digest(self.execution_identity_digest, "Execution identity digest")
        _text(self.terminal_reason, "Evaluation terminal reason")
        _text(self.evidence_path, "Evaluation evidence path")
        _digest(self.evidence_digest, "Evaluation evidence digest")
        _digest(self.operational_evidence_digest, "Operational evidence digest")

    def to_dict(self) -> JsonObject:
        return {
            "runId": self.run_id,
            "evaluationSpecDigest": self.evaluation_spec_digest,
            "executionIdentityDigest": self.execution_identity_digest,
            "terminalReason": self.terminal_reason,
            "disposition": self.disposition.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "residualClosed": self.residual_closed,
            "evidencePath": self.evidence_path,
            "evidenceDigest": self.evidence_digest,
            "operationalEvidenceDigest": self.operational_evidence_digest,
        }
