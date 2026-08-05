from __future__ import annotations

import hashlib
import os
import shutil
import time
from dataclasses import replace
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.identity import security_source_identity

from .backend import (
    EvaluationArtifact,
    EvaluationInstance,
    EvaluationRangeBackend,
    ObserverRecord,
    ResidualClosureReceipt,
)
from .evidence import EvaluationEvidenceChannel, EvaluationEvidenceRecorder
from .findings import choose_disposition, derive_findings
from .models import EvaluationResult, EvaluationSpec
from .vault import SampleVault

EVALUATION_EVIDENCE_SCHEMA_REVISION = "2"


class EvaluationRunner:
    """Run one authorized evaluation through a replaceable external Range backend."""

    def __init__(
        self,
        backend: EvaluationRangeBackend,
        vault: SampleVault,
        *,
        evidence_root: Path,
    ) -> None:
        self.backend = backend
        self.vault = vault
        self.evidence_root = evidence_root

    @staticmethod
    def _wall_ms() -> int:
        return time.time_ns() // 1_000_000

    @staticmethod
    def _mono_ms() -> int:
        return time.monotonic_ns() // 1_000_000

    def execution_identity(self, spec: EvaluationSpec) -> JsonObject:
        identity: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-execution-identity",
            "security": security_source_identity(),
            "evidenceSchemaRevision": EVALUATION_EVIDENCE_SCHEMA_REVISION,
            "backend": self.backend.execution_identity,
            "sampleVault": self.vault.execution_identity,
            "environment": spec.environment.to_dict(),
            "guardianPolicyDigest": spec.guardian_policy.digest,
            "observationPlanDigest": spec.observation_plan.digest,
        }
        validate_json(identity)
        return identity

    def _record_duration(
        self,
        recorder: EvaluationEvidenceRecorder,
        *,
        source_id: str,
        event_type: str,
        started_ms: int,
        payload: JsonObject,
    ) -> None:
        recorder.append_operational(
            recorded_at_ms=self._wall_ms(),
            source_id=source_id,
            event_type=event_type,
            payload={**payload, "durationMs": max(0, self._mono_ms() - started_ms)},
        )

    def _stage_artifacts(
        self,
        artifacts: tuple[EvaluationArtifact, ...],
        *,
        run_id: str,
        max_artifact_bytes: int,
    ) -> tuple[tuple[EvaluationArtifact, ...], Path | None]:
        if not artifacts:
            return (), None
        artifact_ids = tuple(artifact.artifact_id for artifact in artifacts)
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("Evaluation Artifact identities must be unique")
        staging_root = (
            self.evidence_root / ".artifact-staging" / run_id.removeprefix("evaluation-run:")
        )
        if staging_root.exists():
            raise FileExistsError(
                f"Evaluation Artifact staging path already exists: {staging_root}"
            )
        staging_root.mkdir(parents=True)
        staging_root.chmod(0o700)
        staged: list[EvaluationArtifact] = []
        total_bytes = 0
        try:
            for index, artifact in enumerate(artifacts):
                source = artifact.source_path
                if source is None or not source.is_file() or source.is_symlink():
                    raise ValueError("Evaluation Artifact source is missing or unsafe")
                partial = staging_root / f"{index:03d}.partial"
                destination = staging_root / f"{index:03d}.bin"
                digest = hashlib.sha256()
                byte_length = 0
                with source.open("rb") as source_handle, partial.open("xb") as target_handle:
                    partial.chmod(0o600)
                    while chunk := source_handle.read(4 * 1024 * 1024):
                        byte_length += len(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > max_artifact_bytes:
                            raise ValueError("Evaluation Artifacts exceed the Guardian byte bound")
                        digest.update(chunk)
                        target_handle.write(chunk)
                    target_handle.flush()
                    os.fsync(target_handle.fileno())
                actual_digest = "sha256:" + digest.hexdigest()
                if actual_digest != artifact.digest or byte_length != artifact.byte_length:
                    raise ValueError("Evaluation Artifact source differs from declared identity")
                os.replace(partial, destination)
                staged.append(replace(artifact, source_path=destination))
            return tuple(staged), staging_root
        except BaseException:
            shutil.rmtree(staging_root, ignore_errors=True)
            raise

    def run(self, spec: EvaluationSpec, *, run_index: int = 0) -> EvaluationResult:
        if run_index < 0:
            raise ValueError("Evaluation run index must be non-negative")
        execution_identity = self.execution_identity(spec)
        execution_identity_digest = canonical_digest(execution_identity)
        run_digest = canonical_digest(
            {
                "evaluationSpecDigest": spec.digest,
                "executionIdentityDigest": execution_identity_digest,
                "runIndex": run_index,
            }
        )
        run_id = f"evaluation-run:{run_digest.removeprefix('sha256:')[:24]}"
        recorder = EvaluationEvidenceRecorder(run_id)
        recorder.append_operational(
            recorded_at_ms=self._wall_ms(),
            source_id="evaluation-runner",
            event_type="evaluation.invocation-started",
            payload={
                "evaluationSpecDigest": spec.digest,
                "executionIdentityDigest": execution_identity_digest,
                "runIndex": run_index,
            },
        )

        logical_time = 0
        terminal_reason = "invalid-trial"
        valid_trial = False
        guardian_terminated = False
        residual_receipt = ResidualClosureReceipt(clean=True, details={"reason": "not-created"})
        instance: EvaluationInstance | None = None
        observed_with_refs: list[tuple[ObserverRecord, str]] = []
        raw_metrics: JsonObject = {}
        artifacts: tuple[EvaluationArtifact, ...] = ()
        artifact_staging_root: Path | None = None

        try:
            if spec.environment.provider_id != self.backend.provider_id:
                raise ValueError("Evaluation environment Provider differs from backend")
            sample_path = self.vault.resolve(spec.sample)
            recorder.append(
                EvaluationEvidenceChannel.SAMPLE,
                logical_time=logical_time,
                source_id="sample-vault",
                event_type="sample.admitted",
                payload={
                    "sample": spec.sample.to_dict(),
                    "authorityId": spec.authority.authority_id,
                    "authorityDigest": spec.authority.digest,
                },
            )
            recorder.append(
                EvaluationEvidenceChannel.MANAGEMENT,
                logical_time=logical_time,
                source_id="evaluation-runner",
                event_type="evaluation.admitted",
                payload={
                    "evaluationSpecDigest": spec.digest,
                    "requestedActions": list(spec.requested_actions),
                    "networkMode": spec.guardian_policy.network_mode,
                },
            )

            started = self._mono_ms()
            instance = self.backend.create(run_id, spec)
            self._record_duration(
                recorder,
                source_id=self.backend.backend_id,
                event_type="evaluation.create-completed",
                started_ms=started,
                payload={"instanceId": instance.instance_id, "generation": instance.generation},
            )
            logical_time += 1
            recorder.append(
                EvaluationEvidenceChannel.MANAGEMENT,
                logical_time=logical_time,
                source_id=self.backend.backend_id,
                event_type="environment.created",
                payload={"instanceId": instance.instance_id, "generation": instance.generation},
            )

            started = self._mono_ms()
            stage_receipt = self.backend.stage(instance, sample_path, spec.sample)
            self._record_duration(
                recorder,
                source_id=self.backend.backend_id,
                event_type="evaluation.stage-completed",
                started_ms=started,
                payload={"instanceId": instance.instance_id},
            )
            logical_time += 1
            recorder.append(
                EvaluationEvidenceChannel.MANAGEMENT,
                logical_time=logical_time,
                source_id=self.backend.backend_id,
                event_type="sample.staged",
                payload=stage_receipt,
            )

            started = self._mono_ms()
            execution = self.backend.execute(instance, spec)
            self._record_duration(
                recorder,
                source_id=self.backend.backend_id,
                event_type="evaluation.execute-completed",
                started_ms=started,
                payload={"terminalReason": execution.terminal_reason},
            )
            terminal_reason = execution.terminal_reason
            logical_time += 1
            for record in execution.observer_records:
                if len(canonical_bytes(record.to_dict())) > spec.observation_plan.max_event_bytes:
                    raise ValueError("Observer record exceeds the admitted event bound")
                event = recorder.append(
                    EvaluationEvidenceChannel.OBSERVER,
                    logical_time=logical_time,
                    source_id=record.channel,
                    event_type=record.event_type,
                    payload=record.payload,
                )
                observed_with_refs.append((record, event.event_id))
            for guardian_record in execution.guardian_records:
                if (
                    len(canonical_bytes(guardian_record.to_dict()))
                    > spec.observation_plan.max_event_bytes
                ):
                    raise ValueError("Guardian record exceeds the admitted event bound")
                recorder.append(
                    EvaluationEvidenceChannel.GUARDIAN,
                    logical_time=logical_time,
                    source_id="guardian",
                    event_type=f"guardian.{guardian_record.decision}",
                    payload=guardian_record.to_dict(),
                )
                if guardian_record.decision == "terminate":
                    guardian_terminated = True
            recorder.append(
                EvaluationEvidenceChannel.TRUTH,
                logical_time=logical_time,
                source_id=self.backend.backend_id,
                event_type="evaluation.world-facts",
                payload=execution.world_facts,
            )
            artifacts, artifact_staging_root = self._stage_artifacts(
                execution.artifacts,
                run_id=run_id,
                max_artifact_bytes=spec.guardian_policy.max_artifact_bytes,
            )
            raw_metrics = {
                **execution.raw_metrics,
                "evaluation.guardian_terminated": guardian_terminated,
                "evaluation.observer_event_count": len(execution.observer_records),
                "evaluation.artifact_count": len(artifacts),
                "evaluation.artifact_bytes": sum(artifact.byte_length for artifact in artifacts),
            }
            valid_trial = True
        except Exception as error:
            terminal_reason = f"backend-or-admission-failure:{type(error).__name__}"
            recorder.append(
                EvaluationEvidenceChannel.MANAGEMENT,
                logical_time=logical_time + 1,
                source_id="evaluation-runner",
                event_type="evaluation.failed",
                payload={"terminalReason": terminal_reason, "errorType": type(error).__name__},
            )
            recorder.append_operational(
                recorded_at_ms=self._wall_ms(),
                source_id="evaluation-runner",
                event_type="evaluation.exception-observed",
                payload={"errorType": type(error).__name__},
            )
        finally:
            if instance is not None:
                started = self._mono_ms()
                try:
                    residual_receipt = self.backend.destroy(instance)
                except Exception as error:
                    residual_receipt = ResidualClosureReceipt(
                        clean=False,
                        details={"errorType": type(error).__name__},
                    )
                    terminal_reason = f"residual-closure-failure:{type(error).__name__}"
                    valid_trial = False
                self._record_duration(
                    recorder,
                    source_id=self.backend.backend_id,
                    event_type="evaluation.destroy-completed",
                    started_ms=started,
                    payload={"clean": residual_receipt.clean},
                )
            logical_time += 2
            recorder.append(
                EvaluationEvidenceChannel.MANAGEMENT,
                logical_time=logical_time,
                source_id=self.backend.backend_id,
                event_type="environment.residual-closure",
                payload=residual_receipt.to_dict(),
            )
            if not residual_receipt.clean:
                valid_trial = False
                if not terminal_reason.startswith("residual-closure-failure"):
                    terminal_reason = "residual-closure-incomplete"

        findings = derive_findings(tuple(observed_with_refs))
        disposition = choose_disposition(
            findings=findings,
            terminal_reason=terminal_reason,
            guardian_terminated=guardian_terminated,
            valid_trial=valid_trial,
        )
        result_payload: JsonObject = {
            "runId": run_id,
            "evaluationSpecDigest": spec.digest,
            "executionIdentityDigest": execution_identity_digest,
            "terminalReason": terminal_reason,
            "disposition": disposition.value,
            "residualClosed": residual_receipt.clean,
            "rawMetrics": raw_metrics,
            "artifacts": [artifact.to_dict() for artifact in artifacts],
        }
        findings_payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.evaluation-findings",
            "runId": run_id,
            "findings": [finding.to_dict() for finding in findings],
        }
        recorder.append(
            EvaluationEvidenceChannel.MANAGEMENT,
            logical_time=logical_time + 1,
            source_id="evaluation-runner",
            event_type="evaluation.stopped",
            payload=result_payload,
        )
        recorder.append_operational(
            recorded_at_ms=self._wall_ms(),
            source_id="evaluation-runner",
            event_type="evaluation.invocation-completed",
            payload={"terminalReason": terminal_reason, "disposition": disposition.value},
        )
        output_path = self.evidence_root / run_id.removeprefix("evaluation-run:")
        try:
            bundle = recorder.seal(
                output_path,
                evaluation_spec=spec.to_dict(),
                execution_identity=execution_identity,
                findings=findings_payload,
                result=result_payload,
                artifacts=artifacts,
            )
        finally:
            if artifact_staging_root is not None:
                shutil.rmtree(artifact_staging_root, ignore_errors=True)
                parent = artifact_staging_root.parent
                if parent.exists() and not any(parent.iterdir()):
                    parent.rmdir()
        return EvaluationResult(
            run_id=run_id,
            evaluation_spec_digest=spec.digest,
            execution_identity_digest=execution_identity_digest,
            terminal_reason=terminal_reason,
            disposition=disposition,
            findings=findings,
            residual_closed=residual_receipt.clean,
            evidence_path=str(output_path),
            evidence_digest=bundle.digest,
            operational_evidence_digest=bundle.operational_digest,
        )
