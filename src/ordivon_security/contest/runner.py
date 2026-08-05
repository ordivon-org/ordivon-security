from __future__ import annotations

import time
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.protocol import (
    ActorBackend,
    ActorProposalFailure,
    ActorSession,
)
from ordivon_security.evidence.events import EvidenceChannel
from ordivon_security.evidence.recorder import EvidenceRecorder
from ordivon_security.identity import build_trial_identity, trial_identity_digest
from ordivon_security.ranges.protocol import RangeBackend

from .model import ActionAdmission, ActorActionResult, ContestResult, ScenarioManifest


class ContestRunner:
    """Execute simultaneous multi-Actor ticks against one authoritative Range."""

    def __init__(
        self,
        range_backend: RangeBackend,
        actor_backends: dict[str, ActorBackend],
        *,
        evidence_root: Path,
    ) -> None:
        if evidence_root.is_symlink():
            raise ValueError("Contest evidence root must not be a symbolic link")
        if evidence_root.exists() and not evidence_root.is_dir():
            raise ValueError("Contest evidence root must be a directory")
        evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        evidence_root.chmod(0o700)
        self.range_backend = range_backend
        self.actor_backends = dict(actor_backends)
        self.evidence_root = evidence_root

    @staticmethod
    def _wall_ms() -> int:
        return time.time_ns() // 1_000_000

    @staticmethod
    def _mono_ms() -> int:
        return time.monotonic_ns() // 1_000_000

    def _record_duration(
        self,
        recorder: EvidenceRecorder,
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

    def run(self, manifest: ScenarioManifest, *, seed: int) -> ContestResult:
        if seed < 0:
            raise ValueError("Contest seed must be non-negative")
        if manifest.range_id != self.range_backend.range_id:
            raise ValueError("Scenario Range identity differs from backend")
        expected_ids = {actor.actor_id for actor in manifest.actors}
        if set(self.actor_backends) != expected_ids:
            raise ValueError("Actor backend set differs from Scenario actors")

        identity = build_trial_identity(
            range_identity=self.range_backend.execution_identity,
            actor_identities=tuple(
                (binding.actor_id, self.actor_backends[binding.actor_id].execution_identity)
                for binding in manifest.actors
            ),
        )
        identity_digest = trial_identity_digest(identity)
        trial_hash = canonical_digest(
            {
                "scenarioDigest": manifest.digest,
                "trialIdentityDigest": identity_digest,
                "seed": seed,
            }
        )
        trial_id = f"trial:{trial_hash.removeprefix('sha256:')[:24]}"
        recorder = EvidenceRecorder(trial_id)
        recorder.append_operational(
            recorded_at_ms=self._wall_ms(),
            source_id="contest-runner",
            event_type="contest.invocation-started",
            payload={
                "scenarioDigest": manifest.digest,
                "trialIdentityDigest": identity_digest,
            },
        )

        create_started = self._mono_ms()
        instance = self.range_backend.create(trial_id, manifest, seed)
        self._record_duration(
            recorder,
            source_id=self.range_backend.range_id,
            event_type="range.create-completed",
            started_ms=create_started,
            payload={},
        )
        destroyed = False
        sessions: dict[str, ActorSession] = {}
        terminal_reason = "max-ticks-reached"
        ticks_executed = 0
        ticks_attempted = 0
        actor_failure_count = 0
        recorder.append(
            EvidenceChannel.MANAGEMENT,
            logical_time=0,
            source_id="contest-runner",
            event_type="contest.started",
            payload={
                "scenarioDigest": manifest.digest,
                "trialIdentityDigest": identity_digest,
                "seed": seed,
            },
        )
        recorder.append(
            EvidenceChannel.TRUTH,
            logical_time=0,
            source_id=self.range_backend.range_id,
            event_type="world.initial",
            payload=self.range_backend.truth(instance).to_dict(),
        )
        try:
            for binding in manifest.actors:
                backend = self.actor_backends[binding.actor_id]
                if backend.backend_id != binding.backend_id:
                    raise ValueError(f"backend identity differs for {binding.actor_id}")
                if backend.configuration_digest != binding.backend_config_digest:
                    raise ValueError(f"backend configuration differs for {binding.actor_id}")
                started = self._mono_ms()
                session = backend.start(binding, manifest)
                self._record_duration(
                    recorder,
                    source_id=binding.actor_id,
                    event_type="actor.start-completed",
                    started_ms=started,
                    payload={"backendId": backend.backend_id},
                )
                sessions[binding.actor_id] = session
                recorder.append(
                    EvidenceChannel.MANAGEMENT,
                    logical_time=0,
                    source_id=binding.actor_id,
                    event_type="actor.started",
                    payload={"backendId": backend.backend_id, "sessionId": session.session_id},
                )

            for tick in range(manifest.max_ticks):
                ticks_attempted = tick + 1
                proposals = []
                failures: list[tuple[str, ActorProposalFailure]] = []
                for binding in manifest.actors:
                    observation = self.range_backend.observe(instance, binding.actor_id)
                    recorder.append(
                        EvidenceChannel.ACTOR,
                        logical_time=tick,
                        source_id=binding.actor_id,
                        event_type="actor.observation",
                        payload=observation.to_dict(),
                    )
                    started = self._mono_ms()
                    try:
                        proposal = self.actor_backends[binding.actor_id].propose(
                            sessions[binding.actor_id], observation
                        )
                    except ActorProposalFailure as error:
                        actor_failure_count += 1
                        failures.append((binding.actor_id, error))
                        self._record_duration(
                            recorder,
                            source_id=binding.actor_id,
                            event_type="actor.proposal-failed",
                            started_ms=started,
                            payload={"code": error.code.value, "details": error.details},
                        )
                        recorder.append(
                            EvidenceChannel.ACTOR,
                            logical_time=tick,
                            source_id=binding.actor_id,
                            event_type="actor.proposal-failed",
                            payload={
                                "actorId": binding.actor_id,
                                "tick": tick,
                                "code": error.code.value,
                                "details": error.details,
                            },
                        )
                        continue
                    self._record_duration(
                        recorder,
                        source_id=binding.actor_id,
                        event_type="actor.proposal-completed",
                        started_ms=started,
                        payload={"proposalId": proposal.proposal_id},
                    )
                    if proposal.actor_id != binding.actor_id or proposal.tick != tick:
                        raise ValueError("Actor proposal identity or tick drifted")
                    proposals.append(proposal)
                    recorder.append(
                        EvidenceChannel.ACTOR,
                        logical_time=tick,
                        source_id=binding.actor_id,
                        event_type="actor.proposal",
                        payload=proposal.to_dict(),
                    )
                if len({proposal.proposal_id for proposal in proposals}) != len(proposals):
                    raise ValueError("Actor proposal identities must be unique")

                if failures:
                    first_actor, first_failure = failures[0]
                    terminal_reason = f"actor-failure:{first_failure.code.value}"
                    results = tuple(
                        ActorActionResult(
                            proposal.proposal_id,
                            proposal.actor_id,
                            tick,
                            "not-executed",
                            observation={
                                "reason": "contest-invalidated-by-actor-failure",
                                "failedActorId": first_actor,
                            },
                        )
                        for proposal in proposals
                    )
                    self._record_results(recorder, sessions, results, logical_time=tick + 1)
                    recorder.append(
                        EvidenceChannel.MANAGEMENT,
                        logical_time=tick + 1,
                        source_id="contest-runner",
                        event_type="contest.invalidated",
                        payload={
                            "reason": terminal_reason,
                            "failedActors": [
                                {"actorId": actor_id, "code": error.code.value}
                                for actor_id, error in failures
                            ],
                            "worldAdvanced": False,
                        },
                    )
                    recorder.append(
                        EvidenceChannel.TRUTH,
                        logical_time=tick + 1,
                        source_id=self.range_backend.range_id,
                        event_type="world.unchanged",
                        payload=self.range_backend.truth(instance).to_dict(),
                    )
                    break

                admissions: list[ActionAdmission] = []
                rejected_results: list[ActorActionResult] = []
                for proposal in proposals:
                    started = self._mono_ms()
                    admission = self.range_backend.admit(instance, proposal)
                    self._record_duration(
                        recorder,
                        source_id=self.range_backend.range_id,
                        event_type="action.admission-completed",
                        started_ms=started,
                        payload={
                            "proposalId": proposal.proposal_id,
                            "admitted": admission.admitted,
                            "reason": admission.reason,
                        },
                    )
                    admissions.append(admission)
                    recorder.append(
                        EvidenceChannel.MANAGEMENT,
                        logical_time=tick,
                        source_id="contest-runner",
                        event_type="action.admitted" if admission.admitted else "action.rejected",
                        payload=admission.to_dict(),
                    )
                    if not admission.admitted:
                        rejected_results.append(
                            ActorActionResult(
                                proposal.proposal_id,
                                proposal.actor_id,
                                tick,
                                "rejected",
                                observation={"reason": admission.reason},
                            )
                        )

                if rejected_results:
                    terminal_reason = "invalid-action"
                    not_executed = tuple(
                        ActorActionResult(
                            admission.proposal.proposal_id,
                            admission.proposal.actor_id,
                            tick,
                            "not-executed",
                            observation={"reason": "peer-action-rejected"},
                        )
                        for admission in admissions
                        if admission.admitted
                    )
                    results = tuple(
                        sorted((*rejected_results, *not_executed), key=lambda item: item.actor_id)
                    )
                    self._record_results(recorder, sessions, results, logical_time=tick + 1)
                    recorder.append(
                        EvidenceChannel.MANAGEMENT,
                        logical_time=tick + 1,
                        source_id="contest-runner",
                        event_type="contest.invalidated",
                        payload={
                            "reason": terminal_reason,
                            "rejectedProposalIds": [
                                result.proposal_id for result in rejected_results
                            ],
                            "worldAdvanced": False,
                        },
                    )
                    recorder.append(
                        EvidenceChannel.TRUTH,
                        logical_time=tick + 1,
                        source_id=self.range_backend.range_id,
                        event_type="world.unchanged",
                        payload=self.range_backend.truth(instance).to_dict(),
                    )
                    break

                started = self._mono_ms()
                resolution = self.range_backend.resolve(instance, tuple(admissions))
                self._record_duration(
                    recorder,
                    source_id=self.range_backend.range_id,
                    event_type="range.resolve-completed",
                    started_ms=started,
                    payload={"tick": resolution.tick},
                )
                results = tuple(sorted(resolution.results, key=lambda item: item.actor_id))
                for sensor_event in resolution.sensor_events:
                    recorder.append(
                        EvidenceChannel.SENSOR,
                        logical_time=tick + 1,
                        source_id=self.range_backend.range_id,
                        event_type="sensor.observed",
                        payload=sensor_event,
                    )
                recorder.append(
                    EvidenceChannel.MANAGEMENT,
                    logical_time=tick + 1,
                    source_id=self.range_backend.range_id,
                    event_type="range.resolved",
                    payload={
                        "tick": resolution.tick,
                        "results": [result.to_dict() for result in results],
                    },
                )
                self._record_results(recorder, sessions, results, logical_time=tick + 1)
                recorder.append(
                    EvidenceChannel.TRUTH,
                    logical_time=tick + 1,
                    source_id=self.range_backend.range_id,
                    event_type="world.advanced",
                    payload=self.range_backend.truth(instance).to_dict(),
                )
                ticks_executed = tick + 1
                terminal = self.range_backend.terminal(instance)
                if terminal.terminal:
                    terminal_reason = terminal.reason or "range-terminal"
                    break

            for binding in manifest.actors:
                started = self._mono_ms()
                receipt = self.actor_backends[binding.actor_id].stop(sessions[binding.actor_id])
                self._record_duration(
                    recorder,
                    source_id=binding.actor_id,
                    event_type="actor.stop-completed",
                    started_ms=started,
                    payload={"status": receipt.status},
                )
                recorder.append(
                    EvidenceChannel.MANAGEMENT,
                    logical_time=ticks_attempted,
                    source_id=binding.actor_id,
                    event_type="actor.stopped",
                    payload={
                        "backendId": receipt.backend_id,
                        "sessionId": receipt.session_id,
                        "status": receipt.status,
                        "details": receipt.details,
                    },
                )

            raw_metrics: JsonObject = {
                **self.range_backend.metrics(instance),
                "contest.seed": seed,
                "contest.terminal_reason": terminal_reason,
                "contest.ticks.attempted": ticks_attempted,
                "contest.ticks.executed": ticks_executed,
                "contest.actor_failures": actor_failure_count,
            }
            result_payload: JsonObject = {
                "trialId": trial_id,
                "scenarioDigest": manifest.digest,
                "trialIdentityDigest": identity_digest,
                "seed": seed,
                "terminalReason": terminal_reason,
                "ticksExecuted": ticks_executed,
                "ticksAttempted": ticks_attempted,
            }
            recorder.append(
                EvidenceChannel.MANAGEMENT,
                logical_time=ticks_attempted,
                source_id="contest-runner",
                event_type="contest.stopped",
                payload={**result_payload, "rawMetrics": raw_metrics},
            )
            destroy_started = self._mono_ms()
            self.range_backend.destroy(instance)
            destroyed = True
            self._record_duration(
                recorder,
                source_id=self.range_backend.range_id,
                event_type="range.destroy-completed",
                started_ms=destroy_started,
                payload={},
            )
            recorder.append_operational(
                recorded_at_ms=self._wall_ms(),
                source_id="contest-runner",
                event_type="contest.invocation-completed",
                payload={"terminalReason": terminal_reason},
            )
            output_path = self.evidence_root / trial_id.removeprefix("trial:")
            bundle = recorder.seal(
                output_path,
                scenario_manifest=manifest.to_dict(),
                trial_identity=identity,
                raw_metrics=raw_metrics,
                result=result_payload,
            )
            return ContestResult(
                trial_id=trial_id,
                scenario_digest=manifest.digest,
                trial_identity_digest=identity_digest,
                seed=seed,
                terminal_reason=terminal_reason,
                ticks_executed=ticks_executed,
                raw_metrics=raw_metrics,
                evidence_path=str(output_path),
                evidence_digest=bundle.digest,
                operational_evidence_digest=bundle.operational_digest,
            )
        finally:
            if not destroyed:
                self.range_backend.destroy(instance)

    def _record_results(
        self,
        recorder: EvidenceRecorder,
        sessions: dict[str, ActorSession],
        results: tuple[ActorActionResult, ...],
        *,
        logical_time: int,
    ) -> None:
        for result in results:
            self.actor_backends[result.actor_id].observe_result(sessions[result.actor_id], result)
            recorder.append(
                EvidenceChannel.ACTOR,
                logical_time=logical_time,
                source_id=result.actor_id,
                event_type="actor.action-result",
                payload=result.to_dict(),
            )
