from __future__ import annotations

from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.protocol import ActorBackend, ActorSession
from ordivon_security.evidence.events import EvidenceChannel
from ordivon_security.evidence.recorder import EvidenceRecorder
from ordivon_security.ranges.protocol import RangeBackend

from .model import (
    ActionAdmission,
    ActorActionResult,
    ContestResult,
    ScenarioManifest,
)


class ContestRunner:
    """Execute simultaneous multi-Actor ticks against one authoritative Range."""

    def __init__(
        self,
        range_backend: RangeBackend,
        actor_backends: dict[str, ActorBackend],
        *,
        evidence_root: Path,
    ) -> None:
        self.range_backend = range_backend
        self.actor_backends = dict(actor_backends)
        self.evidence_root = evidence_root

    def run(self, manifest: ScenarioManifest, *, seed: int) -> ContestResult:
        if seed < 0:
            raise ValueError("Contest seed must be non-negative")
        if manifest.range_id != self.range_backend.range_id:
            raise ValueError("Scenario Range identity differs from backend")
        expected_ids = {actor.actor_id for actor in manifest.actors}
        if set(self.actor_backends) != expected_ids:
            raise ValueError("Actor backend set differs from Scenario actors")
        trial_hash = canonical_digest({"scenarioDigest": manifest.digest, "seed": seed})
        trial_id = f"trial:{trial_hash.removeprefix('sha256:')[:24]}"
        recorder = EvidenceRecorder(trial_id)
        instance = self.range_backend.create(trial_id, manifest, seed)
        sessions: dict[str, ActorSession] = {}
        terminal_reason = "max-ticks-reached"
        ticks_executed = 0
        recorder.append(
            EvidenceChannel.MANAGEMENT,
            logical_time=0,
            source_id="contest-runner",
            event_type="contest.started",
            payload={"scenarioDigest": manifest.digest, "seed": seed},
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
                session = backend.start(binding, manifest)
                sessions[binding.actor_id] = session
                recorder.append(
                    EvidenceChannel.MANAGEMENT,
                    logical_time=0,
                    source_id=binding.actor_id,
                    event_type="actor.started",
                    payload={"backendId": backend.backend_id, "sessionId": session.session_id},
                )

            for tick in range(manifest.max_ticks):
                proposals = []
                for binding in manifest.actors:
                    observation = self.range_backend.observe(instance, binding.actor_id)
                    recorder.append(
                        EvidenceChannel.ACTOR,
                        logical_time=tick,
                        source_id=binding.actor_id,
                        event_type="actor.observation",
                        payload=observation.to_dict(),
                    )
                    proposal = self.actor_backends[binding.actor_id].propose(
                        sessions[binding.actor_id], observation
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

                admissions: list[ActionAdmission] = []
                rejected_results: list[ActorActionResult] = []
                for proposal in proposals:
                    admission = self.range_backend.admit(instance, proposal)
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

                resolution = self.range_backend.resolve(instance, tuple(admissions))
                all_results = tuple(
                    sorted((*resolution.results, *rejected_results), key=lambda item: item.actor_id)
                )
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
                        "results": [result.to_dict() for result in all_results],
                    },
                )
                for result in all_results:
                    self.actor_backends[result.actor_id].observe_result(
                        sessions[result.actor_id], result
                    )
                    recorder.append(
                        EvidenceChannel.ACTOR,
                        logical_time=tick + 1,
                        source_id=result.actor_id,
                        event_type="actor.action-result",
                        payload=result.to_dict(),
                    )
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
                receipt = self.actor_backends[binding.actor_id].stop(sessions[binding.actor_id])
                recorder.append(
                    EvidenceChannel.MANAGEMENT,
                    logical_time=ticks_executed,
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
            }
            result_payload: JsonObject = {
                "trialId": trial_id,
                "scenarioDigest": manifest.digest,
                "seed": seed,
                "terminalReason": terminal_reason,
                "ticksExecuted": ticks_executed,
            }
            recorder.append(
                EvidenceChannel.MANAGEMENT,
                logical_time=ticks_executed,
                source_id="contest-runner",
                event_type="contest.stopped",
                payload={**result_payload, "rawMetrics": raw_metrics},
            )
            output_path = self.evidence_root / trial_id.removeprefix("trial:")
            bundle = recorder.seal(
                output_path,
                scenario_manifest=manifest.to_dict(),
                raw_metrics=raw_metrics,
                result=result_payload,
            )
            return ContestResult(
                trial_id=trial_id,
                scenario_digest=manifest.digest,
                seed=seed,
                terminal_reason=terminal_reason,
                ticks_executed=ticks_executed,
                raw_metrics=raw_metrics,
                evidence_path=str(output_path),
                evidence_digest=bundle.digest,
            )
        finally:
            self.range_backend.destroy(instance)
