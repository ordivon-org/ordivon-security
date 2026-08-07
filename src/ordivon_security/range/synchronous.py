from __future__ import annotations

from typing import Protocol

from ordivon_security.contest.model import ContestResult, ScenarioManifest

from .session import RangeSession


class _ContestRunner(Protocol):
    def run(self, manifest: ScenarioManifest, *, seed: int) -> ContestResult: ...


class SynchronousContestProfile:
    """Attach one bounded synchronous Contest to a persistent Range Session."""

    profile_id = "profile:synchronous-contest-v1"

    def __init__(self, runner: _ContestRunner) -> None:
        self.runner = runner

    def run(
        self,
        session: RangeSession,
        manifest: ScenarioManifest,
        *,
        seed: int,
        logical_time: int,
    ) -> ContestResult:
        if session.state != "running":
            raise RuntimeError("Synchronous Contest profile requires a running Range session")
        session_actor_ids = set(session.spec.actor_ids)
        contest_actor_ids = {actor.actor_id for actor in manifest.actors}
        if not contest_actor_ids <= session_actor_ids:
            raise ValueError("Synchronous Contest contains an Actor outside the Range session")

        started = session.record_management_event(
            logical_time=logical_time,
            source_id=self.profile_id,
            event_type="profile.synchronous-contest-started",
            payload={
                "profileId": self.profile_id,
                "scenarioDigest": manifest.digest,
                "seed": seed,
            },
        )
        try:
            result = self.runner.run(manifest, seed=seed)
        except Exception as error:
            session.record_management_event(
                logical_time=logical_time,
                source_id=self.profile_id,
                event_type="profile.synchronous-contest-failed",
                payload={
                    "profileId": self.profile_id,
                    "scenarioDigest": manifest.digest,
                    "seed": seed,
                    "errorType": type(error).__name__,
                },
                causal_parents=(started.event_id,),
            )
            raise

        session.record_management_event(
            logical_time=logical_time,
            source_id=self.profile_id,
            event_type="profile.synchronous-contest-completed",
            payload={
                "profileId": self.profile_id,
                "trialId": result.trial_id,
                "scenarioDigest": result.scenario_digest,
                "trialIdentityDigest": result.trial_identity_digest,
                "seed": result.seed,
                "terminalReason": result.terminal_reason,
                "ticksExecuted": result.ticks_executed,
                "evidenceDigest": result.evidence_digest,
                "operationalEvidenceDigest": result.operational_evidence_digest,
            },
            causal_parents=(started.event_id,),
        )
        return result
