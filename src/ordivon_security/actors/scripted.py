from __future__ import annotations

from dataclasses import dataclass, field

from ordivon_security._canonical import canonical_digest
from ordivon_security.contest.model import (
    ActionProposal,
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)

from .protocol import ActorBackendReceipt, ActorSession


@dataclass(slots=True)
class SequenceActorBackend:
    actor_id: str
    actions: tuple[str, ...]
    backend_id: str = "backend:scripted-sequence-v1"
    _results: list[ActorActionResult] = field(default_factory=list, init=False, repr=False)

    @property
    def configuration_digest(self) -> str:
        return canonical_digest({"actions": list(self.actions)})

    def start(self, binding: ActorBinding, scenario: ScenarioManifest) -> ActorSession:
        del scenario
        if binding.actor_id != self.actor_id:
            raise ValueError("Scripted backend Actor identity differs from binding")
        if binding.backend_id != self.backend_id:
            raise ValueError("Scripted backend identity differs from binding")
        if binding.backend_config_digest != self.configuration_digest:
            raise ValueError("Scripted backend configuration differs from binding")
        return ActorSession(
            session_id=f"session:{self.actor_id.removeprefix('actor:')}",
            actor_id=self.actor_id,
        )

    def propose(self, session: ActorSession, observation: ActorObservation) -> ActionProposal:
        if session.actor_id != self.actor_id or observation.actor_id != self.actor_id:
            raise ValueError("Scripted backend received another Actor's context")
        action = self.actions[observation.tick] if observation.tick < len(self.actions) else "wait"
        return ActionProposal(
            proposal_id=f"proposal:{self.actor_id.removeprefix('actor:')}:{observation.tick}",
            actor_id=self.actor_id,
            tick=observation.tick,
            action_type=action,
            objective_refs=(f"objective:{self.actor_id.removeprefix('actor:')}",),
            authority_refs=(f"authority:{self.actor_id.removeprefix('actor:')}",),
        )

    def observe_result(self, session: ActorSession, result: ActorActionResult) -> None:
        if session.actor_id != result.actor_id:
            raise ValueError("Scripted backend received another Actor's result")
        self._results.append(result)

    def stop(self, session: ActorSession) -> ActorBackendReceipt:
        return ActorBackendReceipt(
            actor_id=self.actor_id,
            backend_id=self.backend_id,
            session_id=session.session_id,
            status="completed",
            details={"observedResultCount": len(self._results)},
        )
