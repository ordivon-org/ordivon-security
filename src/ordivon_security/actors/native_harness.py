from __future__ import annotations

from dataclasses import dataclass, field

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json
from ordivon_security.contest.model import (
    ActionProposal,
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)
from ordivon_security.identity import security_source_identity

from .agent_stack import (
    BACKEND_ID,
    AgentTurnDriver,
    AgentTurnDriverError,
    AgentTurnEvidence,
)
from .protocol import (
    ActorBackendReceipt,
    ActorProposalFailure,
    ActorProposalFailureCode,
    ActorSession,
)


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 500:
        raise ValueError(f"{label} exceeds 500 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


@dataclass(slots=True)
class _ActorState:
    binding: ActorBinding
    scenario_digest: str
    turns: list[AgentTurnEvidence] = field(default_factory=list)
    results: list[ActorActionResult] = field(default_factory=list)


class NativeHarnessActorBackend:
    """Security Actor backed by one bounded Harness/DeepSeek loop per Contest tick."""

    backend_id = BACKEND_ID

    def __init__(
        self,
        *,
        actor_id: str,
        side: str,
        objective: str,
        driver: AgentTurnDriver,
    ) -> None:
        _text(actor_id, "Actor identity", prefix="actor")
        _text(side, "Actor side")
        _text(objective, "Actor objective")
        validate_json(driver.execution_identity)
        self.actor_id = actor_id
        self.side = side
        self.objective = objective
        self.driver = driver
        self._states: dict[str, _ActorState] = {}

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "backendId": self.backend_id,
            "backendRevision": "native-harness-deepseek-v1",
            "actorId": self.actor_id,
            "side": self.side,
            "objectiveDigest": canonical_digest({"objective": self.objective}),
            "agentStack": self.driver.execution_identity,
            "agentStackIdentityDigest": canonical_digest(self.driver.execution_identity),
            "implementation": security_source_identity(),
        }

    @property
    def configuration_digest(self) -> str:
        return canonical_digest(self.execution_identity)

    def start(self, binding: ActorBinding, scenario: ScenarioManifest) -> ActorSession:
        if binding.actor_id != self.actor_id or binding.side != self.side:
            raise ValueError("Native Harness backend Actor identity differs from binding")
        if binding.objective != self.objective:
            raise ValueError("Native Harness backend objective differs from binding")
        if binding.backend_id != self.backend_id:
            raise ValueError("Native Harness backend identity differs from binding")
        if binding.backend_config_digest != self.configuration_digest:
            raise ValueError("Native Harness backend configuration differs from binding")
        if binding.allowed_actions != self.driver.allowed_actions:
            raise ValueError("Native Harness action grant differs from driver identity")
        session_id = f"session:{self.actor_id.removeprefix('actor:')}:{scenario.digest[-16:]}"
        if session_id in self._states:
            raise ValueError("Native Harness Actor session already exists")
        self._states[session_id] = _ActorState(binding, scenario.digest)
        return ActorSession(session_id=session_id, actor_id=self.actor_id)

    def propose(self, session: ActorSession, observation: ActorObservation) -> ActionProposal:
        state = self._state(session)
        if observation.actor_id != self.actor_id:
            raise ValueError("Native Harness backend received another Actor's observation")
        try:
            turn = self.driver.run_turn(
                actor_id=self.actor_id,
                side=self.side,
                objective=self.objective,
                observation=observation,
                prior_results=tuple(state.results),
            )
        except AgentTurnDriverError as error:
            raise ActorProposalFailure(
                error.code,
                str(error),
                details=error.details,
            ) from error
        if turn.selected_action not in state.binding.allowed_actions:
            raise ActorProposalFailure(
                ActorProposalFailureCode.MALFORMED,
                "Harness selected an action outside the Actor grant",
                details={"selectedAction": turn.selected_action},
            )
        state.turns.append(turn)
        return ActionProposal(
            proposal_id=(
                f"proposal:{self.actor_id.removeprefix('actor:')}:{observation.tick}:"
                f"{turn.trace_digest[-12:]}"
            ),
            actor_id=self.actor_id,
            tick=observation.tick,
            action_type=turn.selected_action,
            arguments={
                "agentStackIdentityDigest": canonical_digest(self.driver.execution_identity),
                "harnessRunId": turn.harness_run_id,
                "harnessTraceDigest": turn.trace_digest,
                "credentialScopeId": turn.credential_scope_id,
                "requestedModelId": turn.requested_model_id,
                "effectiveModelIds": list(turn.effective_model_ids),
                "harnessStopCode": turn.stop_code,
                "usage": turn.usage,
            },
            objective_refs=(f"objective:{self.actor_id.removeprefix('actor:')}",),
            authority_refs=(f"authority:{self.actor_id.removeprefix('actor:')}",),
            rationale=turn.rationale,
        )

    def observe_result(self, session: ActorSession, result: ActorActionResult) -> None:
        state = self._state(session)
        if result.actor_id != self.actor_id:
            raise ValueError("Native Harness backend received another Actor's result")
        state.results.append(result)

    def stop(self, session: ActorSession) -> ActorBackendReceipt:
        state = self._states.pop(session.session_id, None)
        if state is None:
            raise KeyError(f"unknown Native Harness Actor session: {session.session_id}")
        return ActorBackendReceipt(
            actor_id=self.actor_id,
            backend_id=self.backend_id,
            session_id=session.session_id,
            status="completed",
            details={
                "scenarioDigest": state.scenario_digest,
                "agentStackIdentityDigest": canonical_digest(self.driver.execution_identity),
                "credentialScopeId": self.driver.credential_scope_id,
                "requestedModelId": self.driver.requested_model_id,
                "turnCount": len(state.turns),
                "observedResultCount": len(state.results),
                "turns": [turn.to_dict(include_trace=True) for turn in state.turns],
            },
        )

    def _state(self, session: ActorSession) -> _ActorState:
        if session.actor_id != self.actor_id:
            raise ValueError("Native Harness session belongs to another Actor")
        try:
            return self._states[session.session_id]
        except KeyError as error:
            raise KeyError(f"unknown Native Harness Actor session: {session.session_id}") from error


__all__ = ["NativeHarnessActorBackend"]
