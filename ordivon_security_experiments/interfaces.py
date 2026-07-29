"""Narrow protocols between an experiment runner, actors, and worlds."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .models import ActorIdentity, Decision, Observation, TrialOutcome, WorldIdentity


class Actor(Protocol):
    @property
    def identity(self) -> ActorIdentity: ...

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None: ...

    def decide(self, observation: Observation) -> Decision: ...

    def update(
        self,
        observation: Observation,
        decision: Decision,
        effect: Mapping[str, Any],
    ) -> None: ...

    def usage(self) -> Mapping[str, Any]: ...


class WorldAdapter(Protocol):
    @property
    def identity(self) -> WorldIdentity: ...

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None: ...

    def observe(self, actor_id: str) -> Observation: ...

    def step(self, actor_id: str, decision: Decision) -> Mapping[str, Any]: ...

    def done(self) -> bool: ...

    def truth(self) -> Mapping[str, Any]: ...

    def judge(self, *, actor_usage: Mapping[str, Any]) -> TrialOutcome: ...

    def metadata(self) -> Mapping[str, Any]: ...
