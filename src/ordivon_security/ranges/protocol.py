from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ordivon_security._canonical import JsonObject
from ordivon_security.contest.model import (
    ActionAdmission,
    ActionProposal,
    ActorObservation,
    RangeResolution,
    ScenarioManifest,
    WorldTruthSnapshot,
)


@dataclass(frozen=True, slots=True)
class RangeInstance:
    instance_id: str
    trial_id: str


@dataclass(frozen=True, slots=True)
class RangeTerminal:
    terminal: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class RangeDestroyReceipt:
    instance_id: str
    status: str
    details: JsonObject


class RangeBackend(Protocol):
    range_id: str

    @property
    def execution_identity(self) -> JsonObject: ...

    def create(self, trial_id: str, manifest: ScenarioManifest, seed: int) -> RangeInstance: ...

    def observe(self, instance: RangeInstance, actor_id: str) -> ActorObservation: ...

    def admit(self, instance: RangeInstance, proposal: ActionProposal) -> ActionAdmission: ...

    def resolve(
        self,
        instance: RangeInstance,
        admissions: tuple[ActionAdmission, ...],
    ) -> RangeResolution: ...

    def truth(self, instance: RangeInstance) -> WorldTruthSnapshot: ...

    def metrics(self, instance: RangeInstance) -> JsonObject: ...

    def terminal(self, instance: RangeInstance) -> RangeTerminal: ...

    def destroy(self, instance: RangeInstance) -> RangeDestroyReceipt: ...
