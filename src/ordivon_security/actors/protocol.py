from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ordivon_security._canonical import JsonObject
from ordivon_security.contest.model import (
    ActionProposal,
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)


@dataclass(frozen=True, slots=True)
class ActorSession:
    session_id: str
    actor_id: str


@dataclass(frozen=True, slots=True)
class ActorBackendReceipt:
    actor_id: str
    backend_id: str
    session_id: str
    status: str
    details: JsonObject


class ActorBackend(Protocol):
    @property
    def backend_id(self) -> str: ...

    @property
    def configuration_digest(self) -> str: ...

    def start(self, binding: ActorBinding, scenario: ScenarioManifest) -> ActorSession: ...

    def propose(self, session: ActorSession, observation: ActorObservation) -> ActionProposal: ...

    def observe_result(self, session: ActorSession, result: ActorActionResult) -> None: ...

    def stop(self, session: ActorSession) -> ActorBackendReceipt: ...
