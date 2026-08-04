from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from ordivon_security._canonical import JsonObject
from ordivon_security.contest.model import (
    ActionProposal,
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)


class ActorProposalFailureCode(StrEnum):
    MALFORMED = "malformed"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider-error"
    ACTOR_STOPPED = "actor-stopped"


class ActorProposalFailure(RuntimeError):
    def __init__(
        self,
        code: ActorProposalFailureCode,
        message: str,
        *,
        details: JsonObject | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = {} if details is None else details


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

    @property
    def execution_identity(self) -> JsonObject: ...

    def start(self, binding: ActorBinding, scenario: ScenarioManifest) -> ActorSession: ...

    def propose(self, session: ActorSession, observation: ActorObservation) -> ActionProposal: ...

    def observe_result(self, session: ActorSession, result: ActorActionResult) -> None: ...

    def stop(self, session: ActorSession) -> ActorBackendReceipt: ...
