from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ordivon_security._canonical import JsonObject, validate_json

from .model import RangeSessionSpec


@dataclass(frozen=True, slots=True)
class RangeSessionInstance:
    instance_id: str
    session_id: str


@dataclass(frozen=True, slots=True)
class PendingRangeEvent:
    cursor: int
    logical_time: int
    plane: str
    source_id: str
    event_type: str
    payload: JsonObject
    causal_parents: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.cursor < 0 or self.logical_time < 0:
            raise ValueError("Pending Range event cursor and logical time must be non-negative")
        validate_json(self.payload)


@dataclass(frozen=True, slots=True)
class BackendCheckpoint:
    checkpoint_ref: str
    details: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.checkpoint_ref or self.checkpoint_ref != self.checkpoint_ref.strip():
            raise ValueError("Backend checkpoint reference must be non-empty and trimmed")
        validate_json(self.details)


class RangeSessionBackend(Protocol):
    range_id: str

    @property
    def execution_identity(self) -> JsonObject: ...

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance: ...

    def inspect(self, instance: RangeSessionInstance) -> JsonObject: ...

    def events(
        self,
        instance: RangeSessionInstance,
        *,
        after_cursor: int,
    ) -> tuple[PendingRangeEvent, ...]: ...

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint: ...

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject: ...

    def destroy(self, instance: RangeSessionInstance) -> JsonObject: ...
