from __future__ import annotations

from dataclasses import dataclass, field

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

_RANGE_EVENT_PLANES = {"contested", "management", "sensor", "world-truth"}
_ACTOR_PRESENCE_STATES = {"unknown", "active", "unreachable", "stopped", "compromised"}
_EXTERNAL_BOUNDARIES = {"denied"}


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 300:
        raise ValueError(f"{label} exceeds 300 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} values must be unique")
    for value in values:
        _text(value, label)


@dataclass(frozen=True, slots=True)
class RangeAuthority:
    authority_id: str
    revision: str
    actor_id: str
    zone_refs: tuple[str, ...]
    capabilities: tuple[str, ...]
    external_boundary: str = "denied"
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.authority_id, "Range authority identity", prefix="range-authority")
        _text(self.revision, "Range authority revision")
        _text(self.actor_id, "Range authority Actor identity", prefix="actor")
        _unique(self.zone_refs, "Range authority zone")
        _unique(self.capabilities, "Range authority capability")
        if not self.zone_refs:
            raise ValueError("Range authority must declare at least one zone")
        if not self.capabilities:
            raise ValueError("Range authority must declare at least one capability")
        if self.external_boundary not in _EXTERNAL_BOUNDARIES:
            raise ValueError("Range authority external boundary is unsupported")
        validate_json(self.metadata)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-authority",
            "authorityId": self.authority_id,
            "revision": self.revision,
            "actorId": self.actor_id,
            "zoneRefs": list(self.zone_refs),
            "capabilities": list(self.capabilities),
            "externalBoundary": self.external_boundary,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ActorPresence:
    actor_id: str
    state: str
    details: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.actor_id, "Actor presence identity", prefix="actor")
        if self.state not in _ACTOR_PRESENCE_STATES:
            raise ValueError("Actor presence state is unsupported")
        validate_json(self.details)

    def to_dict(self) -> JsonObject:
        return {
            "actorId": self.actor_id,
            "state": self.state,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class RangeSessionSpec:
    session_id: str
    revision: str
    range_id: str
    actor_ids: tuple[str, ...]
    authorities: tuple[RangeAuthority, ...] = ()
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.session_id, "Range session identity", prefix="range-session")
        _text(self.revision, "Range session revision")
        _text(self.range_id, "Range identity", prefix="range")
        _unique(self.actor_ids, "Range session Actor identity")
        actor_set = set(self.actor_ids)
        authority_ids = tuple(item.authority_id for item in self.authorities)
        _unique(authority_ids, "Range authority identity")
        for authority in self.authorities:
            if authority.actor_id not in actor_set:
                raise ValueError("Range authority references an Actor outside the session")
        validate_json(self.metadata)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-session-spec",
            "sessionId": self.session_id,
            "revision": self.revision,
            "rangeId": self.range_id,
            "actorIds": list(self.actor_ids),
            "authorities": [authority.to_dict() for authority in self.authorities],
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class RangeEvent:
    event_id: str
    session_id: str
    sequence: int
    logical_time: int
    plane: str
    source_id: str
    event_type: str
    payload: JsonObject
    causal_parents: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.event_id, "Range event identity", prefix="range-event")
        _text(self.session_id, "Range event session identity", prefix="range-session")
        if self.sequence < 0 or self.logical_time < 0:
            raise ValueError("Range event sequence and logical time must be non-negative")
        if self.plane not in _RANGE_EVENT_PLANES:
            raise ValueError("Range event plane is unsupported")
        _text(self.source_id, "Range event source identity")
        _text(self.event_type, "Range event type")
        _unique(self.causal_parents, "Range event causal parent")
        validate_json(self.payload)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-event",
            "eventId": self.event_id,
            "sessionId": self.session_id,
            "sequence": self.sequence,
            "logicalTime": self.logical_time,
            "plane": self.plane,
            "sourceId": self.source_id,
            "eventType": self.event_type,
            "payload": self.payload,
            "causalParents": list(self.causal_parents),
        }


@dataclass(frozen=True, slots=True)
class RangeCheckpoint:
    checkpoint_id: str
    session_id: str
    label: str
    logical_time: int
    backend_checkpoint_ref: str
    details: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.checkpoint_id, "Range checkpoint identity", prefix="checkpoint")
        _text(self.session_id, "Range checkpoint session identity", prefix="range-session")
        _text(self.label, "Range checkpoint label")
        if self.logical_time < 0:
            raise ValueError("Range checkpoint logical time must be non-negative")
        _text(self.backend_checkpoint_ref, "Range backend checkpoint reference")
        validate_json(self.details)

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-checkpoint",
            "checkpointId": self.checkpoint_id,
            "sessionId": self.session_id,
            "label": self.label,
            "logicalTime": self.logical_time,
            "backendCheckpointRef": self.backend_checkpoint_ref,
            "details": self.details,
        }
