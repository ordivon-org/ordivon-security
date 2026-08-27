from __future__ import annotations

import json
from dataclasses import dataclass, field

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.range import RangeAuthority, RangeEffectRequest


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 1000:
        raise ValueError(f"{label} exceeds 1000 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _json_copy(value: JsonObject) -> JsonObject:
    copied = json.loads(canonical_bytes(value))
    if not isinstance(copied, dict):
        raise TypeError("canonical JSON object copy changed shape")
    return copied


def _request_from_dict(value: JsonObject) -> RangeEffectRequest:
    return RangeEffectRequest(
        request_id=_text(str(value["requestId"]), "Range intent request identity", prefix="range-effect-request"),
        actor_id=_text(str(value["actorId"]), "Range intent request Actor identity", prefix="actor"),
        authority_id=_text(
            str(value["authorityId"]),
            "Range intent request authority identity",
            prefix="range-authority",
        ),
        zone_ref=_text(str(value["zoneRef"]), "Range intent request zone"),
        capability=_text(str(value["capability"]), "Range intent request capability"),
        effect_type=_text(str(value["effectType"]), "Range intent request effect type"),
        payload=_json_copy(value.get("payload", {})),
    )


@dataclass(frozen=True, slots=True)
class RangeEffectInterface:
    authority_id: str
    zone_ref: str
    capability: str
    effect_type: str
    semantics: str
    consequence: JsonObject | None = None
    representation_contract: JsonObject | None = None
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.authority_id, "Range effect interface authority", prefix="range-authority")
        _text(self.zone_ref, "Range effect interface zone")
        _text(self.capability, "Range effect interface capability")
        _text(self.effect_type, "Range effect interface type")
        _text(self.semantics, "Range effect interface semantics")
        if self.consequence is not None:
            validate_json(self.consequence)
        if self.representation_contract is not None:
            validate_json(self.representation_contract)
        validate_json(self.metadata)

    def to_dict(self) -> JsonObject:
        value: JsonObject = {
            "authorityId": self.authority_id,
            "zoneRef": self.zone_ref,
            "capability": self.capability,
            "effectType": self.effect_type,
            "semantics": self.semantics,
            "metadata": _json_copy(self.metadata),
        }
        if self.consequence is not None:
            value["consequence"] = _json_copy(self.consequence)
        if self.representation_contract is not None:
            value["representationContract"] = _json_copy(self.representation_contract)
        validate_json(value)
        return value


@dataclass(frozen=True, slots=True, init=False)
class RangeIntentContext:
    actor_id: str
    objective: str
    _visible_observation: bytes = field(repr=False)
    _authorities: tuple[bytes, ...] = field(repr=False)
    effect_interfaces: tuple[RangeEffectInterface, ...]
    _metadata: bytes = field(repr=False)

    def __init__(
        self,
        *,
        actor_id: str,
        objective: str,
        visible_observation: JsonObject,
        authorities: tuple[RangeAuthority, ...],
        effect_interfaces: tuple[RangeEffectInterface, ...] = (),
        metadata: JsonObject | None = None,
    ) -> None:
        _text(actor_id, "Range intent Actor identity", prefix="actor")
        _text(objective, "Range intent objective")
        validate_json(visible_observation)
        metadata_value: JsonObject = {} if metadata is None else metadata
        validate_json(metadata_value)
        if len({authority.authority_id for authority in authorities}) != len(authorities):
            raise ValueError("Range intent authorities must have unique identities")
        authority_by_id = {authority.authority_id: authority for authority in authorities}
        for authority in authorities:
            if authority.actor_id != actor_id:
                raise ValueError("Range intent context contains authority for another Actor")
        interface_keys: set[tuple[str, str, str, str]] = set()
        for interface in effect_interfaces:
            authority = authority_by_id.get(interface.authority_id)
            if authority is None:
                raise ValueError("Range effect interface references authority outside the context")
            if interface.zone_ref not in authority.zone_refs:
                raise ValueError("Range effect interface zone is not granted by its authority")
            if interface.capability not in authority.capabilities:
                raise ValueError("Range effect interface capability is not granted by its authority")
            key = (
                interface.authority_id,
                interface.zone_ref,
                interface.capability,
                interface.effect_type,
            )
            if key in interface_keys:
                raise ValueError("Range intent effect interfaces must be unique")
            interface_keys.add(key)
        object.__setattr__(self, "actor_id", actor_id)
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "_visible_observation", canonical_bytes(visible_observation))
        object.__setattr__(
            self,
            "_authorities",
            tuple(canonical_bytes(authority.to_dict()) for authority in authorities),
        )
        object.__setattr__(self, "effect_interfaces", tuple(effect_interfaces))
        object.__setattr__(self, "_metadata", canonical_bytes(metadata_value))

    @property
    def visible_observation(self) -> JsonObject:
        value = json.loads(self._visible_observation)
        if not isinstance(value, dict):
            raise RuntimeError("Range intent observation snapshot changed shape")
        return value

    @property
    def authority_snapshots(self) -> tuple[JsonObject, ...]:
        values: list[JsonObject] = []
        for encoded in self._authorities:
            value = json.loads(encoded)
            if not isinstance(value, dict):
                raise RuntimeError("Range intent authority snapshot changed shape")
            values.append(value)
        return tuple(values)

    @property
    def metadata(self) -> JsonObject:
        value = json.loads(self._metadata)
        if not isinstance(value, dict):
            raise RuntimeError("Range intent metadata snapshot changed shape")
        return value

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-intent-context",
            "actorId": self.actor_id,
            "objective": self.objective,
            "visibleObservation": self.visible_observation,
            "authorities": list(self.authority_snapshots),
            "effectInterfaces": [interface.to_dict() for interface in self.effect_interfaces],
            "metadata": self.metadata,
            "rules": {
                "authorityIsPermissionNotInstruction": True,
                "zeroEffectRequestsAllowed": True,
                "multipleEffectRequestsAllowed": True,
                "intentDoesNotExecuteEffect": True,
                "securityAdmissionOccursAfterDecision": True,
            },
        }
        validate_json(value)
        return value

    def decision(
        self,
        effect_requests: tuple[RangeEffectRequest, ...] = (),
        *,
        metadata: JsonObject | None = None,
    ) -> RangeIntentDecision:
        interfaces = {
            (
                interface.authority_id,
                interface.zone_ref,
                interface.capability,
                interface.effect_type,
            )
            for interface in self.effect_interfaces
        }
        for request in effect_requests:
            key = (
                request.authority_id,
                request.zone_ref,
                request.capability,
                request.effect_type,
            )
            if key not in interfaces:
                raise ValueError("Range intent decision requested an undeclared effect interface")
        return RangeIntentDecision(
            actor_id=self.actor_id,
            context_digest=self.digest,
            effect_requests=effect_requests,
            metadata={} if metadata is None else metadata,
        )


@dataclass(frozen=True, slots=True, init=False)
class RangeIntentDecision:
    actor_id: str
    context_digest: str
    _effect_requests: tuple[bytes, ...] = field(repr=False)
    _metadata: bytes = field(repr=False)

    def __init__(
        self,
        *,
        actor_id: str,
        context_digest: str,
        effect_requests: tuple[RangeEffectRequest, ...] = (),
        metadata: JsonObject | None = None,
    ) -> None:
        _text(actor_id, "Range intent decision Actor identity", prefix="actor")
        _text(context_digest, "Range intent context digest", prefix="sha256")
        request_ids = tuple(request.request_id for request in effect_requests)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("Range intent decision request identities must be unique")
        for request in effect_requests:
            if request.actor_id != actor_id:
                raise ValueError("Range intent decision contains request for another Actor")
        metadata_value: JsonObject = {} if metadata is None else metadata
        validate_json(metadata_value)
        object.__setattr__(self, "actor_id", actor_id)
        object.__setattr__(self, "context_digest", context_digest)
        object.__setattr__(
            self,
            "_effect_requests",
            tuple(canonical_bytes(request.to_dict()) for request in effect_requests),
        )
        object.__setattr__(self, "_metadata", canonical_bytes(metadata_value))

    @property
    def effect_requests(self) -> tuple[RangeEffectRequest, ...]:
        values: list[RangeEffectRequest] = []
        for encoded in self._effect_requests:
            value = json.loads(encoded)
            if not isinstance(value, dict):
                raise RuntimeError("Range intent request snapshot changed shape")
            values.append(_request_from_dict(value))
        return tuple(values)

    @property
    def is_hold(self) -> bool:
        return not self._effect_requests

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        metadata = json.loads(self._metadata)
        if not isinstance(metadata, dict):
            raise RuntimeError("Range intent decision metadata changed shape")
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.range-intent-decision",
            "actorId": self.actor_id,
            "contextDigest": self.context_digest,
            "effectRequests": [request.to_dict() for request in self.effect_requests],
            "hold": self.is_hold,
            "metadata": metadata,
        }
        validate_json(value)
        return value


__all__ = [
    "RangeEffectInterface",
    "RangeIntentContext",
    "RangeIntentDecision",
]
