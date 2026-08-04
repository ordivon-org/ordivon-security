from __future__ import annotations

from dataclasses import dataclass

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json


@dataclass(frozen=True, slots=True)
class OperationalEvidenceEvent:
    event_id: str
    trial_id: str
    sequence: int
    recorded_at_ms: int
    source_id: str
    event_type: str
    payload: JsonObject
    previous_digest: str | None
    payload_digest: str
    event_digest: str

    def __post_init__(self) -> None:
        if self.sequence < 0 or self.recorded_at_ms < 0:
            raise ValueError("operational evidence sequence and time must be non-negative")
        validate_json(self.payload)
        if canonical_digest(self.payload) != self.payload_digest:
            raise ValueError("operational evidence payload digest differs")
        if canonical_digest(self.unsigned_dict()) != self.event_digest:
            raise ValueError("operational evidence event digest differs")

    def unsigned_dict(self) -> JsonObject:
        return {
            "eventId": self.event_id,
            "trialId": self.trial_id,
            "sequence": self.sequence,
            "recordedAtMs": self.recorded_at_ms,
            "sourceId": self.source_id,
            "eventType": self.event_type,
            "payload": self.payload,
            "previousDigest": self.previous_digest,
            "payloadDigest": self.payload_digest,
        }

    def to_dict(self) -> JsonObject:
        return {**self.unsigned_dict(), "eventDigest": self.event_digest}

    @classmethod
    def create(
        cls,
        *,
        trial_id: str,
        sequence: int,
        recorded_at_ms: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
        previous_digest: str | None,
    ) -> OperationalEvidenceEvent:
        event_id = f"operational-event:{sequence}"
        payload_digest = canonical_digest(payload)
        unsigned: JsonObject = {
            "eventId": event_id,
            "trialId": trial_id,
            "sequence": sequence,
            "recordedAtMs": recorded_at_ms,
            "sourceId": source_id,
            "eventType": event_type,
            "payload": payload,
            "previousDigest": previous_digest,
            "payloadDigest": payload_digest,
        }
        return cls(
            event_id=event_id,
            trial_id=trial_id,
            sequence=sequence,
            recorded_at_ms=recorded_at_ms,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            previous_digest=previous_digest,
            payload_digest=payload_digest,
            event_digest=canonical_digest(unsigned),
        )
