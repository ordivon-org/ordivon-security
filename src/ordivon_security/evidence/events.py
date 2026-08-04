from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json


class EvidenceChannel(StrEnum):
    ACTOR = "actor"
    MANAGEMENT = "range-management"
    SENSOR = "sensor"
    TRUTH = "world-truth"


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    event_id: str
    trial_id: str
    channel: EvidenceChannel
    sequence: int
    logical_time: int
    source_id: str
    event_type: str
    payload: JsonObject
    previous_digest: str | None
    payload_digest: str
    event_digest: str

    def __post_init__(self) -> None:
        if self.sequence < 0 or self.logical_time < 0:
            raise ValueError("Evidence sequence and logical time must be non-negative")
        validate_json(self.payload)
        if canonical_digest(self.payload) != self.payload_digest:
            raise ValueError("Evidence payload digest differs")
        if canonical_digest(self.unsigned_dict()) != self.event_digest:
            raise ValueError("Evidence event digest differs")

    def unsigned_dict(self) -> JsonObject:
        return {
            "eventId": self.event_id,
            "trialId": self.trial_id,
            "channel": self.channel.value,
            "sequence": self.sequence,
            "logicalTime": self.logical_time,
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
        channel: EvidenceChannel,
        sequence: int,
        logical_time: int,
        source_id: str,
        event_type: str,
        payload: JsonObject,
        previous_digest: str | None,
    ) -> EvidenceEvent:
        event_id = f"event:{channel.value}:{sequence}"
        payload_digest = canonical_digest(payload)
        unsigned: JsonObject = {
            "eventId": event_id,
            "trialId": trial_id,
            "channel": channel.value,
            "sequence": sequence,
            "logicalTime": logical_time,
            "sourceId": source_id,
            "eventType": event_type,
            "payload": payload,
            "previousDigest": previous_digest,
            "payloadDigest": payload_digest,
        }
        return cls(
            event_id=event_id,
            trial_id=trial_id,
            channel=channel,
            sequence=sequence,
            logical_time=logical_time,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            previous_digest=previous_digest,
            payload_digest=payload_digest,
            event_digest=canonical_digest(unsigned),
        )
