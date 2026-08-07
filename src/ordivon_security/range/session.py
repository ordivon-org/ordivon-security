from __future__ import annotations

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

from .model import ActorPresence, RangeCheckpoint, RangeEvent, RangeSessionSpec
from .protocol import RangeSessionBackend, RangeSessionInstance

_SESSION_STATES = {"created", "running", "terminated", "destroyed"}


class RangeSession:
    """Own one persistent contested-world lifecycle without imposing tick barriers."""

    def __init__(self, backend: RangeSessionBackend, spec: RangeSessionSpec) -> None:
        if backend.range_id != spec.range_id:
            raise ValueError("Range session specification targets another backend")
        self.backend = backend
        self.spec = spec
        self._state = "created"
        self._instance: RangeSessionInstance | None = None
        self._events: list[RangeEvent] = []
        self._backend_cursor = -1
        self._presence = {
            actor_id: ActorPresence(actor_id=actor_id, state="unknown")
            for actor_id in spec.actor_ids
        }

    @property
    def state(self) -> str:
        return self._state

    @property
    def events(self) -> tuple[RangeEvent, ...]:
        return tuple(self._events)

    @property
    def instance(self) -> RangeSessionInstance:
        if self._instance is None:
            raise RuntimeError("Range session has not started")
        return self._instance

    def presence(self, actor_id: str) -> ActorPresence:
        try:
            return self._presence[actor_id]
        except KeyError as error:
            raise KeyError(f"unknown Range session Actor: {actor_id}") from error

    def start(self) -> RangeSessionInstance:
        if self._state != "created":
            raise RuntimeError("Range session can only start from created state")
        backend_identity = self.backend.execution_identity
        validate_json(backend_identity)
        instance = self.backend.create(self.spec)
        if instance.session_id != self.spec.session_id:
            raise ValueError("Range backend instance session identity differs")
        self._append_event(
            logical_time=0,
            plane="management",
            source_id="security:range-session",
            event_type="range.session-started",
            payload={
                "instanceId": instance.instance_id,
                "rangeId": self.spec.range_id,
                "specDigest": self.spec.digest,
                "backendIdentity": backend_identity,
            },
        )
        self._instance = instance
        self._state = "running"
        return instance

    def update_actor_presence(
        self,
        actor_id: str,
        state: str,
        *,
        logical_time: int,
        details: JsonObject | None = None,
    ) -> ActorPresence:
        self._require_live()
        self._validate_logical_time(logical_time)
        if actor_id not in self._presence:
            raise KeyError(f"unknown Range session Actor: {actor_id}")
        presence = ActorPresence(
            actor_id=actor_id,
            state=state,
            details={} if details is None else details,
        )
        previous = self._presence[actor_id]
        self._append_event(
            logical_time=logical_time,
            plane="management",
            source_id=actor_id,
            event_type="actor.presence-changed",
            payload={"previous": previous.state, "current": state, "details": presence.details},
        )
        self._presence[actor_id] = presence
        return presence

    def poll_backend(self) -> tuple[RangeEvent, ...]:
        self._require_live(allow_terminated=True)
        pending = self.backend.events(self.instance, after_cursor=self._backend_cursor)
        previous_cursor = self._backend_cursor
        base_sequence = len(self._events)
        emitted: list[RangeEvent] = []
        for item in pending:
            if item.cursor <= previous_cursor:
                raise ValueError("Range backend event cursor did not advance monotonically")
            previous_cursor = item.cursor
            emitted.append(
                self._build_event(
                    sequence=base_sequence + len(emitted),
                    logical_time=item.logical_time,
                    plane=item.plane,
                    source_id=item.source_id,
                    event_type=item.event_type,
                    payload=item.payload,
                    causal_parents=item.causal_parents,
                )
            )
        self._events.extend(emitted)
        self._backend_cursor = previous_cursor
        return tuple(emitted)

    def checkpoint(self, label: str, *, logical_time: int) -> RangeCheckpoint:
        self._require_live()
        self._validate_logical_time(logical_time)
        if not label or label != label.strip():
            raise ValueError("Range checkpoint label must be non-empty and trimmed")
        backend_checkpoint = self.backend.checkpoint(self.instance, label)
        checkpoint_digest = canonical_digest(
            {
                "sessionId": self.spec.session_id,
                "label": label,
                "logicalTime": logical_time,
                "backendCheckpointRef": backend_checkpoint.checkpoint_ref,
                "details": backend_checkpoint.details,
            }
        )
        checkpoint = RangeCheckpoint(
            checkpoint_id=f"checkpoint:{checkpoint_digest.removeprefix('sha256:')[:24]}",
            session_id=self.spec.session_id,
            label=label,
            logical_time=logical_time,
            backend_checkpoint_ref=backend_checkpoint.checkpoint_ref,
            details=backend_checkpoint.details,
        )
        self._append_event(
            logical_time=logical_time,
            plane="management",
            source_id="security:range-session",
            event_type="range.checkpoint-created",
            payload=checkpoint.to_dict(),
        )
        return checkpoint

    def terminate(self, reason: str, *, logical_time: int) -> JsonObject:
        self._require_live()
        self._validate_logical_time(logical_time)
        if not reason or reason != reason.strip():
            raise ValueError("Range termination reason must be non-empty and trimmed")
        receipt = self.backend.terminate(self.instance, reason)
        validate_json(receipt)
        self._append_event(
            logical_time=logical_time,
            plane="management",
            source_id="security:range-session",
            event_type="range.session-terminated",
            payload={"reason": reason, "backendReceipt": receipt},
        )
        self._state = "terminated"
        return receipt

    def destroy(self, *, logical_time: int) -> JsonObject:
        self._require_live(allow_terminated=True)
        self._validate_logical_time(logical_time)
        receipt = self.backend.destroy(self.instance)
        validate_json(receipt)
        self._append_event(
            logical_time=logical_time,
            plane="management",
            source_id="security:range-session",
            event_type="range.session-destroyed",
            payload={"backendReceipt": receipt},
        )
        self._state = "destroyed"
        return receipt

    def inspect(self) -> JsonObject:
        if self._state not in _SESSION_STATES:
            raise RuntimeError("Range session state is invalid")
        backend_state: JsonObject | None
        if self._state == "destroyed" or self._instance is None:
            backend_state = None
        else:
            backend_state = self.backend.inspect(self.instance)
            validate_json(backend_state)
        return {
            "sessionId": self.spec.session_id,
            "specDigest": self.spec.digest,
            "rangeId": self.spec.range_id,
            "state": self._state,
            "actors": [self._presence[actor_id].to_dict() for actor_id in self.spec.actor_ids],
            "authorities": [authority.to_dict() for authority in self.spec.authorities],
            "eventCount": len(self._events),
            "backendState": backend_state,
        }

    def _append_event(
        self,
        *,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
        causal_parents: tuple[str, ...] = (),
    ) -> RangeEvent:
        event = self._build_event(
            sequence=len(self._events),
            logical_time=logical_time,
            plane=plane,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            causal_parents=causal_parents,
        )
        self._events.append(event)
        return event

    def _build_event(
        self,
        *,
        sequence: int,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
        causal_parents: tuple[str, ...] = (),
    ) -> RangeEvent:
        token = self.spec.session_id.removeprefix("range-session:")
        return RangeEvent(
            event_id=f"range-event:{token}:{sequence}",
            session_id=self.spec.session_id,
            sequence=sequence,
            logical_time=logical_time,
            plane=plane,
            source_id=source_id,
            event_type=event_type,
            payload=payload,
            causal_parents=causal_parents,
        )

    @staticmethod
    def _validate_logical_time(logical_time: int) -> None:
        if logical_time < 0:
            raise ValueError("Range session logical time must be non-negative")

    def _require_live(self, *, allow_terminated: bool = False) -> None:
        valid = {"running", "terminated"} if allow_terminated else {"running"}
        if self._state not in valid:
            raise RuntimeError(
                f"Range session state {self._state!r} does not permit this operation"
            )
