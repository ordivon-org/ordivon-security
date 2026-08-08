from __future__ import annotations

import unittest

from ordivon_security._canonical import JsonObject
from ordivon_security.range import (
    BackendCheckpoint,
    PendingRangeEvent,
    RangeAuthority,
    RangeEffectRequest,
    RangeSession,
    RangeSessionInstance,
    RangeSessionSpec,
)


class _MemoryRangeBackend:
    range_id = "range:memory-war-s0"

    def __init__(self) -> None:
        self.pending: list[PendingRangeEvent] = []
        self.created = False
        self.terminated = False
        self.destroyed = False

    @property
    def execution_identity(self) -> JsonObject:
        return {"rangeId": self.range_id, "implementationRevision": "test-v1"}

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        self.created = True
        return RangeSessionInstance(
            instance_id=f"range-instance:{spec.session_id.removeprefix('range-session:')}",
            session_id=spec.session_id,
        )

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        return {
            "instanceId": instance.instance_id,
            "terminated": self.terminated,
            "destroyed": self.destroyed,
        }

    def events(
        self,
        instance: RangeSessionInstance,
        *,
        after_cursor: int,
    ) -> tuple[PendingRangeEvent, ...]:
        del instance
        return tuple(item for item in self.pending if item.cursor > after_cursor)

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        return BackendCheckpoint(
            checkpoint_ref=f"memory-checkpoint:{instance.instance_id}:{label}",
            details={"kind": "memory"},
        )

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        self.terminated = True
        return {"instanceId": instance.instance_id, "reason": reason, "terminated": True}

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        self.destroyed = True
        return {"instanceId": instance.instance_id, "destroyed": True}

    def emit(
        self,
        *,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> None:
        self.pending.append(
            PendingRangeEvent(
                cursor=len(self.pending),
                logical_time=logical_time,
                plane=plane,
                source_id=source_id,
                event_type=event_type,
                payload=payload,
            )
        )


def _authority(actor_id: str) -> RangeAuthority:
    suffix = actor_id.removeprefix("actor:")
    return RangeAuthority(
        authority_id=f"range-authority:{suffix}",
        revision="1",
        actor_id=actor_id,
        zone_refs=("zone:battlefield",),
        capabilities=("native-execution", "range-network"),
        external_boundary="denied",
    )


def _spec(*actor_ids: str) -> RangeSessionSpec:
    return RangeSessionSpec(
        session_id="range-session:s0-test",
        revision="1",
        range_id="range:memory-war-s0",
        actor_ids=tuple(actor_ids),
        authorities=tuple(_authority(actor_id) for actor_id in actor_ids),
    )


class RangeSessionS0Tests(unittest.TestCase):
    def test_actor_exists_without_action_menu(self) -> None:
        spec = _spec("actor:red")
        self.assertFalse(hasattr(spec, "allowed_actions"))
        self.assertFalse(hasattr(spec.authorities[0], "allowed_actions"))
        session = RangeSession(_MemoryRangeBackend(), spec)
        session.start()
        self.assertEqual(session.state, "running")

    def test_actor_failure_does_not_invalidate_world_or_peer(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red", "actor:blue"))
        session.start()
        session.update_actor_presence(
            "actor:red",
            "unreachable",
            logical_time=4,
            details={"reason": "provider-timeout"},
        )
        session.update_actor_presence("actor:blue", "active", logical_time=4)
        backend.emit(
            logical_time=5,
            plane="contested",
            source_id="environment:service",
            event_type="service.state-changed",
            payload={"available": False},
        )
        emitted = session.poll_backend()
        self.assertEqual(session.state, "running")
        self.assertEqual(session.presence("actor:red").state, "unreachable")
        self.assertEqual(session.presence("actor:blue").state, "active")
        self.assertEqual(emitted[0].event_type, "service.state-changed")

    def test_environment_can_change_without_actor_proposal(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        backend.emit(
            logical_time=9,
            plane="contested",
            source_id="environment:clock",
            event_type="environment.condition-changed",
            payload={"condition": "degraded"},
        )
        emitted = session.poll_backend()
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0].source_id, "environment:clock")
        self.assertNotIn("proposal", emitted[0].to_dict())

    def test_logical_time_is_not_a_barrier(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        backend.emit(
            logical_time=12,
            plane="contested",
            source_id="node:a",
            event_type="node.changed",
            payload={"value": 1},
        )
        backend.emit(
            logical_time=12,
            plane="contested",
            source_id="node:b",
            event_type="node.changed",
            payload={"value": 2},
        )
        first, second = session.poll_backend()
        self.assertEqual(first.logical_time, second.logical_time)
        self.assertNotEqual(first.sequence, second.sequence)
        self.assertNotEqual(first.event_id, second.event_id)

    def test_authority_grants_zone_and_capability_not_commands(self) -> None:
        authority = _authority("actor:red")
        value = authority.to_dict()
        self.assertEqual(value["zoneRefs"], ["zone:battlefield"])
        self.assertEqual(value["capabilities"], ["native-execution", "range-network"])
        self.assertEqual(value["externalBoundary"], "denied")
        self.assertNotIn("actions", value)
        self.assertNotIn("allowedActions", value)

    def test_external_boundary_is_profile_defined_not_core_enum(self) -> None:
        authority = RangeAuthority(
            authority_id="range-authority:delegated",
            revision="1",
            actor_id="actor:red",
            zone_refs=("zone:battlefield",),
            capabilities=("range-network",),
            external_boundary="owned-delegated-world",
        )
        self.assertEqual(authority.to_dict()["externalBoundary"], "owned-delegated-world")

    def test_external_boundary_must_still_be_exact_nonempty_text(self) -> None:
        with self.assertRaises(ValueError):
            RangeAuthority(
                authority_id="range-authority:bad-boundary",
                revision="1",
                actor_id="actor:red",
                zone_refs=("zone:battlefield",),
                capabilities=("range-network",),
                external_boundary=" ",
            )

    def test_management_and_contested_planes_are_distinct(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        backend.emit(
            logical_time=1,
            plane="contested",
            source_id="node:red",
            event_type="node.mutated",
            payload={"changed": True},
        )
        contested = session.poll_backend()[0]
        management = session.events[0]
        self.assertEqual(management.plane, "management")
        self.assertEqual(contested.plane, "contested")

    def test_world_truth_plane_is_distinct_from_management_and_contested(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        backend.emit(
            logical_time=2,
            plane="world-truth",
            source_id="observer:external",
            event_type="world.state-observed",
            payload={"changed": True},
        )
        event = session.poll_backend()[0]
        self.assertEqual(event.plane, "world-truth")
        self.assertEqual(session.events[0].plane, "management")

    def test_sensor_plane_is_observation_not_world_truth(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        backend.emit(
            logical_time=3,
            plane="sensor",
            source_id="sensor:external-packet-capture",
            event_type="sensor.packet-observed",
            payload={"packetCount": 1},
        )
        event = session.poll_backend()[0]
        self.assertEqual(event.plane, "sensor")
        self.assertNotEqual(event.plane, "world-truth")

    def test_effect_admission_uses_exact_actor_zone_and_capability_authority(self) -> None:
        session = RangeSession(_MemoryRangeBackend(), _spec("actor:red"))
        session.start()
        request = RangeEffectRequest(
            request_id="range-effect-request:red-replace-peer",
            actor_id="actor:red",
            authority_id="range-authority:red",
            zone_ref="zone:battlefield",
            capability="range-network",
            effect_type="fabric.replace-peer",
            payload={"peer": "b"},
        )
        admission = session.admit_effect(request, logical_time=2)
        self.assertTrue(admission.admitted)
        self.assertEqual(admission.reason, "admitted")
        self.assertEqual(admission.authority_digest, _authority("actor:red").digest)
        self.assertEqual(session.events[-2].plane, "contested")
        self.assertEqual(session.events[-2].event_type, "actor.effect-requested")
        self.assertEqual(session.events[-1].plane, "management")
        self.assertEqual(session.events[-1].event_type, "effect.admitted")

    def test_effect_admission_rejects_fake_authority_wrong_zone_and_wrong_capability(self) -> None:
        session = RangeSession(_MemoryRangeBackend(), _spec("actor:red"))
        session.start()
        cases = (
            (
                "fake",
                "range-authority:fake",
                "zone:battlefield",
                "range-network",
                "unknown-authority",
            ),
            ("zone", "range-authority:red", "zone:elsewhere", "range-network", "zone-not-granted"),
            (
                "cap",
                "range-authority:red",
                "zone:battlefield",
                "destroy-world",
                "capability-not-granted",
            ),
        )
        for suffix, authority_id, zone_ref, capability, reason in cases:
            admission = session.admit_effect(
                RangeEffectRequest(
                    request_id=f"range-effect-request:red-{suffix}",
                    actor_id="actor:red",
                    authority_id=authority_id,
                    zone_ref=zone_ref,
                    capability=capability,
                    effect_type="fabric.replace-peer",
                ),
                logical_time=2,
            )
            self.assertFalse(admission.admitted)
            self.assertEqual(admission.reason, reason)
            self.assertEqual(session.events[-1].event_type, "effect.rejected")

    def test_effect_admission_rejects_authority_owned_by_another_actor(self) -> None:
        session = RangeSession(_MemoryRangeBackend(), _spec("actor:red", "actor:blue"))
        session.start()
        admission = session.admit_effect(
            RangeEffectRequest(
                request_id="range-effect-request:red-using-blue",
                actor_id="actor:red",
                authority_id="range-authority:blue",
                zone_ref="zone:battlefield",
                capability="range-network",
                effect_type="fabric.replace-peer",
            ),
            logical_time=2,
        )
        self.assertFalse(admission.admitted)
        self.assertEqual(admission.reason, "authority-actor-mismatch")

    def test_effect_admission_exact_replay_is_idempotent_and_changed_replay_fails(self) -> None:
        session = RangeSession(_MemoryRangeBackend(), _spec("actor:red"))
        session.start()
        request = RangeEffectRequest(
            request_id="range-effect-request:red-replay",
            actor_id="actor:red",
            authority_id="range-authority:red",
            zone_ref="zone:battlefield",
            capability="range-network",
            effect_type="fabric.replace-peer",
        )
        first = session.admit_effect(request, logical_time=3)
        event_count = len(session.events)
        second = session.admit_effect(request, logical_time=99)
        self.assertEqual(first, second)
        self.assertEqual(len(session.events), event_count)
        changed = RangeEffectRequest(
            request_id=request.request_id,
            actor_id="actor:red",
            authority_id="range-authority:red",
            zone_ref="zone:battlefield",
            capability="native-execution",
            effect_type="fabric.replace-peer",
        )
        with self.assertRaisesRegex(ValueError, "reused with different content"):
            session.admit_effect(changed, logical_time=4)

    def test_checkpoint_is_backend_owned_but_session_identified(self) -> None:
        session = RangeSession(_MemoryRangeBackend(), _spec("actor:red"))
        session.start()
        checkpoint = session.checkpoint("before-reboot", logical_time=3)
        self.assertTrue(checkpoint.checkpoint_id.startswith("checkpoint:"))
        self.assertEqual(checkpoint.session_id, "range-session:s0-test")
        self.assertTrue(checkpoint.backend_checkpoint_ref.startswith("memory-checkpoint:"))
        self.assertEqual(session.events[-1].event_type, "range.checkpoint-created")

    def test_terminate_and_destroy_are_separate_lifecycle_transitions(self) -> None:
        backend = _MemoryRangeBackend()
        session = RangeSession(backend, _spec("actor:red"))
        session.start()
        session.terminate("experiment-complete", logical_time=20)
        self.assertEqual(session.state, "terminated")
        session.destroy(logical_time=21)
        self.assertEqual(session.state, "destroyed")
        self.assertTrue(backend.terminated)
        self.assertTrue(backend.destroyed)


if __name__ == "__main__":
    unittest.main()
