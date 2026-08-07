from __future__ import annotations

import unittest

from ordivon_security._canonical import JsonObject
from ordivon_security.range import (
    BackendCheckpoint,
    RangeSession,
    RangeSessionInstance,
    RangeSessionSpec,
)


class _BadCreateBackend:
    range_id = "range:s01-cleanup"

    def __init__(self, *, cleanup_fails: bool = False) -> None:
        self.cleanup_fails = cleanup_fails
        self.destroy_calls = 0

    @property
    def execution_identity(self) -> JsonObject:
        return {"rangeId": self.range_id, "implementationRevision": "test-v1"}

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        return RangeSessionInstance(
            instance_id="range-instance:bad-create",
            session_id=spec.session_id + "-wrong",
        )

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        return {"instanceId": instance.instance_id}

    def events(self, instance: RangeSessionInstance, *, after_cursor: int):
        del instance, after_cursor
        return ()

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        del instance
        return BackendCheckpoint(checkpoint_ref=f"checkpoint-ref:{label}")

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        return {"instanceId": instance.instance_id, "reason": reason}

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        self.destroy_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("simulated cleanup failure")
        return {"instanceId": instance.instance_id, "destroyed": True}


def _spec() -> RangeSessionSpec:
    return RangeSessionSpec(
        session_id="range-session:s01-cleanup",
        revision="1",
        range_id="range:s01-cleanup",
        actor_ids=(),
    )


class RangeSessionCreateCleanupTests(unittest.TestCase):
    def test_post_create_validation_failure_destroys_backend_instance(self) -> None:
        backend = _BadCreateBackend()
        session = RangeSession(backend, _spec())
        with self.assertRaisesRegex(ValueError, "session identity differs"):
            session.start()
        self.assertEqual(backend.destroy_calls, 1)
        self.assertEqual(session.state, "created")
        self.assertEqual(session.events, ())

    def test_cleanup_failure_is_not_silently_hidden(self) -> None:
        backend = _BadCreateBackend(cleanup_fails=True)
        session = RangeSession(backend, _spec())
        with self.assertRaisesRegex(RuntimeError, "cleanup also failed"):
            session.start()
        self.assertEqual(backend.destroy_calls, 1)
        self.assertEqual(session.state, "created")
        self.assertEqual(session.events, ())


if __name__ == "__main__":
    unittest.main()
