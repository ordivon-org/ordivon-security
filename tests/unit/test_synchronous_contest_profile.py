from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import JsonObject
from ordivon_security.actors import SequenceActorBackend
from ordivon_security.cli import build_manifest
from ordivon_security.contest.runner import ContestRunner
from ordivon_security.range import (
    BackendCheckpoint,
    RangeSession,
    RangeSessionInstance,
    RangeSessionSpec,
    SynchronousContestProfile,
)
from ordivon_security.ranges import MicroContestRange

_RED_ACTIONS = ("recon", "exploit_web", "pivot_vault", "exfiltrate", "wait")
_BLUE_WAIT = ("wait",) * 5


class _PersistentMemoryBackend:
    range_id = "range:persistent-s1-memory"

    @property
    def execution_identity(self) -> JsonObject:
        return {"rangeId": self.range_id, "implementationRevision": "test-v1"}

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        return RangeSessionInstance(
            instance_id="range-instance:persistent-s1-memory",
            session_id=spec.session_id,
        )

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        return {"instanceId": instance.instance_id, "alive": True}

    def events(self, instance: RangeSessionInstance, *, after_cursor: int):
        del instance, after_cursor
        return ()

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        return BackendCheckpoint(checkpoint_ref=f"checkpoint-ref:{instance.instance_id}:{label}")

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        return {"instanceId": instance.instance_id, "reason": reason, "terminated": True}

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        return {"instanceId": instance.instance_id, "destroyed": True}


class _FailingRunner:
    def run(self, manifest, *, seed: int):
        del manifest, seed
        raise RuntimeError("simulated contest infrastructure failure")


class _NeverCalledRunner:
    def __init__(self) -> None:
        self.called = False

    def run(self, manifest, *, seed: int):
        del manifest, seed
        self.called = True
        raise AssertionError("runner should not be called")


def _session(*actor_ids: str) -> RangeSession:
    session = RangeSession(
        _PersistentMemoryBackend(),
        RangeSessionSpec(
            session_id="range-session:s1-profile",
            revision="1",
            range_id="range:persistent-s1-memory",
            actor_ids=tuple(actor_ids),
        ),
    )
    session.start()
    return session


class SynchronousContestProfileTests(unittest.TestCase):
    def test_completed_contest_is_attached_without_ending_persistent_session(self) -> None:
        session = _session("actor:red", "actor:blue")
        manifest = build_manifest(red_actions=_RED_ACTIONS, blue_actions=_BLUE_WAIT)
        with tempfile.TemporaryDirectory() as directory:
            runner = ContestRunner(
                MicroContestRange(),
                {
                    "actor:red": SequenceActorBackend("actor:red", _RED_ACTIONS),
                    "actor:blue": SequenceActorBackend("actor:blue", _BLUE_WAIT),
                },
                evidence_root=Path(directory),
            )
            result = SynchronousContestProfile(runner).run(
                session,
                manifest,
                seed=7,
                logical_time=10,
            )

        self.assertEqual(session.state, "running")
        self.assertTrue(result.raw_metrics["red.objective.completed"])
        started, completed = session.events[-2:]
        self.assertEqual(started.event_type, "profile.synchronous-contest-started")
        self.assertEqual(completed.event_type, "profile.synchronous-contest-completed")
        self.assertEqual(completed.causal_parents, (started.event_id,))
        self.assertEqual(completed.payload["trialId"], result.trial_id)
        self.assertEqual(completed.payload["evidenceDigest"], result.evidence_digest)
        self.assertNotIn("allowedActions", completed.payload)

    def test_profile_infrastructure_failure_does_not_end_range_session(self) -> None:
        session = _session("actor:red", "actor:blue")
        manifest = build_manifest(red_actions=_RED_ACTIONS, blue_actions=_BLUE_WAIT)
        profile = SynchronousContestProfile(_FailingRunner())  # type: ignore[arg-type]
        with self.assertRaisesRegex(RuntimeError, "simulated contest"):
            profile.run(session, manifest, seed=7, logical_time=11)
        self.assertEqual(session.state, "running")
        started, failed = session.events[-2:]
        self.assertEqual(failed.event_type, "profile.synchronous-contest-failed")
        self.assertEqual(failed.causal_parents, (started.event_id,))
        self.assertEqual(failed.payload["errorType"], "RuntimeError")

    def test_profile_rejects_actor_outside_persistent_session_before_execution(self) -> None:
        session = _session("actor:red")
        manifest = build_manifest(red_actions=_RED_ACTIONS, blue_actions=_BLUE_WAIT)
        runner = _NeverCalledRunner()
        profile = SynchronousContestProfile(runner)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "Actor outside"):
            profile.run(session, manifest, seed=7, logical_time=12)
        self.assertFalse(runner.called)
        self.assertEqual(session.state, "running")
        self.assertEqual(len(session.events), 1)


if __name__ == "__main__":
    unittest.main()
