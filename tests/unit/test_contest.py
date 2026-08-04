from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import JsonObject
from ordivon_security.actors import (
    ActorProposalFailure,
    ActorProposalFailureCode,
    SequenceActorBackend,
)
from ordivon_security.cli import build_manifest
from ordivon_security.contest.model import ActorObservation
from ordivon_security.contest.runner import ContestRunner
from ordivon_security.evidence import (
    verify_evidence_bundle,
    verify_operational_evidence,
)
from ordivon_security.ranges import MicroContestRange

_RED_ACTIONS = ("recon", "exploit_web", "pivot_vault", "exfiltrate", "wait")


class _TimeoutActorBackend(SequenceActorBackend):
    def propose(self, session, observation: ActorObservation):
        del session, observation
        raise ActorProposalFailure(
            ActorProposalFailureCode.TIMEOUT,
            "provider deadline expired",
            details={"providerId": "provider:test"},
        )


class _IdentityActorBackend(SequenceActorBackend):
    def __init__(self, actor_id: str, actions: tuple[str, ...], revision: str) -> None:
        super().__init__(actor_id, actions)
        self.revision = revision

    @property
    def execution_identity(self) -> JsonObject:
        return {
            **super().execution_identity,
            "testImplementationRevision": self.revision,
        }


class ContestCoreTests(unittest.TestCase):
    def _run(self, root: Path, blue_actions: tuple[str, ...], seed: int = 7):
        return ContestRunner(
            MicroContestRange(),
            {
                "actor:red": SequenceActorBackend("actor:red", _RED_ACTIONS),
                "actor:blue": SequenceActorBackend("actor:blue", blue_actions),
            },
            evidence_root=root,
        ).run(build_manifest(red_actions=_RED_ACTIONS, blue_actions=blue_actions), seed=seed)

    def test_sleepy_blue_allows_red_objective(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(Path(directory), ("wait",) * 5)
            self.assertTrue(result.raw_metrics["red.objective.completed"])
            self.assertEqual(result.terminal_reason, "red-objective-completed")
            self.assertEqual(
                verify_evidence_bundle(Path(result.evidence_path)), result.evidence_digest
            )
            self.assertEqual(
                verify_operational_evidence(Path(result.evidence_path)),
                result.operational_evidence_digest,
            )
            self.assertTrue((Path(result.evidence_path) / "trial-identity.json").is_file())

    def test_simultaneous_isolation_blocks_pivot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                Path(directory),
                ("wait", "monitor", "isolate_vault", "wait", "wait"),
            )
            self.assertFalse(result.raw_metrics["red.objective.completed"])
            self.assertTrue(result.raw_metrics["blue.objective.preserved"])
            self.assertEqual(result.terminal_reason, "max-ticks-reached")

    def test_same_input_replays_to_same_semantic_evidence_digest(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            actions = ("wait", "monitor", "isolate_vault", "wait", "wait")
            one = self._run(Path(first), actions)
            two = self._run(Path(second), actions)
            self.assertEqual(one.trial_id, two.trial_id)
            self.assertEqual(one.raw_metrics, two.raw_metrics)
            self.assertEqual(one.evidence_digest, two.evidence_digest)

    def test_backend_configuration_changes_trial_identity(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            reactive = self._run(
                Path(first),
                ("wait", "monitor", "isolate_vault", "wait", "wait"),
            )
            sleepy = self._run(Path(second), ("wait",) * 5)
            self.assertNotEqual(reactive.trial_id, sleepy.trial_id)
            self.assertNotEqual(reactive.scenario_digest, sleepy.scenario_digest)

    def test_execution_implementation_changes_trial_identity(self) -> None:
        actions = ("wait",) * 5
        manifest = build_manifest(red_actions=actions, blue_actions=actions)
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = ContestRunner(
                MicroContestRange(),
                {
                    "actor:red": _IdentityActorBackend("actor:red", actions, "one"),
                    "actor:blue": SequenceActorBackend("actor:blue", actions),
                },
                evidence_root=Path(first),
            ).run(manifest, seed=7)
            two = ContestRunner(
                MicroContestRange(),
                {
                    "actor:red": _IdentityActorBackend("actor:red", actions, "two"),
                    "actor:blue": SequenceActorBackend("actor:blue", actions),
                },
                evidence_root=Path(second),
            ).run(manifest, seed=7)
            self.assertEqual(one.scenario_digest, two.scenario_digest)
            self.assertNotEqual(one.trial_identity_digest, two.trial_identity_digest)
            self.assertNotEqual(one.trial_id, two.trial_id)

    def test_rejected_action_invalidates_tick_without_world_advance(self) -> None:
        red_actions = ("not-granted",)
        blue_actions = ("wait",)
        manifest = build_manifest(red_actions=red_actions, blue_actions=blue_actions)
        with tempfile.TemporaryDirectory() as directory:
            result = ContestRunner(
                MicroContestRange(),
                {
                    "actor:red": SequenceActorBackend("actor:red", red_actions),
                    "actor:blue": SequenceActorBackend("actor:blue", blue_actions),
                },
                evidence_root=Path(directory),
            ).run(manifest, seed=7)
            self.assertEqual(result.terminal_reason, "invalid-action")
            self.assertEqual(result.ticks_executed, 0)
            self.assertEqual(result.raw_metrics["contest.ticks"], 0)
            self.assertEqual(result.raw_metrics["contest.ticks.attempted"], 1)
            actor_events = self._events(result, "actor")
            statuses = {
                event["payload"]["actorId"]: event["payload"]["status"]
                for event in actor_events
                if event["eventType"] == "actor.action-result"
            }
            self.assertEqual(statuses, {"actor:red": "rejected", "actor:blue": "not-executed"})

    def test_actor_timeout_invalidates_tick_without_peer_execution(self) -> None:
        actions = ("wait",)
        manifest = build_manifest(red_actions=actions, blue_actions=actions)
        with tempfile.TemporaryDirectory() as directory:
            result = ContestRunner(
                MicroContestRange(),
                {
                    "actor:red": _TimeoutActorBackend("actor:red", actions),
                    "actor:blue": SequenceActorBackend("actor:blue", actions),
                },
                evidence_root=Path(directory),
            ).run(manifest, seed=7)
            self.assertEqual(result.terminal_reason, "actor-failure:timeout")
            self.assertEqual(result.ticks_executed, 0)
            self.assertEqual(result.raw_metrics["contest.actor_failures"], 1)
            actor_events = self._events(result, "actor")
            self.assertTrue(
                any(
                    event["eventType"] == "actor.proposal-failed"
                    and event["payload"]["code"] == "timeout"
                    for event in actor_events
                )
            )
            self.assertTrue(
                any(
                    event["eventType"] == "actor.action-result"
                    and event["payload"]["actorId"] == "actor:blue"
                    and event["payload"]["status"] == "not-executed"
                    for event in actor_events
                )
            )

    def test_blue_observation_does_not_expose_hidden_red_access(self) -> None:
        manifest = build_manifest()
        range_backend = MicroContestRange()
        instance = range_backend.create("trial:observation-test", manifest, 0)
        try:
            observation = range_backend.observe(instance, "actor:blue")
            self.assertNotIn("redWebAccess", observation.visible_state)
            self.assertNotIn("redVaultAccess", observation.visible_state)
        finally:
            range_backend.destroy(instance)

    def test_tampered_event_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(Path(directory), ("wait",) * 5)
            actor_path = Path(result.evidence_path) / "events" / "actor.jsonl"
            lines = actor_path.read_text(encoding="utf-8").splitlines()
            value = json.loads(lines[0])
            value["payload"]["tick"] = 99
            lines[0] = json.dumps(value, sort_keys=True, separators=(",", ":"))
            actor_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_evidence_bundle(Path(result.evidence_path))

    def test_tampered_operational_event_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(Path(directory), ("wait",) * 5)
            path = Path(result.evidence_path) / "events" / "operational.jsonl"
            lines = path.read_text(encoding="utf-8").splitlines()
            value = json.loads(lines[0])
            value["payload"]["durationMs"] = 999
            lines[0] = json.dumps(value, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_operational_evidence(Path(result.evidence_path))

    @staticmethod
    def _events(result, channel: str) -> list[dict]:
        return [
            json.loads(line)
            for line in (Path(result.evidence_path) / "events" / f"{channel}.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]


if __name__ == "__main__":
    unittest.main()
