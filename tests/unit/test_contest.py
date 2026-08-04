from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ordivon_security.actors import SequenceActorBackend
from ordivon_security.cli import build_manifest
from ordivon_security.contest.runner import ContestRunner
from ordivon_security.evidence import verify_evidence_bundle
from ordivon_security.ranges import MicroContestRange

_RED_ACTIONS = ("recon", "exploit_web", "pivot_vault", "exfiltrate", "wait")


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

    def test_simultaneous_isolation_blocks_pivot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                Path(directory),
                ("wait", "monitor", "isolate_vault", "wait", "wait"),
            )
            self.assertFalse(result.raw_metrics["red.objective.completed"])
            self.assertTrue(result.raw_metrics["blue.objective.preserved"])
            self.assertEqual(result.terminal_reason, "max-ticks-reached")

    def test_same_input_replays_to_same_evidence_digest(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
