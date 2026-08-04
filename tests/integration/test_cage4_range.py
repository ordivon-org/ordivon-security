from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ordivon_security.actors import SequenceActorBackend
from ordivon_security.cli_cage4 import build_cage4_manifest
from ordivon_security.contest.runner import ContestRunner
from ordivon_security.evidence import verify_evidence_bundle
from ordivon_security.ranges.cage4 import (
    CAGE4_NATIVE_PLAN,
    CAGE4_SLEEP_PLAN,
    Cage4RangeBackend,
    Cage4RangeConfig,
)

_SOURCE = os.environ.get("ORDIVON_CAGE4_SOURCE")


@unittest.skipUnless(_SOURCE, "optional pinned CAGE 4 source not configured")
class Cage4RangeIntegrationTests(unittest.TestCase):
    def _bindings(self, *, red_plan: str, blue_plan: str, steps: int):
        config = Cage4RangeConfig(source_path=str(_SOURCE))
        red_actions = (red_plan,) * steps
        blue_actions = (blue_plan,) * steps
        manifest = build_cage4_manifest(
            config,
            red_actions=red_actions,
            blue_actions=blue_actions,
            steps=steps,
        )
        actors = {
            "actor:red": SequenceActorBackend("actor:red", red_actions),
            "actor:blue": SequenceActorBackend("actor:blue", blue_actions),
        }
        return config, manifest, actors

    def _run(self, root: Path, *, red_plan: str, blue_plan: str, steps: int = 2):
        config, manifest, actors = self._bindings(
            red_plan=red_plan,
            blue_plan=blue_plan,
            steps=steps,
        )
        return ContestRunner(
            Cage4RangeBackend(config),
            actors,
            evidence_root=root,
        ).run(manifest, seed=1)

    def test_dirty_source_tree_is_rejected(self) -> None:
        source = Path(str(_SOURCE))
        marker = source / ".ordivon-dirty-source-test"
        config, manifest, _ = self._bindings(
            red_plan=CAGE4_NATIVE_PLAN,
            blue_plan=CAGE4_SLEEP_PLAN,
            steps=1,
        )
        marker.write_text("dirty", encoding="utf-8")
        try:
            with self.assertRaisesRegex(ValueError, "source tree must be clean"):
                Cage4RangeBackend(config).create("trial:dirty-source", manifest, seed=1)
        finally:
            marker.unlink(missing_ok=True)

    def test_external_red_blue_actions_cover_all_team_agents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                Path(directory),
                red_plan=CAGE4_NATIVE_PLAN,
                blue_plan=CAGE4_SLEEP_PLAN,
            )
            expected = (
                result.raw_metrics["cage.red.agent_count"]
                + result.raw_metrics["cage.blue.agent_count"]
            ) * result.raw_metrics["cage.ticks"]
            self.assertEqual(result.raw_metrics["cage.external_actions.submitted"], expected)
            self.assertEqual(result.raw_metrics["cage.default_red_blue_actions.used"], 0)
            self.assertEqual(
                verify_evidence_bundle(Path(result.evidence_path)), result.evidence_digest
            )

            actor_events = [
                json.loads(line)
                for line in (Path(result.evidence_path) / "events" / "actor.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            action_results = [
                event["payload"]
                for event in actor_events
                if event["eventType"] == "actor.action-result"
            ]
            self.assertTrue(action_results)
            self.assertTrue(all(result["status"] == "resolved" for result in action_results))
            self.assertTrue(
                all(
                    effect.startswith("cage-action-attempt:")
                    for result in action_results
                    for effect in result["effects"]
                )
            )

    def test_same_seed_and_plans_replay_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = self._run(
                Path(first),
                red_plan=CAGE4_NATIVE_PLAN,
                blue_plan=CAGE4_SLEEP_PLAN,
            )
            two = self._run(
                Path(second),
                red_plan=CAGE4_NATIVE_PLAN,
                blue_plan=CAGE4_SLEEP_PLAN,
            )
            self.assertEqual(one.trial_id, two.trial_id)
            self.assertEqual(one.raw_metrics, two.raw_metrics)
            self.assertEqual(one.evidence_digest, two.evidence_digest)


if __name__ == "__main__":
    unittest.main()
