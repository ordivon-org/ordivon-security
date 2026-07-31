from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from ordivon_security_experiments.actors import (
    CommandDecisionActor,
    CommitteeActor,
    GreedyActor,
    OpponentAwareActor,
)
from ordivon_security_experiments.analysis import compare_actor_families
from ordivon_security_experiments.evidence import verify_trial_evidence
from ordivon_security_experiments.micro_contest import (
    MicroContestScorer,
    MicroContestWorld,
)
from ordivon_security_experiments.models import (
    ActorIdentity,
    EvaluationIdentity,
    ExperimentSpec,
    digest_json,
)
from ordivon_security_experiments.runner import run_family, run_trial


class ExperimentModelTests(unittest.TestCase):
    def test_spec_round_trip_and_digest_are_stable(self) -> None:
        world = MicroContestWorld()
        actor = ActorIdentity("greedy", "Red", "scripted", "GreedyActor")
        spec = ExperimentSpec(
            experiment_id="EXP-TEST",
            world=world.identity,
            actor=actor,
            evaluation=EvaluationIdentity("judge", "1"),
            seeds=(1, 2),
            opponent_policies=("alpha-decoy-switch",),
            max_turns=8,
        )
        restored = ExperimentSpec.from_dict(spec.to_dict())
        self.assertEqual(restored, spec)
        self.assertEqual(digest_json(restored.to_dict()), digest_json(spec.to_dict()))

    def test_observation_does_not_expose_authoritative_opponent_state(self) -> None:
        world = MicroContestWorld()
        world.reset(trial_id="trial", seed=1, opponent_policy="alpha-decoy-switch")
        observation = world.observe("red")
        self.assertNotIn("decoy_route", observation.visible_state)
        self.assertNotIn("opponent_policy", observation.visible_state)
        self.assertIn("decoy_route", world.truth())
        self.assertNotEqual(observation.source_truth_digest, digest_json(observation.visible_state))


class MicroContestScorerWithDrift(MicroContestScorer):
    @property
    def identity(self) -> EvaluationIdentity:
        return EvaluationIdentity("micro-contest-multidimensional-judge", "drift")


class DynamicContestTests(unittest.TestCase):
    def _spec(self, actor_identity: ActorIdentity, experiment_id: str = "EXP-TEST") -> ExperimentSpec:
        return ExperimentSpec(
            experiment_id=experiment_id,
            world=MicroContestWorld().identity,
            actor=actor_identity,
            evaluation=MicroContestScorer().identity,
            seeds=(3,),
            opponent_policies=("adaptive-counter",),
            max_turns=8,
        )

    def test_greedy_local_success_can_be_strategic_failure(self) -> None:
        identity = ActorIdentity("greedy", "Red", "scripted", "GreedyActor")
        with tempfile.TemporaryDirectory() as directory:
            result = run_trial(
                spec=self._spec(identity),
                world=MicroContestWorld(),
                actor=GreedyActor(identity),
                scorer=MicroContestScorer(),
                seed=3,
                opponent_policy="adaptive-counter",
                output_dir=Path(directory),
            )
        self.assertTrue(result.outcome.details["decoy_triggered"])
        self.assertFalse(result.outcome.details["objective_achieved"])
        self.assertGreater(result.outcome.tactical, result.outcome.strategic)

    def test_opponent_aware_actor_emits_evidence_linked_revision(self) -> None:
        identity = ActorIdentity(
            "aware",
            "Red",
            "explicit-hypothesis",
            "OpponentAwareActor",
            memory_mode="structured",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = run_trial(
                spec=self._spec(identity),
                world=MicroContestWorld(),
                actor=OpponentAwareActor(identity),
                scorer=MicroContestScorer(),
                seed=3,
                opponent_policy="adaptive-counter",
                output_dir=Path(directory),
            )
        self.assertTrue(result.outcome.details["policy_switch_recognized"])
        self.assertGreaterEqual(result.outcome.information, 2 / 3)
        self.assertGreaterEqual(result.outcome.details["strategic_revisions"], 1)

    def test_command_actor_requires_allowed_json_action(self) -> None:
        identity = ActorIdentity("command", "Red", "llm", "CommandDecisionActor")
        actor = CommandDecisionActor(
            identity,
            command=(
                sys.executable,
                "-c",
                "import json; print(json.dumps({'action':'scan_beta','rationale':'bounded'}))",
                "{prompt}",
            ),
        )
        world = MicroContestWorld()
        world.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        actor.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        decision = actor.decide(world.observe(identity.actor_id))
        self.assertEqual(decision.action, "scan_beta")
        self.assertEqual(actor.usage()["model_calls"], 1)
        self.assertEqual(actor.usage()["parse_failures"], 0)

    def test_command_actor_turns_provider_invocation_failure_into_evidence(self) -> None:
        identity = ActorIdentity("missing-provider", "Red", "llm", "CommandDecisionActor")
        actor = CommandDecisionActor(
            identity,
            command=("/definitely/missing/provider", "{prompt}"),
            timeout_seconds=1,
        )
        world = MicroContestWorld()
        world.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        actor.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        decision = actor.decide(world.observe(identity.actor_id))
        self.assertEqual(decision.action, "wait")
        self.assertEqual(decision.metadata["provider_exception"], "FileNotFoundError")
        self.assertEqual(actor.usage()["model_calls"], 1)
        self.assertEqual(actor.usage()["parse_failures"], 1)

    def test_command_actor_records_provider_tokens_and_elapsed_time(self) -> None:
        identity = ActorIdentity("metered", "Red", "llm", "CommandDecisionActor")
        script = (
            "import json,sys; "
            "print('tokens used\\n1,234', file=sys.stderr); "
            "print(json.dumps({'action':'wait','rationale':'metered','strategic_revision':None,'hypothesis_updates':[]}))"
        )
        actor = CommandDecisionActor(
            identity,
            command=(sys.executable, "-c", script, "{prompt}"),
        )
        world = MicroContestWorld()
        world.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        actor.reset(trial_id="trial", seed=2, opponent_policy="alpha-decoy-switch")
        decision = actor.decide(world.observe(identity.actor_id))
        usage = actor.usage()
        self.assertEqual(decision.action, "wait")
        self.assertEqual(usage["provider_reported_tokens"], 1234)
        self.assertGreater(usage["provider_elapsed_seconds"], 0.0)

    def test_compartmentalization_changes_compromised_committee_choice(self) -> None:
        observation_world = MicroContestWorld()
        observation_world.reset(trial_id="trial", seed=5, opponent_policy="alpha-decoy-switch")
        observation = observation_world.observe("committee")
        identity = ActorIdentity(
            "committee",
            "Red organization",
            "organization",
            "CommitteeActor",
            organization_id="committee",
        )
        naive = CommitteeActor(identity, compartmentalized=False, compromised_member=True)
        protected = CommitteeActor(identity, compartmentalized=True, compromised_member=True)
        naive.reset(trial_id="trial", seed=5, opponent_policy="alpha-decoy-switch")
        protected.reset(trial_id="trial", seed=5, opponent_policy="alpha-decoy-switch")
        self.assertEqual(naive.decide(observation).action, "exploit_alpha")
        self.assertIn(protected.decide(observation).action, observation.allowed_actions)

    def test_family_preserves_trials_and_builds_comparison(self) -> None:
        identity = ActorIdentity("greedy", "Red", "scripted", "GreedyActor")
        spec = ExperimentSpec(
            experiment_id="EXP-FAMILY",
            world=MicroContestWorld().identity,
            actor=identity,
            evaluation=MicroContestScorer().identity,
            seeds=(1, 2),
            opponent_policies=("alpha-decoy-switch", "beta-decoy-switch"),
            max_turns=6,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            summary = run_family(
                spec=spec,
                world_factory=MicroContestWorld,
                actor_factory=lambda: GreedyActor(identity),
                scorer_factory=MicroContestScorer,
                output_dir=output,
            )
            comparison = compare_actor_families([output / "trial-index.json"])
            index = json.loads((output / "trial-index.json").read_text())
        self.assertEqual(summary.trial_count, 4)
        self.assertEqual(len(index), 4)
        self.assertEqual(comparison["greedy"]["trial_count"], 4)

    def test_trial_evidence_is_sealed_replayable_and_immutable(self) -> None:
        identity = ActorIdentity("sealed", "Red", "scripted", "GreedyActor")
        spec = self._spec(identity, "EXP-SEALED")
        scorer = MicroContestScorer()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = run_trial(
                spec=spec,
                world=MicroContestWorld(),
                actor=GreedyActor(identity),
                scorer=scorer,
                seed=3,
                opponent_policy="adaptive-counter",
                output_dir=output,
            )
            trial_dir = next((output / "trials").iterdir())
            seal = verify_trial_evidence(trial_dir)
            hidden = json.loads(
                (trial_dir / "hidden-evaluation-record.json").read_text()
            )
            recomputed = scorer.score(
                hidden["payload"],
                actor_usage=result.metadata["actor_usage"],
            )
            self.assertEqual(result.outcome, recomputed)
            self.assertEqual(result.trial_key, seal.trial_key)
            with self.assertRaisesRegex(FileExistsError, "immutable Trial evidence"):
                run_trial(
                    spec=spec,
                    world=MicroContestWorld(),
                    actor=GreedyActor(identity),
                    scorer=MicroContestScorer(),
                    seed=3,
                    opponent_policy="adaptive-counter",
                    output_dir=output,
                )
            result_path = trial_dir / "result.json"
            result_path.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "evidence bytes differ"):
                verify_trial_evidence(trial_dir)

    def test_trial_admission_rejects_identity_drift(self) -> None:
        identity = ActorIdentity("identity", "Red", "scripted", "GreedyActor")
        spec = self._spec(identity, "EXP-IDENTITY")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Scorer identity differs"):
                run_trial(
                    spec=spec,
                    world=MicroContestWorld(),
                    actor=GreedyActor(identity),
                    scorer=MicroContestScorerWithDrift(),
                    seed=3,
                    opponent_policy="adaptive-counter",
                    output_dir=Path(directory),
                )


if __name__ == "__main__":
    unittest.main()
