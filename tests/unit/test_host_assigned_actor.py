from __future__ import annotations

import math
import stat
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.agent_stack import AgentTurnEvidence
from ordivon_security.actors.host_assigned import (
    _candidate_completed_conclusion,
    _host_json_value,
    _model_context_from_compiled,
)
from ordivon_security.actors.native_harness import NativeHarnessActorBackend
from ordivon_security.cli_cage4_deepseek import (
    _paths_overlap,
    _prepare_private_state_root,
    build_parser,
)
from ordivon_security.contest.model import (
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)

_ACTIONS = ("cage.team.native-policy", "cage.team.sleep")
_DIGESTS = tuple("sha256:" + character * 64 for character in "1234567")


@dataclass
class _HostDriver:
    @property
    def credential_scope_id(self) -> str:
        return "credential-scope:deepseek:flash:0"

    @property
    def requested_model_id(self) -> str:
        return "deepseek-v4-flash"

    @property
    def allowed_actions(self) -> tuple[str, ...]:
        return _ACTIONS

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security-agent-stack-identity",
            "provider": {
                "requestedModelId": self.requested_model_id,
                "credentialScopeId": self.credential_scope_id,
            },
            "harness": {"mode": "host-assigned-domain-tool-loop-v1"},
            "host": {
                "componentId": "ordivon-host",
                "revision": "host:test",
                "mode": "durable-task-assignment-completion-v1",
                "consumed": True,
                "configuration": {},
            },
            "runtime": {
                "componentId": "ordivon-runtime",
                "revision": "runtime:test",
                "mode": "not-consumed-domain-action",
                "consumed": False,
                "configuration": {},
            },
            "security": {"allowedActions": list(_ACTIONS)},
        }

    def run_turn(
        self,
        *,
        actor_id: str,
        side: str,
        objective: str,
        observation: ActorObservation,
        prior_results: tuple[ActorActionResult, ...],
    ) -> AgentTurnEvidence:
        del side, objective, prior_results
        run_id = f"harness-run:security-host:{actor_id.removeprefix('actor:')}:tick-0:g1"
        trace: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": run_id,
            "events": [],
        }
        return AgentTurnEvidence(
            harness_run_id=run_id,
            assignment_id="assignment:security-host:red:attempt-1:g1",
            context_digest=_DIGESTS[1],
            selected_action="cage.team.native-policy",
            rationale="Host accepted the bounded team-plan decision.",
            stop_code="candidate_completed",
            trace=trace,
            trace_digest=canonical_digest(trace),
            usage={"modelCalls": 2, "toolCalls": 1},
            requested_model_id=self.requested_model_id,
            effective_model_ids=(self.requested_model_id,),
            credential_scope_id=self.credential_scope_id,
            host_task_id="task:security-host:red:tick-0:test",
            host_task_revision=5,
            host_task_contract_digest=_DIGESTS[0],
            host_context_object_digest=_DIGESTS[1],
            host_assignment_digest=_DIGESTS[2],
            host_run_receipt_digest=_DIGESTS[3],
            host_completion_proposal_digest=_DIGESTS[4],
            host_completion_decision_digest=_DIGESTS[5],
            host_completion_accepted=True,
        )


def _backend() -> NativeHarnessActorBackend:
    return NativeHarnessActorBackend(
        actor_id="actor:red",
        side="red",
        objective="Select one admitted Red team plan.",
        driver=_HostDriver(),
    )


def _scenario(backend: NativeHarnessActorBackend) -> ScenarioManifest:
    binding = ActorBinding(
        actor_id=backend.actor_id,
        side=backend.side,
        backend_id=backend.backend_id,
        backend_config_digest=backend.configuration_digest,
        objective=backend.objective,
        allowed_actions=_ACTIONS,
    )
    peer = ActorBinding(
        actor_id="actor:blue",
        side="blue",
        backend_id="backend:scripted-sequence-v1",
        backend_config_digest=_DIGESTS[6],
        objective="Defend the environment.",
        allowed_actions=_ACTIONS,
    )
    return ScenarioManifest(
        scenario_id="scenario:host-assigned-test",
        revision="1",
        range_id="range:cage4-enterprise-v1",
        actors=(binding, peer),
        max_ticks=1,
    )


class _CompiledContextFixture:
    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.compiled-context",
            "payload": {
                "taskId": "task:fixture",
                "taskAttemptId": "task-attempt:fixture:1",
                "taskContractDigest": _DIGESTS[0],
                "objective": {"large": "duplicated and intentionally omitted"},
                "acceptanceCriteria": {"large": "duplicated and intentionally omitted"},
                "constraints": ["Use only selected Context."],
                "blocks": [
                    {
                        "blockId": "context-block:fixture:selected",
                        "payloadDigest": _DIGESTS[1],
                        "payload": {
                            "actorId": "actor:red",
                            "objective": "Select one admitted plan.",
                            "observationProjection": {"bounded": True},
                            "priorActionResults": [],
                            "rules": {"mustChooseExactlyOnePlan": True},
                        },
                    }
                ],
            },
            "manifest": {
                "selectedBlockIds": ["context-block:fixture:selected"],
                "omittedBlockIds": [],
                "tokenBudget": 12_000,
                "estimatedTokens": 100,
            },
        }


class HostAssignedActorTests(unittest.TestCase):
    def test_host_lifecycle_enters_action_proposal_and_receipt(self) -> None:
        backend = _backend()
        scenario = _scenario(backend)
        session = backend.start(scenario.actors[0], scenario)
        proposal = backend.propose(
            session,
            ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
        )
        receipt = backend.stop(session)

        host = proposal.arguments["hostLifecycle"]
        self.assertEqual(host["taskRevision"], 5)
        self.assertEqual(host["contextObjectDigest"], _DIGESTS[1])
        self.assertTrue(host["completionAccepted"])
        turns = receipt.details["turns"]
        assert isinstance(turns, list)
        self.assertEqual(turns[0]["hostLifecycle"], host)
        self.assertTrue(backend.execution_identity["agentStack"]["host"]["consumed"])
        self.assertFalse(backend.execution_identity["agentStack"]["runtime"]["consumed"])

    def test_partial_host_lifecycle_is_rejected(self) -> None:
        trace: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": "harness-run:partial",
            "events": [],
        }
        with self.assertRaisesRegex(ValueError, "must be complete"):
            AgentTurnEvidence(
                harness_run_id="harness-run:partial",
                assignment_id="assignment:partial",
                context_digest=_DIGESTS[0],
                selected_action="cage.team.sleep",
                rationale="Partial evidence must fail.",
                stop_code="candidate_completed",
                trace=trace,
                trace_digest=canonical_digest(trace),
                usage={},
                requested_model_id="deepseek-v4-flash",
                effective_model_ids=("deepseek-v4-flash",),
                credential_scope_id="credential-scope:deepseek:flash:0",
                host_task_id="task:partial",
            )

    def test_candidate_completed_conclusion_retains_structured_unknowns(self) -> None:
        trace: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": "harness-run:unknowns",
            "events": [],
        }
        evidence = AgentTurnEvidence(
            harness_run_id="harness-run:unknowns",
            assignment_id="assignment:unknowns",
            context_digest=_DIGESTS[0],
            selected_action="cage.team.sleep",
            rationale="decision with residual unknowns",
            stop_code="candidate_completed",
            trace=trace,
            trace_digest=canonical_digest(trace),
            usage={},
            requested_model_id="deepseek-v4-flash",
            effective_model_ids=("deepseek-v4-flash",),
            credential_scope_id="credential-scope:deepseek:flash:0",
            unresolved_unknowns=(
                "exact input bytes were not re-observed",
                "provider receipt identity not yet reconciled",
            ),
        )
        conclusion = _candidate_completed_conclusion(evidence)
        self.assertEqual(conclusion["status"], "candidate_completed")
        self.assertEqual(conclusion["summary"], "decision with residual unknowns")
        self.assertEqual(
            conclusion["unresolved_unknowns"],
            [
                "exact input bytes were not re-observed",
                "provider receipt identity not yet reconciled",
            ],
        )

    def test_candidate_completed_conclusion_defaults_to_no_unknowns(self) -> None:
        trace: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": "harness-run:empty",
            "events": [],
        }
        evidence = AgentTurnEvidence(
            harness_run_id="harness-run:empty",
            assignment_id="assignment:empty",
            context_digest=_DIGESTS[1],
            selected_action="cage.team.native-policy",
            rationale="fully determined decision",
            stop_code="candidate_completed",
            trace=trace,
            trace_digest=canonical_digest(trace),
            usage={},
            requested_model_id="deepseek-v4-flash",
            effective_model_ids=("deepseek-v4-flash",),
            credential_scope_id="credential-scope:deepseek:flash:0",
        )
        self.assertEqual(
            _candidate_completed_conclusion(evidence)["unresolved_unknowns"], []
        )

    def test_float_normalization_is_deterministic_and_finite_only(self) -> None:
        self.assertEqual(
            _host_json_value(0.0),
            {"kind": "ordivon.canonical-float", "decimal": "0"},
        )
        self.assertEqual(
            _host_json_value(-1.25),
            {"kind": "ordivon.canonical-float", "decimal": "-1.25"},
        )
        self.assertEqual(
            _host_json_value({"reward": 0.5, "values": [1.0, 2]}),
            {
                "reward": {"kind": "ordivon.canonical-float", "decimal": "0.5"},
                "values": [
                    {"kind": "ordivon.canonical-float", "decimal": "1"},
                    2,
                ],
            },
        )
        with self.assertRaisesRegex(ValueError, "non-finite"):
            _host_json_value(math.inf)

    def test_model_context_uses_selected_host_blocks_without_storage_duplication(self) -> None:
        model_context = _model_context_from_compiled(
            _CompiledContextFixture(),
            context_object_digest=_DIGESTS[2],
        )
        self.assertEqual(
            model_context["selectedContext"],
            [
                {
                    "objective": "Select one admitted plan.",
                    "observation": {"bounded": True},
                    "priorActionResults": [],
                    "rules": {"mustChooseExactlyOnePlan": True},
                }
            ],
        )
        self.assertNotIn("hostContextObjectDigest", model_context)
        self.assertNotIn("taskContractDigest", model_context)
        self.assertNotIn("taskId", model_context)
        self.assertNotIn("taskAttemptId", model_context)
        self.assertNotIn("constraints", model_context)
        self.assertNotIn("manifest", model_context)

    def test_private_host_state_root_is_empty_private_and_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = _prepare_private_state_root(parent / "host-state", "Host state root")
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertTrue(_paths_overlap(root, root / "red"))
            self.assertFalse(_paths_overlap(root, parent / "evidence"))
            (root / "residual").write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                _prepare_private_state_root(root, "Host state root")

    def test_cli_exposes_p0b_without_changing_p0a_default(self) -> None:
        parser = build_parser()
        baseline = parser.parse_args(
            ["--red-secret", "/private/red.json", "--blue-secret", "/private/blue.json"]
        )
        self.assertEqual(baseline.variant, "p0a")
        self.assertIsNone(baseline.output)
        self.assertIsNone(baseline.host_state_root)
        self.assertIsNone(baseline.host_state_namespace)
        p0b = parser.parse_args(
            [
                "--variant",
                "p0b",
                "--red-secret",
                "/private/red.json",
                "--blue-secret",
                "/private/blue.json",
                "--host-state-root",
                "/private/host-state",
                "--host-state-namespace",
                "host-state:security:p0b-test",
            ]
        )
        self.assertEqual(p0b.variant, "p0b")
        self.assertEqual(str(p0b.host_state_root), "/private/host-state")
        self.assertEqual(p0b.host_context_tokens, 12_000)


if __name__ == "__main__":
    unittest.main()
