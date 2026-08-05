from __future__ import annotations

import math
import stat
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.agent_stack import AgentTurnEvidence
from ordivon_security.actors.host_assigned import _host_json_value
from ordivon_security.actors.native_harness import NativeHarnessActorBackend
from ordivon_security.cli_cage4_deepseek import (
    _paths_overlap,
    _prepare_private_host_state_root,
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

    def test_private_host_state_root_is_empty_private_and_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = _prepare_private_host_state_root(parent / "host-state")
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertTrue(_paths_overlap(root, root / "red"))
            self.assertFalse(_paths_overlap(root, parent / "evidence"))
            (root / "residual").write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                _prepare_private_host_state_root(root)

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
