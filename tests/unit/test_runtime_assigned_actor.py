from __future__ import annotations

import stat
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.agent_stack import AgentTurnEvidence
from ordivon_security.actors.native_harness import NativeHarnessActorBackend
from ordivon_security.actors.runtime_mcp import read_runtime_token
from ordivon_security.cli_cage4_deepseek import build_parser
from ordivon_security.contest.model import (
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)

_ACTIONS = ("cage.team.native-policy", "cage.team.sleep")
_DIGESTS = tuple("sha256:" + character * 64 for character in "123456789abcdef")


def _runtime_evidence() -> AgentTurnEvidence:
    trace: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.harness-trace",
        "harnessRunId": "harness-run:security-host-runtime:red:tick-0:g1",
        "events": [],
    }
    return AgentTurnEvidence(
        harness_run_id="harness-run:security-host-runtime:red:tick-0:g1",
        assignment_id="assignment:security-host-runtime:red:attempt-1:g1",
        context_digest=_DIGESTS[1],
        selected_action="cage.team.native-policy",
        rationale="Runtime executed the bounded Harness turn; Host accepted its proposal.",
        stop_code="candidate_completed",
        trace=trace,
        trace_digest=canonical_digest(trace),
        usage={"modelCalls": 2, "toolCalls": 1},
        requested_model_id="deepseek-v4-flash",
        effective_model_ids=("deepseek-v4-flash",),
        credential_scope_id="credential-scope:deepseek:flash:0",
        host_task_id="task:security-host-runtime:red:tick-0:test",
        host_task_revision=5,
        host_task_contract_digest=_DIGESTS[0],
        host_context_object_digest=_DIGESTS[1],
        host_assignment_digest=_DIGESTS[2],
        host_run_receipt_digest=_DIGESTS[3],
        host_completion_proposal_digest=_DIGESTS[4],
        host_completion_decision_digest=_DIGESTS[5],
        host_completion_accepted=True,
        runtime_job_id="job:security-p0c-red",
        runtime_attempt_id="attempt:security-p0c-red:1",
        runtime_client_request_id="request:security-p0c:red:g1:test",
        runtime_workspace_id="security-p0c-red-test",
        runtime_source_revision="runtime:test",
        runtime_terminal_evidence_digest=_DIGESTS[6],
        runtime_stdout_artifact_digest=_DIGESTS[7],
        runtime_tool_catalog_digest=_DIGESTS[8],
        runtime_response_digest=_DIGESTS[9],
        runtime_exact_replay_confirmed=True,
        runtime_recovery_lookup_confirmed=True,
    )


@dataclass
class _RuntimeDriver:
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
            "harness": {"mode": "host-assigned-runtime-executed-domain-tool-loop-v1"},
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
                "mode": "host-assignment-runtime-job-v1",
                "consumed": True,
                "configuration": {"semanticCompletionAuthority": False},
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
        del actor_id, side, objective, observation, prior_results
        return _runtime_evidence()


class RuntimeAssignedActorTests(unittest.TestCase):
    def test_runtime_lifecycle_enters_proposal_and_receipt(self) -> None:
        backend = NativeHarnessActorBackend(
            actor_id="actor:red",
            side="red",
            objective="Select one admitted Red team plan.",
            driver=_RuntimeDriver(),
        )
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
            backend_config_digest=_DIGESTS[10],
            objective="Defend the environment.",
            allowed_actions=_ACTIONS,
        )
        scenario = ScenarioManifest(
            scenario_id="scenario:runtime-assigned-test",
            revision="1",
            range_id="range:cage4-enterprise-v1",
            actors=(binding, peer),
            max_ticks=1,
        )
        session = backend.start(binding, scenario)
        proposal = backend.propose(
            session,
            ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
        )
        receipt = backend.stop(session)

        runtime = proposal.arguments["runtimeLifecycle"]
        self.assertEqual(runtime["jobId"], "job:security-p0c-red")
        self.assertTrue(runtime["exactReplayConfirmed"])
        self.assertTrue(runtime["recoveryLookupConfirmed"])
        turns = receipt.details["turns"]
        assert isinstance(turns, list)
        self.assertEqual(turns[0]["runtimeLifecycle"], runtime)
        self.assertTrue(backend.execution_identity["agentStack"]["runtime"]["consumed"])

    def test_partial_runtime_lifecycle_is_rejected(self) -> None:
        evidence = _runtime_evidence()
        values = evidence.to_dict(include_trace=True)
        self.assertIn("runtimeLifecycle", values)
        with self.assertRaisesRegex(ValueError, "must be complete"):
            AgentTurnEvidence(
                harness_run_id=evidence.harness_run_id,
                assignment_id=evidence.assignment_id,
                context_digest=evidence.context_digest,
                selected_action=evidence.selected_action,
                rationale=evidence.rationale,
                stop_code=evidence.stop_code,
                trace=evidence.trace,
                trace_digest=evidence.trace_digest,
                usage=evidence.usage,
                requested_model_id=evidence.requested_model_id,
                effective_model_ids=evidence.effective_model_ids,
                credential_scope_id=evidence.credential_scope_id,
                runtime_job_id="job:partial",
            )

    def test_runtime_token_file_requires_owner_only_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "runtime.env"
            token_file.write_text("ORDIVON_BEARER_TOKEN=test-token\n", encoding="utf-8")
            token_file.chmod(0o600)
            self.assertEqual(read_runtime_token(token_file), "test-token")
            self.assertEqual(stat.S_IMODE(token_file.stat().st_mode), 0o600)
            token_file.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "group- or world-readable"):
                read_runtime_token(token_file)

    def test_cli_exposes_p0c_runtime_inputs_without_changing_default(self) -> None:
        parser = build_parser()
        baseline = parser.parse_args(
            ["--red-secret", "/private/red.json", "--blue-secret", "/private/blue.json"]
        )
        self.assertEqual(baseline.variant, "p0a")
        self.assertIsNone(baseline.runtime_request_root)
        p0c = parser.parse_args(
            [
                "--variant",
                "p0c",
                "--red-secret",
                "/private/red.json",
                "--blue-secret",
                "/private/blue.json",
                "--host-state-root",
                "/private/host-state",
                "--host-state-namespace",
                "host-state:security:p0c-test",
                "--runtime-request-root",
                "/private/runtime-requests",
            ]
        )
        self.assertEqual(p0c.variant, "p0c")
        self.assertEqual(str(p0c.runtime_request_root), "/private/runtime-requests")
        self.assertEqual(p0c.runtime_endpoint, "http://127.0.0.1:8897/mcp")
        self.assertEqual(p0c.runtime_timeout_ms, 300_000)


if __name__ == "__main__":
    unittest.main()
