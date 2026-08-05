from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, replace

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.actors.agent_stack import (
    AgentLayerBinding,
    AgentTurnDriverError,
    AgentTurnEvidence,
)
from ordivon_security.actors.native_harness import NativeHarnessActorBackend
from ordivon_security.actors.protocol import (
    ActorProposalFailure,
    ActorProposalFailureCode,
)
from ordivon_security.contest.model import (
    ActorActionResult,
    ActorBinding,
    ActorObservation,
    ScenarioManifest,
)

_ACTIONS = ("cage.team.native-policy", "cage.team.sleep")
_SECRET_SENTINEL = "credential-material-must-never-appear"


@dataclass
class _FakeDriver:
    selected_action: str = "cage.team.sleep"
    fail: AgentTurnDriverError | None = None
    host_mode: str = "not-consumed-security-domain-session"
    runtime_mode: str = "not-consumed-domain-action"
    credential: str = "credential-scope:deepseek:flash:0"

    @property
    def credential_scope_id(self) -> str:
        return self.credential

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
                "providerId": "provider:deepseek",
                "requestedModelId": self.requested_model_id,
                "credentialScopeId": self.credential,
            },
            "harness": {
                "revision": "harness:test",
                "mode": "domain-tool-loop-v1",
            },
            "host": AgentLayerBinding(
                "ordivon-host",
                "host:test",
                self.host_mode,
                False,
            ).to_dict(),
            "runtime": AgentLayerBinding(
                "ordivon-runtime",
                "runtime:test",
                self.runtime_mode,
                False,
            ).to_dict(),
            "security": {
                "promptRevision": "security-cage-team-plan-v1",
                "allowedActions": list(_ACTIONS),
            },
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
        if self.fail is not None:
            raise self.fail
        trace: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": f"harness-run:{actor_id.removeprefix('actor:')}:{observation.tick}",
            "events": [
                {
                    "sequence": 1,
                    "kind": "run_started",
                    "occurredAtMs": 1,
                    "payload": {"credentialScopeId": self.credential},
                },
                {
                    "sequence": 2,
                    "kind": "run_stopped",
                    "occurredAtMs": 2,
                    "payload": {"stopCode": "candidate_completed"},
                },
            ],
        }
        return AgentTurnEvidence(
            harness_run_id=trace["harnessRunId"],
            assignment_id=f"assignment:{actor_id.removeprefix('actor:')}:{observation.tick}",
            context_digest=canonical_digest(observation.to_dict()),
            selected_action=self.selected_action,
            rationale="Selected the bounded team plan.",
            stop_code="candidate_completed",
            trace=trace,
            trace_digest=canonical_digest(trace),
            usage={
                "modelCalls": 2,
                "toolCalls": 1,
                "totalTokens": 128,
                "effectiveModelIds": [self.requested_model_id],
            },
            requested_model_id=self.requested_model_id,
            effective_model_ids=(self.requested_model_id,),
            credential_scope_id=self.credential,
        )


def _backend(driver: _FakeDriver | None = None) -> NativeHarnessActorBackend:
    return NativeHarnessActorBackend(
        actor_id="actor:red",
        side="red",
        objective="Choose the best admitted Red team plan from bounded evidence.",
        driver=driver or _FakeDriver(),
    )


def _binding(backend: NativeHarnessActorBackend) -> ActorBinding:
    return ActorBinding(
        actor_id="actor:red",
        side="red",
        backend_id=backend.backend_id,
        backend_config_digest=backend.configuration_digest,
        objective=backend.objective,
        allowed_actions=_ACTIONS,
    )


def _scenario(binding: ActorBinding) -> ScenarioManifest:
    peer = ActorBinding(
        actor_id="actor:blue",
        side="blue",
        backend_id="backend:scripted-sequence-v1",
        backend_config_digest="sha256:" + "a" * 64,
        objective="Defend the environment.",
        allowed_actions=_ACTIONS,
    )
    return ScenarioManifest(
        scenario_id="scenario:native-harness-test",
        revision="1",
        range_id="range:cage4-enterprise-v1",
        actors=(binding, peer),
        max_ticks=1,
    )


class NativeHarnessActorP0Tests(unittest.TestCase):
    def test_turn_evidence_enters_proposal_and_stop_receipt(self) -> None:
        backend = _backend()
        binding = _binding(backend)
        session = backend.start(binding, _scenario(binding))
        observation = ActorObservation(
            actor_id="actor:red",
            tick=0,
            visible_state={"bounded": True, "missionPhase": 0},
            allowed_actions=_ACTIONS,
        )

        proposal = backend.propose(session, observation)
        backend.observe_result(
            session,
            ActorActionResult(
                proposal_id=proposal.proposal_id,
                actor_id="actor:red",
                tick=0,
                status="resolved",
                observation={"teamReward": 0.0},
            ),
        )
        receipt = backend.stop(session)

        self.assertEqual(proposal.action_type, "cage.team.sleep")
        self.assertEqual(
            proposal.arguments["credentialScopeId"],
            "credential-scope:deepseek:flash:0",
        )
        self.assertEqual(proposal.arguments["requestedModelId"], "deepseek-v4-flash")
        self.assertEqual(receipt.details["turnCount"], 1)
        turns = receipt.details["turns"]
        self.assertIsInstance(turns, list)
        assert isinstance(turns, list)
        self.assertEqual(turns[0]["trace"]["kind"], "ordivon.harness-trace")
        self.assertEqual(receipt.details["observedResultCount"], 1)

    def test_each_agent_layer_changes_configuration_identity(self) -> None:
        baseline = _backend(_FakeDriver())
        changed_host = _backend(_FakeDriver(host_mode="host-assignment-v1"))
        changed_runtime = _backend(_FakeDriver(runtime_mode="runtime-process-v1"))
        changed_credential = _backend(_FakeDriver(credential="credential-scope:deepseek:flash:1"))

        digests = {
            baseline.configuration_digest,
            changed_host.configuration_digest,
            changed_runtime.configuration_digest,
            changed_credential.configuration_digest,
        }
        self.assertEqual(len(digests), 4)
        identity = baseline.execution_identity
        self.assertIs(identity["agentStack"]["host"]["consumed"], False)
        self.assertIs(identity["agentStack"]["runtime"]["consumed"], False)

    def test_secret_material_never_enters_identity_or_evidence(self) -> None:
        backend = _backend()
        encoded_identity = json.dumps(backend.execution_identity, sort_keys=True)
        self.assertNotIn(_SECRET_SENTINEL, encoded_identity)
        self.assertNotIn("apiKey", encoded_identity)

        binding = _binding(backend)
        session = backend.start(binding, _scenario(binding))
        proposal = backend.propose(
            session,
            ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
        )
        receipt = backend.stop(session)
        retained = json.dumps(
            {"proposal": proposal.to_dict(), "receipt": receipt.details},
            sort_keys=True,
        )
        self.assertNotIn(_SECRET_SENTINEL, retained)
        self.assertNotIn("apiKey", retained)

    def test_ungranted_action_fails_closed(self) -> None:
        backend = _backend(_FakeDriver(selected_action="cage.team.ungranted"))
        binding = _binding(backend)
        session = backend.start(binding, _scenario(binding))
        with self.assertRaisesRegex(ActorProposalFailure, "outside the Actor grant"):
            backend.propose(
                session,
                ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
            )
        receipt = backend.stop(session)
        self.assertEqual(receipt.details["turnCount"], 0)

    def test_driver_failure_maps_to_actor_failure(self) -> None:
        failure = AgentTurnDriverError(
            ActorProposalFailureCode.PROVIDER_ERROR,
            "injected Provider failure",
            details={"providerFailureCode": "unavailable"},
        )
        backend = _backend(_FakeDriver(fail=failure))
        binding = _binding(backend)
        session = backend.start(binding, _scenario(binding))
        with self.assertRaises(ActorProposalFailure) as caught:
            backend.propose(
                session,
                ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
            )
        self.assertIs(caught.exception.code, ActorProposalFailureCode.PROVIDER_ERROR)
        self.assertEqual(
            caught.exception.details["providerFailureCode"],
            "unavailable",
        )
        receipt = backend.stop(session)
        self.assertEqual(receipt.details["failedTurnCount"], 1)
        self.assertEqual(
            receipt.details["failedTurns"][0]["providerFailureCode"],
            "unavailable",
        )

    def test_harness_stop_trace_is_retained_in_failure_receipt(self) -> None:
        trace = {
            "schemaVersion": 1,
            "kind": "ordivon.harness-trace",
            "harnessRunId": "harness-run:red:failed",
            "events": [
                {
                    "sequence": 1,
                    "kind": "run_stopped",
                    "occurredAtMs": 2,
                    "payload": {"stopCode": "budget_exhausted"},
                }
            ],
        }
        failure = AgentTurnDriverError(
            ActorProposalFailureCode.ACTOR_STOPPED,
            "injected Harness budget stop",
            details={
                "harnessRunId": "harness-run:red:failed",
                "assignmentId": "assignment:red:failed",
                "contextDigest": "sha256:" + "1" * 64,
                "stopCode": "budget_exhausted",
                "selectedAction": "cage.team.native-policy",
                "trace": trace,
                "traceDigest": canonical_digest(trace),
                "usage": {"modelCalls": 2, "toolCalls": 1},
                "requestedModelId": "deepseek-v4-flash",
                "effectiveModelIds": ["deepseek-v4-flash"],
                "credentialScopeId": "credential-scope:deepseek:flash:0",
            },
        )
        backend = _backend(_FakeDriver(fail=failure))
        binding = _binding(backend)
        session = backend.start(binding, _scenario(binding))
        with self.assertRaises(ActorProposalFailure):
            backend.propose(
                session,
                ActorObservation("actor:red", 0, {"bounded": True}, _ACTIONS),
            )
        receipt = backend.stop(session)
        self.assertEqual(receipt.details["failedTurnCount"], 1)
        failed = receipt.details["failedTurns"][0]
        self.assertEqual(failed["stopCode"], "budget_exhausted")
        self.assertEqual(failed["trace"]["kind"], "ordivon.harness-trace")
        self.assertEqual(failed["selectedAction"], "cage.team.native-policy")

    def test_default_budget_allows_domain_action_and_conclusion(self) -> None:
        from ordivon_security.actors.agent_stack import HarnessBudgetConfig

        budget = HarnessBudgetConfig()
        self.assertEqual(budget.max_tool_calls, 2)
        self.assertEqual(budget.max_model_observation_bytes, 262_144)

    def test_binding_drift_is_rejected_before_model_call(self) -> None:
        driver = _FakeDriver()
        backend = _backend(driver)
        binding = _binding(backend)
        drifted = replace(binding, backend_config_digest="sha256:" + "f" * 64)
        with self.assertRaisesRegex(ValueError, "configuration differs"):
            backend.start(drifted, _scenario(drifted))


if __name__ == "__main__":
    unittest.main()
