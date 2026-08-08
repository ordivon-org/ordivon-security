from __future__ import annotations

import unittest
from dataclasses import dataclass

from ordivon_security._canonical import canonical_digest
from ordivon_security.cli_windows_kvm_c1a_acceptance import (
    _AUTHORITY_ID,
    _CAPABILITY,
    _CONTROL_OBJECTIVE,
    _EFFECT_OBJECTIVE,
    _EFFECT_TYPE,
    _ZONE_REF,
    _effect_request_from_decision,
    _intent_context,
    _RangeIntentBridge,
    _visible_snapshot,
)
from ordivon_security.range import RangeAuthority


@dataclass
class _Call:
    tool_call_id: str
    name: str
    arguments: dict[str, object]


@dataclass
class _Observation:
    tool_call_id: str
    tool_name: str
    status: str
    structured_content: dict[str, object]


class C1aAcceptanceUnitTests(unittest.TestCase):
    def _authority(self) -> RangeAuthority:
        return RangeAuthority(
            authority_id=_AUTHORITY_ID,
            revision="1",
            actor_id="actor:c1a-autonomous-controller",
            zone_refs=(_ZONE_REF,),
            capabilities=(_CAPABILITY,),
            external_boundary="denied",
        )

    def _state(self) -> dict[str, object]:
        return {
            "peerAExitCode": 0,
            "actorReplacementRequest": None,
            "topologyChurnCompleted": False,
            "secretBackendField": "must-not-enter-model-context",
            "fabricTruth": {
                "phase": "peer-a-present",
                "currentPeerAddress": "10.253.70.3",
                "externalRouteAbsent": True,
                "rawKernelDetail": "must-not-enter-model-context",
            },
        }

    def test_visible_snapshot_is_bounded_projection(self) -> None:
        snapshot = _visible_snapshot(self._state())
        encoded = str(snapshot)
        self.assertTrue(snapshot["peerAService"]["completedSuccessfully"])
        self.assertEqual(snapshot["currentTopology"]["phase"], "peer-a-present")
        self.assertNotIn("secretBackendField", encoded)
        self.assertNotIn("rawKernelDetail", encoded)

    def test_objective_changes_context_without_changing_observation_or_authority(self) -> None:
        snapshot = _visible_snapshot(self._state())
        authority = self._authority()
        control = _intent_context(
            objective=_CONTROL_OBJECTIVE,
            observation=snapshot,
            authority=authority,
        )
        effect = _intent_context(
            objective=_EFFECT_OBJECTIVE,
            observation=snapshot,
            authority=authority,
        )
        self.assertEqual(control["visibleObservationDigest"], effect["visibleObservationDigest"])
        self.assertEqual(control["authorityDigest"], effect["authorityDigest"])
        self.assertNotEqual(canonical_digest(control), canonical_digest(effect))

    def test_bridge_records_intent_without_execution_or_admission(self) -> None:
        bridge = _RangeIntentBridge(
            catalog=object(),
            observation_type=_Observation,
            bridge_identity={"bridge": "c1a"},
        )
        call = _Call(
            tool_call_id="tool-call:1",
            name="submit_range_intent",
            arguments={
                "decision": "request-effect",
                "authorityId": _AUTHORITY_ID,
                "zoneRef": _ZONE_REF,
                "capability": _CAPABILITY,
                "effectType": _EFFECT_TYPE,
            },
        )
        observed = bridge.execute(call, step_id="step:1")
        self.assertEqual(bridge.decision, call.arguments)
        self.assertIs(observed.structured_content["effectExecuted"], False)
        self.assertIs(observed.structured_content["securityAdmissionPerformed"], False)
        with self.assertRaisesRegex(ValueError, "only once"):
            bridge.execute(call, step_id="step:2")

    def test_model_effect_request_preserves_scope_without_correction(self) -> None:
        decision = {
            "decision": "request-effect",
            "authorityId": "range-authority:model-typo",
            "zoneRef": "zone:model-typo",
            "capability": "fabric.model-typo",
            "effectType": "fabric.model-typo",
        }
        request = _effect_request_from_decision("abc", decision)
        self.assertEqual(request.authority_id, "range-authority:model-typo")
        self.assertEqual(request.zone_ref, "zone:model-typo")
        self.assertEqual(request.capability, "fabric.model-typo")
        self.assertEqual(request.effect_type, "fabric.model-typo")
        self.assertEqual(request.payload["modelDecisionDigest"], canonical_digest(decision))


if __name__ == "__main__":
    unittest.main()
