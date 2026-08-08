from __future__ import annotations

import unittest

from ordivon_security.actors.autonomous import RangeEffectInterface, RangeIntentContext
from ordivon_security.integrations import RangeIntentHarnessFailure
from ordivon_security.range import RangeAuthority, RangeEffectRequest


class AutonomousRangeIntentTests(unittest.TestCase):
    def _authority(self) -> RangeAuthority:
        return RangeAuthority(
            authority_id="range-authority:af2-red",
            revision="1",
            actor_id="actor:red",
            zone_refs=("zone:service",),
            capabilities=("service.quarantine", "service.notify"),
            external_boundary="owned-local-test-world",
        )

    def _interface(self, effect_type: str = "service.set-quarantined") -> RangeEffectInterface:
        return RangeEffectInterface(
            authority_id="range-authority:af2-red",
            zone_ref="zone:service",
            capability="service.quarantine",
            effect_type=effect_type,
            semantics="Set the owned local service quarantine state to true.",
        )

    def test_context_snapshots_visible_observation(self) -> None:
        observation = {"service": {"compromised": False}}
        context = RangeIntentContext(
            actor_id="actor:red",
            objective="Preserve the service unless compromise is independently verified.",
            visible_observation=observation,
            authorities=(self._authority(),),
            effect_interfaces=(self._interface(),),
        )
        before = context.digest
        observation["service"]["compromised"] = True
        self.assertFalse(context.visible_observation["service"]["compromised"])
        self.assertEqual(context.digest, before)

    def test_zero_request_decision_is_valid_hold(self) -> None:
        context = RangeIntentContext(
            actor_id="actor:red",
            objective="Hold the current world.",
            visible_observation={"state": "stable"},
            authorities=(self._authority(),),
            effect_interfaces=(self._interface(),),
        )
        decision = context.decision()
        self.assertTrue(decision.is_hold)
        self.assertEqual(decision.effect_requests, ())
        self.assertTrue(decision.to_dict()["hold"])

    def test_multiple_requests_are_not_a_tick_menu(self) -> None:
        authority = self._authority()
        quarantine = self._interface()
        notify = RangeEffectInterface(
            authority_id=authority.authority_id,
            zone_ref="zone:service",
            capability="service.notify",
            effect_type="service.emit-notice",
            semantics="Emit a management notice about the owned service.",
        )
        context = RangeIntentContext(
            actor_id="actor:red",
            objective="Quarantine and notify if compromise is verified.",
            visible_observation={"compromised": True},
            authorities=(authority,),
            effect_interfaces=(quarantine, notify),
        )
        decision = context.decision(
            (
                RangeEffectRequest(
                    request_id="range-effect-request:af2-q",
                    actor_id="actor:red",
                    authority_id=authority.authority_id,
                    zone_ref="zone:service",
                    capability="service.quarantine",
                    effect_type="service.set-quarantined",
                ),
                RangeEffectRequest(
                    request_id="range-effect-request:af2-n",
                    actor_id="actor:red",
                    authority_id=authority.authority_id,
                    zone_ref="zone:service",
                    capability="service.notify",
                    effect_type="service.emit-notice",
                ),
            )
        )
        self.assertFalse(decision.is_hold)
        self.assertEqual(len(decision.effect_requests), 2)

    def test_undeclared_effect_interface_is_rejected(self) -> None:
        authority = self._authority()
        context = RangeIntentContext(
            actor_id="actor:red",
            objective="Act only through declared interfaces.",
            visible_observation={},
            authorities=(authority,),
            effect_interfaces=(self._interface(),),
        )
        with self.assertRaises(ValueError):
            context.decision(
                (
                    RangeEffectRequest(
                        request_id="range-effect-request:af2-invented",
                        actor_id="actor:red",
                        authority_id=authority.authority_id,
                        zone_ref="zone:service",
                        capability="service.quarantine",
                        effect_type="service.delete-everything",
                    ),
                )
            )

    def test_harness_failure_retains_structured_evidence(self) -> None:
        evidence = {
            "schemaVersion": 1,
            "kind": "ordivon.security.af2-range-intent-harness-failure",
            "stopCode": "harness_failed",
        }
        error = RangeIntentHarnessFailure("harness_failed", evidence)
        self.assertEqual(error.stop_code, "harness_failed")
        self.assertEqual(error.evidence, evidence)

    def test_context_rejects_interface_outside_authority(self) -> None:
        with self.assertRaises(ValueError):
            RangeIntentContext(
                actor_id="actor:red",
                objective="No invented capability.",
                visible_observation={},
                authorities=(self._authority(),),
                effect_interfaces=(
                    RangeEffectInterface(
                        authority_id="range-authority:af2-red",
                        zone_ref="zone:service",
                        capability="service.destroy",
                        effect_type="service.destroy",
                        semantics="Not granted.",
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
