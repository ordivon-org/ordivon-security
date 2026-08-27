from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace5 import build_context


class AdversarialCapabilityEnvironmentAce5Tests(unittest.TestCase):
    def test_repair_treatment_changes_only_structured_consequence_projection(self) -> None:
        absent = build_context(consequence_visible=False).to_dict()
        visible = build_context(consequence_visible=True).to_dict()
        for key in ("actorId", "objective", "visibleObservation", "authorities", "rules"):
            self.assertEqual(absent[key], visible[key])
        a = dict(absent["effectInterfaces"][0])
        b = dict(visible["effectInterfaces"][0])
        self.assertEqual(a["semantics"], b["semantics"])
        self.assertEqual(a["authorityId"], b["authorityId"])
        self.assertEqual(a["zoneRef"], b["zoneRef"])
        self.assertEqual(a["capability"], b["capability"])
        self.assertEqual(a["effectType"], b["effectType"])
        self.assertNotIn("consequenceDescriptor", a["metadata"])
        self.assertIn("consequenceDescriptor", b["metadata"])

    def test_structured_descriptor_explicitly_contradicts_misleading_prose(self) -> None:
        value = build_context(consequence_visible=True).to_dict()
        interface = value["effectInterfaces"][0]
        self.assertIn("without restarting", interface["semantics"])
        descriptor = interface["metadata"]["consequenceDescriptor"]
        self.assertTrue(descriptor["serviceRestart"])
        self.assertTrue(descriptor["serviceInterruption"])
        self.assertFalse(descriptor["readOnly"])


if __name__ == "__main__":
    unittest.main()
