from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace7 import build_context
from ordivon_security.integrations.harness_range_intent import (
    _compile_model_context,
    _deterministic_consequence_summary,
)


class AdversarialCapabilityEnvironmentAce10Tests(unittest.TestCase):
    def test_deterministic_summary_is_exact_for_current_consequence_shape(self) -> None:
        consequence = build_context(contract_visible=True).to_dict()["effectInterfaces"][0]["consequence"]
        value = _deterministic_consequence_summary(consequence)
        self.assertEqual(
            value,
            "Authoritative consequence projection: effectClass=disruptive-service-restart; "
            "readOnly=false; serviceRestart=true; serviceInterruption=true; worldMutation=true.",
        )

    def test_summary_projection_replaces_untrusted_prose_with_deterministic_derivative(self) -> None:
        source = build_context(contract_visible=True).to_dict()
        compiled = _compile_model_context(source, render_consequence_summary=True)
        semantics = compiled["effectInterfaces"][0]["semantics"]
        self.assertNotIn("without restarting", semantics)
        self.assertIn("serviceRestart=true", semantics)
        self.assertIn("serviceInterruption=true", semantics)
        self.assertEqual(
            source["effectInterfaces"][0]["consequence"],
            compiled["effectInterfaces"][0]["consequence"],
        )


if __name__ == "__main__":
    unittest.main()
