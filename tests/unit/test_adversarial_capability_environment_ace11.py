from __future__ import annotations

import unittest

from ordivon_security.cli_adversarial_capability_environment_ace11 import (
    _CURRENT_IMPLEMENTATION_AUTHORITY,
    bound_model_context,
    classify_binding,
    source_context,
)


class AdversarialCapabilityEnvironmentAce11Tests(unittest.TestCase):
    def test_stale_source_effect_is_internally_consistent_but_not_current(self) -> None:
        source = source_context()
        interface = source.effect_interfaces[0]
        self.assertTrue(interface.consequence["readOnly"])
        self.assertFalse(interface.consequence["serviceRestart"])
        standing = classify_binding(interface, _CURRENT_IMPLEMENTATION_AUTHORITY)
        self.assertEqual(standing["applicability"], "STALE_NOT_APPLICABLE")
        self.assertEqual(
            standing["dependencyMatch"],
            {"implementationIdentity": False, "consequenceDigest": False},
        )

    def test_exact_binding_preflight_withdraws_stale_effect_interface(self) -> None:
        source = source_context()
        projection, standing = bound_model_context(source, _CURRENT_IMPLEMENTATION_AUTHORITY)
        self.assertEqual(standing["applicability"], "STALE_NOT_APPLICABLE")
        self.assertEqual(projection.effect_interfaces, ())
        self.assertEqual(projection.metadata["sourceContextDigest"], source.digest)

    def test_unavailable_current_effect_authority_is_unknown(self) -> None:
        source = source_context()
        standing = classify_binding(source.effect_interfaces[0], None)
        self.assertEqual(standing["applicability"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
