from __future__ import annotations

import unittest
from pathlib import Path


class IF3CurrentSurfaceRejectionTests(unittest.TestCase):
    def test_if3_driver_structures_undeclared_current_interface_rejection(self) -> None:
        source = Path("src/ordivon_security/deliberation_before_authority_research_support.py").read_text()
        self.assertIn('"stopCode": "security_intent_rejected"', source)
        self.assertIn('"reason": "requested-effect-interface-not-currently-declared"', source)
        self.assertIn('"securityAdmissionPerformed": False', source)
        self.assertIn('"effectExecuted": False', source)


if __name__ == "__main__":
    unittest.main()
