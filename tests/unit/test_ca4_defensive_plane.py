from __future__ import annotations

import unittest
from importlib.resources import files
from pathlib import Path

from ordivon_security.cli_ca4_defensive_plane import _CLEAN, _EICAR
from ordivon_security.fixtures import CLEAN_TEST_BYTES, EICAR_TEST_BYTES


class Ca4DefensivePlaneTests(unittest.TestCase):
    def test_ca4_uses_reusable_maintained_fixtures(self) -> None:
        self.assertEqual(_EICAR, EICAR_TEST_BYTES)
        self.assertEqual(_CLEAN, CLEAN_TEST_BYTES)

    def test_eicar_fixture_is_bounded_test_pattern_not_real_malware(self) -> None:
        self.assertEqual(len(_EICAR), 68)
        self.assertIn(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", _EICAR)
        self.assertNotEqual(_EICAR, _CLEAN)

    def test_runner_separates_observation_detection_adjudication_response_truth(self) -> None:
        path = Path(str(files("ordivon_security").joinpath("cli_ca4_defensive_plane.py")))
        source = path.read_text(encoding="utf-8")
        for value in (
            "raw-artifact-observation",
            "derived-detection",
            "STALE_NOT_APPLICABLE",
            "UNKNOWN_NO_RESPONSE",
            "responseReceipt",
            "postResponseTruth",
            "worldTruthVerified",
        ):
            self.assertIn(value, source)
        self.assertIn("malwareTruthClaim", source)
        self.assertNotIn("RangeActionGateway", source)

    def test_response_is_only_case_local_quarantine(self) -> None:
        path = Path(str(files("ordivon_security").joinpath("cli_ca4_defensive_plane.py")))
        source = path.read_text(encoding="utf-8")
        self.assertIn("quarantine-move", source)
        self.assertIn("case-local quarantine move only", source)
        self.assertNotIn("kill -9", source)
        self.assertNotIn("iptables", source)


if __name__ == "__main__":
    unittest.main()
