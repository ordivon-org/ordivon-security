from __future__ import annotations

import unittest

from ordivon_security.ranges.cage4 import CAGE4_REVISION, Cage4RangeConfig


class Cage4ContractTests(unittest.TestCase):
    def test_rejects_unpinned_revision(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported CAGE 4 revision"):
            Cage4RangeConfig(
                source_path="/tmp/cage4",
                source_revision="not-the-pinned-revision",
            )

    def test_pinned_configuration_has_stable_digest(self) -> None:
        config = Cage4RangeConfig(source_path=".cache/cage4")
        self.assertEqual(config.source_revision, CAGE4_REVISION)
        self.assertTrue(config.digest.startswith("sha256:"))

    def test_local_source_path_does_not_change_experiment_identity(self) -> None:
        first = Cage4RangeConfig(source_path="/machine-a/cache/cage4")
        second = Cage4RangeConfig(source_path="/machine-b/cache/cage4")
        self.assertEqual(first.digest, second.digest)
        self.assertNotEqual(first.to_dict(), second.to_dict())


if __name__ == "__main__":
    unittest.main()
