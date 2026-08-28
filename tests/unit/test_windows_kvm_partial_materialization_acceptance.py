from __future__ import annotations

import unittest

from ordivon_security.windows_kvm_partial_world_fixture import partial_link_names


class PartialMaterializationAcceptanceTests(unittest.TestCase):
    def test_partial_resource_names_are_deterministic_from_session(self) -> None:
        first = partial_link_names("range-session:partial:test")
        second = partial_link_names("range-session:partial:test")
        other = partial_link_names("range-session:partial:other")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first[0].startswith("s6q"))
        self.assertTrue(first[1].startswith("q"))
        self.assertTrue(first[2].startswith("w"))
        self.assertEqual(len(first[1]), 9)
        self.assertEqual(len(first[2]), 9)


if __name__ == "__main__":
    unittest.main()
