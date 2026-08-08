from __future__ import annotations

import unittest
from unittest.mock import patch

from ordivon_security.cli_windows_kvm_fresh_controller_continuation_acceptance import (
    _namespace_addresses,
    _namespace_link_names,
)


class FreshControllerContinuationAcceptanceTests(unittest.TestCase):
    def test_namespace_link_names_reads_only_reported_namespace_links(self) -> None:
        completed = type(
            "Completed", (), {"returncode": 0, "stdout": '[{"ifname":"lo"},{"ifname":"q12345678"}]'}
        )()
        with patch("subprocess.run", return_value=completed):
            self.assertEqual(
                _namespace_link_names("s6q12345678"),
                ["lo", "q12345678"],
            )

    def test_namespace_addresses_preserves_prefix_identity(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": (
                    '[{"ifname":"q12345678","addr_info":[{"local":"10.253.70.4","prefixlen":24}]}]'
                ),
            },
        )()
        with patch("subprocess.run", return_value=completed):
            self.assertEqual(
                _namespace_addresses("s6q12345678", "q12345678"),
                ["10.253.70.4/24"],
            )


if __name__ == "__main__":
    unittest.main()
