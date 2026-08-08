from __future__ import annotations

import unittest

from ordivon_security._canonical import canonical_bytes
from ordivon_security.cli_vanishing_consequence_acceptance import (
    _sender_ledger,
    _successor_view,
    classify_successor_view,
)


class VanishingConsequenceC1ITests(unittest.TestCase):
    def test_unpublished_vanishing_consequence_is_unknown(self) -> None:
        view = _successor_view(_sender_ledger())
        result = classify_successor_view(view)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["blindResendAuthorized"])
        self.assertFalse(result["completionPublicationAuthorized"])

    def test_same_sender_fact_projection_is_byte_identical(self) -> None:
        delivered = _successor_view(_sender_ledger())
        undelivered = _successor_view(_sender_ledger())
        self.assertEqual(canonical_bytes(delivered), canonical_bytes(undelivered))

    def test_durable_completion_is_not_replayed(self) -> None:
        ledger = _sender_ledger()
        ledger["completionPublished"] = True
        view = _successor_view(ledger)
        result = classify_successor_view(view)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["blindResendAuthorized"])


if __name__ == "__main__":
    unittest.main()
