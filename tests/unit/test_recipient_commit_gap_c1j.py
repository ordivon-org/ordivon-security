from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ordivon_security.cli_recipient_commit_gap_acceptance import (
    _EFFECT_ID,
    _effect_binding,
    _persist_marker,
    _recipient_marker_state,
)


class RecipientCommitGapC1JTests(unittest.TestCase):
    def test_effect_identity_is_stable(self) -> None:
        self.assertEqual(_effect_binding()["effectId"], _EFFECT_ID)

    def test_recipient_marker_is_durable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "private" / "marker.json"
            self.assertEqual(_recipient_marker_state(path)["dedupEffectIds"], [])
            _persist_marker(path)
            first = path.read_bytes()
            _persist_marker(path)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual(_recipient_marker_state(path)["dedupEffectIds"], [_EFFECT_ID])


if __name__ == "__main__":
    unittest.main()
