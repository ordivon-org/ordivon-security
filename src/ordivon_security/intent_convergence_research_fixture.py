from __future__ import annotations

from ordivon_security._canonical import JsonObject
from ordivon_security.actors.autonomous import RangeIntentContext
from ordivon_security.autonomous_communication_research_fixture import (
    AC0_ACTOR_A_ID,
    AC0_ACTOR_B_ID,
)
from ordivon_security.cli_verifiable_disclosure_ac2_acceptance import _b_context

AC2_MISMATCH_CONTEXT_DIGEST = (
    "sha256:e9dd7c82c0f2f518aaf80ae5ca2e6adef5257e37027c5fae0e9b5b013741f8d5"
)


def exact_ac2_mismatch_context() -> RangeIntentContext:
    """Reconstruct the exact AC2 mismatch consumer reused by IF0-IF3."""
    state: JsonObject = {
        "messages": [
            {
                "messageId": "message:ac0:ac0-a:1",
                "sourceId": AC0_ACTOR_A_ID,
                "recipientId": AC0_ACTOR_B_ID,
                "content": {"signal": 1},
                "claimTruthStatus": "not-promoted",
            }
        ]
    }
    verified: JsonObject = {
        "disclosureId": "verified-disclosure:ac2:a-signal:1",
        "sourceId": AC0_ACTOR_A_ID,
        "recipientId": AC0_ACTOR_B_ID,
        "property": "privateSignal",
        "value": 1,
        "truthAuthority": "owned-range-selective-disclosure",
        "verificationStatus": "verified-current-private-signal",
        "derivedFromSenderMessage": False,
    }
    context = _b_context(state, signal_b=0, verified_disclosure=verified)
    if context.digest != AC2_MISMATCH_CONTEXT_DIGEST:
        raise RuntimeError(
            "IF-series AC2 mismatch context drifted: "
            f"{context.digest} != {AC2_MISMATCH_CONTEXT_DIGEST}"
        )
    return context
