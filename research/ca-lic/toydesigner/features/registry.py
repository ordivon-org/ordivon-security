"""Central gate registry — one of the three gate idioms used in V3.

Feature -> minimum tier. Gates raise NotEntitled with a TD-style string
(these strings are the "string xrefs" an attacker greps for, exactly like
"This feature requires Pro license." in 核心库.dll).
"""

from . import _lic

FEATURE_TIERS = {
    "render_4k": "pro",
    "shared_memory": "commercial",
    "private_toe": "pro",
    "multi_node_sync": "pro",
}


def gate(feature: str, msg: str) -> None:
    need = FEATURE_TIERS[feature]
    _lic().require_tier(need, msg)
