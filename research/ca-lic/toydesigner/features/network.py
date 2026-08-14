"""Network / sync features — class-method gate idiom (idiom #2 of 3 in V3)."""
from . import _lic


def shared_memory() -> str:
    _lic().require_tier("commercial", "Shared Memory requires a Commercial license.")
    return "shared memory handle 0x1"


def multi_node_sync() -> str:
    _lic().require_pro("Using Synchronized Outputs requires a Pro license.")
    return "frame-lock sync enabled"
