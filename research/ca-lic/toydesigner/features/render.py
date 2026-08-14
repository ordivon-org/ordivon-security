"""Render pipeline — direct-check gate idiom (idiom #1 of 3 in V3)."""
from license_model import NotEntitled

from . import _lic

FREE_MAX_HEIGHT = 720


def _gate_render_4k():
    """Direct boolean check, no helper. One attacker-visible site."""
    if not _lic().is_pro():
        raise NotEntitled("This feature requires Pro license.")


def render(height: int, width: int) -> dict:
    if height > FREE_MAX_HEIGHT:
        _gate_render_4k()
    return {"res": f"{width}x{height}", "frames": 60, "hdr": height > FREE_MAX_HEIGHT}
