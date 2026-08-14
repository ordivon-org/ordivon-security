"""Private project storage — registry-gate idiom (idiom #3 of 3 in V3).

NOTE the module-level `gate` binding: it is imported *by name* from the
registry, so patching registry.gate does NOT affect this module. An attacker
must patch this module's own binding — one more site to find and hit.
"""
from .registry import gate


def save_private(path: str) -> str:
    gate("private_toe",
         "Cannot save a private toe without a Pro licence. Please remove privacy.")
    return f"saved private project {path}"
