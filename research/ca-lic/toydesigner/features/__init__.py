"""Feature modules for ToyDesigner.

The `lic` slot is set by app.py at startup; feature gates read it at call
time. In V3 the gates are *scattered*: different modules use different gate
idioms (direct check / class method / central registry), mirroring how
目标产品's Pro-gated strings are spread across the engine.
"""
lic = None


def _lic():
    if lic is None:
        raise RuntimeError("app not initialized")
    return lic


from . import (  # noqa: E402  (expose submodules as package attributes)
    network,
    projects,
    registry,
    render,
)

__all__ = ["network", "projects", "registry", "render", "lic", "_lic"]
