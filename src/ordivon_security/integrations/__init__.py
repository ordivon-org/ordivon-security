"""Explicit cross-repository integration surface.

These adapters are accepted experiment integrations, not Security's generic Agent cognition,
Task continuity, or physical execution state machines. Historical imports from
``ordivon_security.actors`` remain compatible.
"""

from ordivon_security.actors.host_assigned import HostAssignedDeepSeekHarnessTurnDriver
from ordivon_security.actors.runtime_assigned import RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver

__all__ = [
    "HostAssignedDeepSeekHarnessTurnDriver",
    "RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver",
]
