"""Explicit cross-repository integration surface.

These adapters are accepted experiment integrations, not Security's generic Agent cognition,
Task continuity, or physical execution state machines. Historical imports remain compatible.
"""

from ordivon_security.actors.host_assigned import HostAssignedDeepSeekHarnessTurnDriver
from ordivon_security.actors.runtime_assigned import RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver

from .harness_range_intent import (
    DeepSeekRangeIntentConfig,
    DeepSeekRangeIntentDriver,
)

__all__ = [
    "DeepSeekRangeIntentConfig",
    "DeepSeekRangeIntentDriver",
    "HostAssignedDeepSeekHarnessTurnDriver",
    "RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver",
]
